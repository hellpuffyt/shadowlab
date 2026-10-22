"""Regression tests for defects found in the production-readiness audit:
guessing strategies that passed, answer-key leaks in ``show``, crashes on
hostile/malformed input, history data loss, and the "no execution / no
network" safety claim."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from shadowlab import cli, engine

IR_SCENARIOS = ("ransomware_ir", "phishing_bec_ir")
CHECKLIST_SCENARIOS = ("firewall_audit", "sshd_hardening")


# ------------------------------------------------------------- gaming


@pytest.mark.parametrize("scenario_id", CHECKLIST_SCENARIOS)
def test_selecting_every_catalog_id_does_not_pass(scenario_id):
    # Before: 75% (firewall_audit) and 88.57% (sshd_hardening), both PASS,
    # contradicting "submitting every possible id is not a winning strategy".
    catalog = engine.scenario_def_for(scenario_id).checklist_catalog
    assert catalog is not None
    result = engine.grade(scenario_id, {"selected_ids": list(catalog.all_ids)})
    assert result.passed is False


@pytest.mark.parametrize("scenario_id", CHECKLIST_SCENARIOS)
def test_exact_findings_still_score_full_marks(scenario_id):
    sdef = engine.scenario_def_for(scenario_id)
    assert sdef.ground_truth_fn is not None
    findings = sdef.ground_truth_fn(sdef.read_data(sdef.scenario.data_files[0]))
    result = engine.grade(scenario_id, {"selected_ids": [f.rule_id for f in findings]})
    assert result.points_earned == 100


@pytest.mark.parametrize("scenario_id", IR_SCENARIOS)
@pytest.mark.parametrize("order", ["catalog", "alphabetical", "reverse"])
def test_submitting_the_whole_ir_catalog_does_not_pass(scenario_id, order):
    # Before: the whole catalog in catalog (= display) order scored 85% PASS,
    # paying the ransom included.
    catalog = engine.scenario_def_for(scenario_id).action_catalog
    assert catalog is not None
    ids = [e.id for e in catalog.entries]
    ids = {"catalog": ids, "alphabetical": sorted(ids), "reverse": ids[::-1]}[order]
    result = engine.grade(scenario_id, {"ordered_ids": ids})
    assert result.passed is False
    assert any(fs.field == "unsafe-action deduction" and fs.points_earned < 0 for fs in result.field_scores)


@pytest.mark.parametrize("scenario_id", IR_SCENARIOS)
def test_ideal_ir_plan_still_scores_full_marks(scenario_id):
    catalog = engine.scenario_def_for(scenario_id).action_catalog
    assert catalog is not None
    result = engine.grade(scenario_id, {"ordered_ids": list(catalog.correct_order)})
    assert result.points_earned == 100


# ------------------------------------------------------ answer-key leaks


@pytest.mark.parametrize("scenario_id", IR_SCENARIOS)
def test_show_does_not_reveal_phase_labels_or_ideal_order(scenario_id, capsys):
    # Before: a "phase" column labelled every distractor "harmful" and the
    # rows were printed in the ideal order.
    assert cli.main(["--no-color", "show", scenario_id]) == 0
    out = capsys.readouterr().out
    catalog_part = out[out.index("Action catalog"):]
    assert "harmful" not in catalog_part
    for phase in ("containment", "eradication", "recovery", "lessons_learned"):
        assert phase not in catalog_part
    catalog = engine.scenario_def_for(scenario_id).action_catalog
    assert catalog is not None
    positions = [catalog_part.index(e.id + " ") for e in sorted(catalog.entries, key=lambda e: e.id)]
    assert positions == sorted(positions)


def test_show_lists_checklist_ids_alphabetically(capsys):
    assert cli.main(["--no-color", "show", "sshd_hardening"]) == 0
    out = capsys.readouterr().out
    catalog = engine.scenario_def_for("sshd_hardening").checklist_catalog
    assert catalog is not None
    positions = [out.index(rid + " ") for rid in sorted(catalog.all_ids)]
    assert positions == sorted(positions)


# --------------------------------------------- hostile / malformed input


def _submit(tmp_path: Path, scenario_id: str, answers: object, *extra: str) -> int:
    path = tmp_path / "answers.json"
    path.write_text(answers if isinstance(answers, str) else json.dumps(answers), encoding="utf-8")
    return cli.main(["--no-color", "submit", scenario_id, "--answers", str(path), "--no-record", *extra])


def test_rich_markup_in_an_answer_is_shown_verbatim_not_parsed(tmp_path, capsys):
    # Before: rich.errors.MarkupError traceback.
    rc = _submit(tmp_path, "brute_force_ssh", {"attacker_ip": "[/foo][bold]x"})
    assert rc == 2  # graded, failed
    assert "[/foo][bold]x" in capsys.readouterr().out


def test_terminal_escape_sequences_in_an_answer_are_not_emitted(tmp_path, capsys):
    rc = _submit(tmp_path, "brute_force_ssh", {"attacker_ip": "\x1b]0;title\x07\x1b[2Jboom"})
    assert rc == 2
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("scenario_id", "answers"),
    [
        ("brute_force_ssh", {"usernames_tried": 5}),
        ("brute_force_ssh", {"usernames_tried": "root"}),
        ("brute_force_ssh", '{"failed_attempt_count": 1e999}'),
        ("brute_force_ssh", {"failed_attempt_count": [1]}),
    ],
)
def test_wrongly_typed_fields_score_zero_instead_of_crashing(tmp_path, capsys, scenario_id, answers):
    # Before: TypeError / OverflowError tracebacks; a bare string was
    # silently split into characters.
    assert _submit(tmp_path, scenario_id, answers) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_bare_string_is_not_split_into_characters():
    result = engine.grade("brute_force_ssh", {"usernames_tried": "root"})
    row = next(fs for fs in result.field_scores if fs.field == "usernames tried")
    assert row.points_earned == 0
    assert "expected a list" in row.detail


@pytest.mark.parametrize(
    ("scenario_id", "answers"),
    [
        ("ransomware_ir", {"ordered_ids": [["ir-isolate-host"]]}),
        ("ransomware_ir", {"ordered_ids": [{"id": 1}]}),
        ("firewall_audit", {"selected_ids": [["fw-telnet-open"]]}),
        ("firewall_audit", {"selected_ids": [1, 2]}),
    ],
)
def test_non_string_ids_are_an_invalid_submission(tmp_path, capsys, scenario_id, answers):
    assert _submit(tmp_path, scenario_id, answers) == 1
    assert "invalid submission" in capsys.readouterr().out


# ------------------------------------------------------------- history


def _good_answers(tmp_path: Path) -> Path:
    path = tmp_path / "good.json"
    path.write_text(json.dumps({"selected_ids": ["fw-telnet-open"]}), encoding="utf-8")
    return path


@pytest.mark.parametrize("content", ['{"brute_force_ssh": {"points_earned": 1', "[1, 2]", "\udcff"])
def test_unreadable_history_is_never_overwritten(tmp_path, capsys, content):
    # Before: a corrupt history was treated as empty and replaced, losing
    # every recorded attempt; a non-object history crashed.
    history = tmp_path / "history.json"
    if content == "\udcff":
        history.write_bytes(b"\xff\xfe{")
    else:
        history.write_text(content, encoding="utf-8")
    before = history.read_bytes()
    rc = cli.main(
        ["--no-color", "submit", "firewall_audit", "--answers", str(_good_answers(tmp_path)), "--history", str(history)]
    )
    assert rc == 1
    assert history.read_bytes() == before
    assert "attempt not recorded" in " ".join(capsys.readouterr().out.split())


def test_report_skips_malformed_records_instead_of_crashing(tmp_path, capsys):
    history = tmp_path / "history.json"
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"selected_ids": ["fw-telnet-open"]}), encoding="utf-8")
    assert cli.main(["--no-color", "submit", "firewall_audit", "--answers", str(good), "--history", str(history)]) in (0, 2)
    data = json.loads(history.read_text(encoding="utf-8"))
    data["sshd_hardening"] = {"points_earned": "<script>alert(1)</script>"}
    history.write_text(json.dumps(data), encoding="utf-8")
    out_html = tmp_path / "r.html"
    assert cli.main(["--no-color", "report", "--history", str(history), "--out", str(out_html)]) == 0
    assert "skipped malformed" in capsys.readouterr().out
    html = out_html.read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "Misconfigured Perimeter Firewall Audit" in html


def test_submitted_html_is_escaped_in_the_report(tmp_path):
    history = tmp_path / "history.json"
    answers = tmp_path / "a.json"
    answers.write_text(json.dumps({"attacker_ip": "<img src=x onerror=alert(1)>"}), encoding="utf-8")
    cli.main(["--no-color", "submit", "brute_force_ssh", "--answers", str(answers), "--history", str(history)])
    out_html = tmp_path / "r.html"
    assert cli.main(["--no-color", "report", "--history", str(history), "--out", str(out_html)]) == 0
    html = out_html.read_text(encoding="utf-8")
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


# ------------------------------------------------- "sandboxed" claim


def test_no_command_opens_a_network_connection_or_runs_a_process(tmp_path, monkeypatch, capsys):
    """Run every command against every scenario with network and process
    creation disabled; any attempt raises and fails the test. Also check that
    nothing is written outside the explicit --history / --out paths."""

    def forbidden(*args, **kwargs):
        raise AssertionError("network or process access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    for name in ("execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "posix_spawn", "fork"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)

    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    history = work / "h.json"
    answers = tmp_path / "a.json"
    answers.write_text("{}", encoding="utf-8")

    assert cli.main(["--no-color", "list"]) == 0
    for scenario in engine.list_scenarios():
        assert cli.main(["--no-color", "show", scenario.id]) == 0
        assert cli.main(["--no-color", "submit", scenario.id, "--answers", str(answers), "--history", str(history)]) in (0, 2)
    assert cli.main(["--no-color", "report", "--history", str(history), "--out", str(work / "r.html")]) == 0
    assert sorted(p.name for p in work.iterdir()) == ["h.json", "r.html"]
    capsys.readouterr()
