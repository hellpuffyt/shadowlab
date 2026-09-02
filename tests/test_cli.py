"""Tests for the shadowlab CLI, run in-process via ``cli.main``."""

from __future__ import annotations

import json

import pytest

from shadowlab import cli


def test_list_command_runs(capsys):
    rc = cli.main(["--no-color", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "brute_force_ssh" in out


def test_list_command_filters_by_category(capsys):
    rc = cli.main(["--no-color", "list", "--category", "config-audit"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "firewall_audit" in out
    assert "brute_force_ssh" not in out


def test_show_command_runs_for_log_scenario(capsys):
    rc = cli.main(["--no-color", "show", "brute_force_ssh"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "attacker_ip" in out


def test_show_command_runs_for_checklist_scenario(capsys):
    rc = cli.main(["--no-color", "show", "firewall_audit"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "fw-telnet-open" in out


def test_show_command_runs_for_ir_scenario(capsys):
    rc = cli.main(["--no-color", "show", "ransomware_ir"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ir-isolate-host" in out


def test_show_unknown_scenario_returns_error(capsys):
    rc = cli.main(["--no-color", "show", "nope"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "error" in out.lower()


def test_submit_command_grades_and_records(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "attacker_ip": "203.0.113.55",
                "compromised_user": "root",
                "breach_time": "Jan 15 03:18:47",
                "failed_attempt_count": 9,
                "usernames_tried": [
                    "admin", "test", "oracle", "git", "ubuntu", "postgres", "deploy", "guest", "root",
                ],
            }
        ),
        encoding="utf-8",
    )
    history = tmp_path / "history.json"
    rc = cli.main(
        [
            "--no-color",
            "submit",
            "brute_force_ssh",
            "--answers",
            str(answers),
            "--history",
            str(history),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert history.exists()
    recorded = json.loads(history.read_text(encoding="utf-8"))
    assert recorded["brute_force_ssh"]["passed"] is True


def test_submit_command_missing_answers_file_errors(tmp_path, capsys):
    rc = cli.main(
        ["--no-color", "submit", "brute_force_ssh", "--answers", str(tmp_path / "missing.json")]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "error" in out.lower()


def test_submit_command_invalid_json_errors(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = cli.main(["--no-color", "submit", "brute_force_ssh", "--answers", str(bad)])
    assert rc == 1


def test_submit_command_unknown_scenario_errors(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text("{}", encoding="utf-8")
    rc = cli.main(["--no-color", "submit", "nope", "--answers", str(answers)])
    assert rc == 1


def test_submit_command_no_record_skips_history(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text("{}", encoding="utf-8")
    history = tmp_path / "history.json"
    rc = cli.main(
        [
            "--no-color",
            "submit",
            "brute_force_ssh",
            "--answers",
            str(answers),
            "--history",
            str(history),
            "--no-record",
        ]
    )
    assert rc == 2  # failed (empty submission), but a valid run
    assert not history.exists()


def test_report_command_with_no_history_warns(tmp_path, capsys):
    rc = cli.main(["--no-color", "report", "--history", str(tmp_path / "nope.json"), "--out", str(tmp_path / "out.html")])
    assert rc == 1


def test_report_command_generates_html_after_submit(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps({"selected_ids": ["ssh-permit-root-login", "ssh-permit-empty-passwords"]}),
        encoding="utf-8",
    )
    history = tmp_path / "history.json"
    cli.main(["--no-color", "submit", "sshd_hardening", "--answers", str(answers), "--history", str(history)])
    capsys.readouterr()

    out_path = tmp_path / "report.html"
    rc = cli.main(["--no-color", "report", "--history", str(history), "--out", str(out_path)])
    assert rc == 0
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "SSH Daemon Hardening Review" in content


def test_build_parser_requires_subcommand():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
