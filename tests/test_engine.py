"""End-to-end tests for the scenario engine (list/load/grade dispatch)."""

from __future__ import annotations

import pytest

from shadowlab import engine
from shadowlab.engine import InvalidSubmissionError, UnknownScenarioError
from shadowlab.models import Category
from shadowlab.scenarios.registry import get_scenario_def


def test_list_scenarios_returns_all_by_default():
    assert len(engine.list_scenarios()) >= 6


def test_list_scenarios_filters_by_category():
    only_log = engine.list_scenarios(Category.LOG_ANALYSIS)
    assert all(s.category == Category.LOG_ANALYSIS for s in only_log)
    assert len(only_log) >= 2


def test_load_scenario_returns_bundle_with_data():
    bundle = engine.load_scenario("brute_force_ssh")
    assert bundle.scenario.id == "brute_force_ssh"
    assert "auth.log" in bundle.data
    assert "203.0.113.55" in bundle.data["auth.log"]


def test_load_unknown_scenario_raises():
    with pytest.raises(UnknownScenarioError):
        engine.load_scenario("does-not-exist")


def test_grade_unknown_scenario_raises():
    with pytest.raises(UnknownScenarioError):
        engine.grade("does-not-exist", {})


def test_grade_non_dict_submission_raises():
    with pytest.raises(InvalidSubmissionError):
        engine.grade("brute_force_ssh", ["not", "a", "dict"])  # type: ignore[arg-type]


def test_grade_checklist_rejects_non_list_selected_ids():
    with pytest.raises(InvalidSubmissionError):
        engine.grade("firewall_audit", {"selected_ids": "not-a-list"})


def test_grade_ir_rejects_non_list_ordered_ids():
    with pytest.raises(InvalidSubmissionError):
        engine.grade("ransomware_ir", {"ordered_ids": "not-a-list"})


def test_grade_log_fields_scenario_end_to_end():
    result = engine.grade(
        "web_scanner_probe",
        {
            "attacker_ip": "198.51.100.77",
            "scanner_user_agent": "sqlmap/1.7.2#stable (http://sqlmap.org)",
            "suspicious_request_count": 9,
            "webshell_path": "/uploads/shell.php",
            "first_probe_time": "15/Jan/2026:04:02:11 +0000",
        },
    )
    assert result.percent == 100.0


def test_grade_checklist_scenario_end_to_end():
    result = engine.grade("sshd_hardening", {"selected_ids": ["ssh-permit-root-login"]})
    assert 0 < result.percent < 100


def test_grade_ir_scenario_end_to_end():
    sdef = get_scenario_def("phishing_bec_ir")
    result = engine.grade("phishing_bec_ir", {"ordered_ids": list(sdef.action_catalog.correct_order)})
    assert result.percent == 100.0
    assert result.passed


def test_scenario_def_for_unknown_raises():
    with pytest.raises(UnknownScenarioError):
        engine.scenario_def_for("nope")


def test_scenario_def_for_known_returns_def():
    sdef = engine.scenario_def_for("firewall_audit")
    assert sdef.kind == "checklist"


@pytest.mark.parametrize("scenario_id", [s.id for s in engine.list_scenarios()])
def test_grading_an_empty_submission_never_crashes(scenario_id):
    sdef = engine.scenario_def_for(scenario_id)
    if sdef.kind == "log_fields":
        submission = {}
    elif sdef.kind == "checklist":
        submission = {"selected_ids": []}
    else:
        submission = {"ordered_ids": []}
    result = engine.grade(scenario_id, submission)
    assert result.points_earned == 0 or result.points_earned >= 0
    assert result.passed is False


def test_unknown_scenario_message_is_not_double_quoted() -> None:
    with pytest.raises(UnknownScenarioError) as info:
        engine.load_scenario("nope")
    message = str(info.value)
    assert message.startswith("unknown scenario id 'nope'")
    assert not message.startswith(("'", '"'))
