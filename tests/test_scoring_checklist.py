"""Unit tests for the config-audit checklist rubric."""

from __future__ import annotations

from shadowlab.models import Finding, Severity
from shadowlab.scoring.checklist import ChecklistCatalog, score_checklist


def _findings():
    return (
        Finding(rule_id="crit1", severity=Severity.CRITICAL, message="critical thing"),
        Finding(rule_id="high1", severity=Severity.HIGH, message="high thing"),
        Finding(rule_id="low1", severity=Severity.LOW, message="low thing"),
    )


def _catalog():
    return ChecklistCatalog(
        all_ids=("crit1", "high1", "low1", "decoy1", "decoy2"),
        descriptions={
            "crit1": "critical",
            "high1": "high",
            "low1": "low",
            "decoy1": "decoy one",
            "decoy2": "decoy two",
        },
    )


def test_all_findings_selected_scores_full_points():
    result = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("crit1", "high1", "low1"),
        catalog=_catalog(),
        max_points=100,
    )
    assert result.points_earned == 100
    assert result.passed is True


def test_no_selection_scores_zero():
    result = score_checklist(
        scenario_id="s", findings=_findings(), submitted_ids=(), catalog=_catalog(), max_points=100
    )
    assert result.points_earned == 0
    assert result.passed is False


def test_higher_severity_findings_worth_more():
    only_crit = score_checklist(
        scenario_id="s", findings=_findings(), submitted_ids=("crit1",), catalog=_catalog(), max_points=100
    )
    only_low = score_checklist(
        scenario_id="s", findings=_findings(), submitted_ids=("low1",), catalog=_catalog(), max_points=100
    )
    assert only_crit.points_earned > only_low.points_earned


def test_false_positive_incurs_penalty():
    clean = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("crit1", "high1", "low1"),
        catalog=_catalog(),
        max_points=100,
    )
    with_fp = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("crit1", "high1", "low1", "decoy1"),
        catalog=_catalog(),
        max_points=100,
    )
    assert with_fp.points_earned < clean.points_earned


def test_score_never_goes_negative():
    result = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("decoy1", "decoy2"),
        catalog=_catalog(),
        max_points=100,
    )
    assert result.points_earned == 0


def test_unknown_ids_outside_catalog_are_ignored():
    result = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("crit1", "high1", "low1", "not-in-catalog"),
        catalog=_catalog(),
        max_points=100,
    )
    assert result.points_earned == 100  # unknown id neither helps nor penalizes


def test_field_scores_include_missed_and_false_positive_details():
    result = score_checklist(
        scenario_id="s",
        findings=_findings(),
        submitted_ids=("crit1", "decoy1"),
        catalog=_catalog(),
        max_points=100,
    )
    details = {fs.field: fs.detail for fs in result.field_scores}
    assert "missed" in details["high1"]
    assert "not a real finding" in details["decoy1"]


def test_no_real_findings_and_no_selection_does_not_crash():
    result = score_checklist(
        scenario_id="s", findings=(), submitted_ids=(), catalog=_catalog(), max_points=100
    )
    assert result.points_possible == 100
    # weight_total defaults to 1.0 when there are no findings, earned_raw stays 0
    assert result.points_earned == 0
