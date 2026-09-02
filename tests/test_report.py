"""Tests for HTML report-card generation."""

from __future__ import annotations

from shadowlab.models import Category, FieldScore, Scenario, ScoreResult
from shadowlab.report import build_report_html


def _scenario(sid: str, category: Category) -> Scenario:
    return Scenario(
        id=sid,
        category=category,
        title=f"Title for {sid}",
        difficulty="easy",
        prompt="prompt",
        data_files=(),
        directory=sid,
        submission_schema={},
        max_points=100.0,
    )


def _result(sid: str, earned: float, possible: float, passed: bool) -> ScoreResult:
    return ScoreResult(
        scenario_id=sid,
        points_earned=earned,
        points_possible=possible,
        field_scores=(FieldScore(field="f1", points_earned=earned, points_possible=possible, detail="a detail"),),
        passed=passed,
    )


def test_report_contains_scenario_titles():
    pairs = [(_scenario("s1", Category.LOG_ANALYSIS), _result("s1", 80, 100, True))]
    html_out = build_report_html(pairs)
    assert "Title for s1" in html_out
    assert "<!doctype html>" in html_out


def test_report_escapes_html_in_titles_and_details():
    scenario = Scenario(
        id="s1",
        category=Category.LOG_ANALYSIS,
        title="<script>alert(1)</script>",
        difficulty="easy",
        prompt="prompt",
        data_files=(),
        directory="s1",
        submission_schema={},
        max_points=100.0,
    )
    result = ScoreResult(
        scenario_id="s1",
        points_earned=0,
        points_possible=100,
        field_scores=(FieldScore(field="f", points_earned=0, points_possible=100, detail="<b>evil</b>"),),
        passed=False,
    )
    html_out = build_report_html([(scenario, result)])
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out
    assert "<b>evil</b>" not in html_out


def test_report_computes_overall_percent():
    pairs = [
        (_scenario("s1", Category.LOG_ANALYSIS), _result("s1", 100, 100, True)),
        (_scenario("s2", Category.CONFIG_AUDIT), _result("s2", 0, 100, False)),
    ]
    html_out = build_report_html(pairs)
    assert "50%" in html_out or "50.0%" in html_out


def test_report_pass_count_shown():
    pairs = [
        (_scenario("s1", Category.LOG_ANALYSIS), _result("s1", 100, 100, True)),
        (_scenario("s2", Category.CONFIG_AUDIT), _result("s2", 100, 100, True)),
        (_scenario("s3", Category.INCIDENT_RESPONSE), _result("s3", 0, 100, False)),
    ]
    html_out = build_report_html(pairs)
    assert "2/3" in html_out


def test_report_handles_empty_results_list():
    html_out = build_report_html([])
    assert "<!doctype html>" in html_out
    assert "0/0" in html_out or "0%" in html_out


def test_report_custom_title():
    html_out = build_report_html([], title="My Custom Title")
    assert "My Custom Title" in html_out
