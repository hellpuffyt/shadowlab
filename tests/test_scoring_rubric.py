"""Unit tests for the generic field-comparison rubric."""

from __future__ import annotations

from shadowlab.scoring.rubric import FieldSpec, score_fields


def _specs():
    return (
        FieldSpec("a", weight=1, kind="exact_ci", label="A"),
        FieldSpec("b", weight=1, kind="int_tolerance", tolerance=1, label="B"),
        FieldSpec("c", weight=1, kind="str_set_ci", label="C"),
        FieldSpec("d", weight=1, kind="optional_exact_ci", label="D"),
    )


def test_perfect_submission_scores_full_points():
    gt = {"a": "Foo", "b": 10, "c": ["x", "y"], "d": None}
    sub = {"a": "foo", "b": 10, "c": ["y", "x"], "d": None}
    result = score_fields(scenario_id="s", ground_truth=gt, submission=sub, specs=_specs(), max_points=100)
    assert result.points_earned == 100
    assert result.passed is True


def test_all_wrong_scores_zero_or_near_zero():
    gt = {"a": "Foo", "b": 10, "c": ["x"], "d": "real"}
    sub = {"a": "bar", "b": 999, "c": [], "d": None}
    result = score_fields(scenario_id="s", ground_truth=gt, submission=sub, specs=_specs(), max_points=100)
    assert result.points_earned < 30
    assert result.passed is False


def test_exact_ci_is_case_insensitive_and_trims_whitespace():
    gt = {"a": "  Hello  "}
    sub = {"a": "hello"}
    specs = (FieldSpec("a", weight=1, kind="exact_ci"),)
    result = score_fields(scenario_id="s", ground_truth=gt, submission=sub, specs=specs, max_points=100)
    assert result.points_earned == 100


def test_int_tolerance_within_window_full_credit():
    specs = (FieldSpec("n", weight=1, kind="int_tolerance", tolerance=2),)
    result = score_fields(
        scenario_id="s", ground_truth={"n": 10}, submission={"n": 12}, specs=specs, max_points=100
    )
    assert result.points_earned == 100


def test_int_tolerance_partial_credit_decays_with_distance():
    specs = (FieldSpec("n", weight=1, kind="int_tolerance", tolerance=2),)
    near = score_fields(scenario_id="s", ground_truth={"n": 10}, submission={"n": 14}, specs=specs, max_points=100)
    far = score_fields(scenario_id="s", ground_truth={"n": 10}, submission={"n": 100}, specs=specs, max_points=100)
    assert near.points_earned > far.points_earned
    assert far.points_earned == 0


def test_int_tolerance_non_numeric_submission_scores_zero():
    specs = (FieldSpec("n", weight=1, kind="int_tolerance", tolerance=0),)
    result = score_fields(
        scenario_id="s", ground_truth={"n": 10}, submission={"n": "not a number"}, specs=specs, max_points=100
    )
    assert result.points_earned == 0


def test_str_set_ci_partial_overlap():
    specs = (FieldSpec("s", weight=1, kind="str_set_ci"),)
    result = score_fields(
        scenario_id="s",
        ground_truth={"s": ["a", "b", "c", "d"]},
        submission={"s": ["a", "b"]},
        specs=specs,
        max_points=100,
    )
    assert 0 < result.points_earned < 100


def test_str_set_ci_both_empty_full_credit():
    specs = (FieldSpec("s", weight=1, kind="str_set_ci"),)
    result = score_fields(scenario_id="s", ground_truth={"s": []}, submission={"s": []}, specs=specs, max_points=100)
    assert result.points_earned == 100


def test_optional_exact_ci_none_ground_truth_matches_falsy_submission():
    specs = (FieldSpec("d", weight=1, kind="optional_exact_ci"),)
    for falsy in (None, "", []):
        result = score_fields(
            scenario_id="s", ground_truth={"d": None}, submission={"d": falsy}, specs=specs, max_points=100
        )
        assert result.points_earned == 100


def test_optional_exact_ci_none_ground_truth_but_submission_present_scores_zero():
    specs = (FieldSpec("d", weight=1, kind="optional_exact_ci"),)
    result = score_fields(
        scenario_id="s", ground_truth={"d": None}, submission={"d": "/x.php"}, specs=specs, max_points=100
    )
    assert result.points_earned == 0


def test_missing_submission_key_treated_as_none():
    specs = (FieldSpec("a", weight=1, kind="exact_ci"),)
    result = score_fields(scenario_id="s", ground_truth={"a": "x"}, submission={}, specs=specs, max_points=100)
    assert result.points_earned == 0


def test_weights_distribute_points_proportionally():
    specs = (
        FieldSpec("a", weight=3, kind="exact_ci"),
        FieldSpec("b", weight=1, kind="exact_ci"),
    )
    result = score_fields(
        scenario_id="s",
        ground_truth={"a": "x", "b": "y"},
        submission={"a": "x", "b": "wrong"},
        specs=specs,
        max_points=100,
    )
    assert result.points_earned == 75.0


def test_pass_threshold_is_configurable():
    specs = (FieldSpec("a", weight=1, kind="exact_ci"),)
    result = score_fields(
        scenario_id="s",
        ground_truth={"a": "x"},
        submission={"a": "wrong"},
        specs=specs,
        max_points=100,
        pass_threshold=0.0,
    )
    assert result.passed is True


def test_field_scores_are_returned_in_spec_order():
    result = score_fields(
        scenario_id="s",
        ground_truth={"a": "x", "b": 1, "c": [], "d": None},
        submission={"a": "x", "b": 1, "c": [], "d": None},
        specs=_specs(),
        max_points=100,
    )
    assert [fs.field for fs in result.field_scores] == ["A", "B", "C", "D"]
