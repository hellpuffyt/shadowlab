"""Unit tests for the incident-response ordered-action rubric."""

from __future__ import annotations

from shadowlab.scoring.ir import ActionCatalog, ActionCatalogEntry, score_ir_sequence


def _catalog():
    entries = (
        ActionCatalogEntry("contain", "isolate the host", "containment", True),
        ActionCatalogEntry("eradicate", "remove malware", "eradication", True),
        ActionCatalogEntry("recover", "restore from backup", "recovery", True),
        ActionCatalogEntry("harmful1", "pay the ransom", "harmful", False),
        ActionCatalogEntry("harmful2", "reconnect immediately", "harmful", False),
    )
    return ActionCatalog(entries=entries, correct_order=("contain", "eradicate", "recover"))


def test_perfect_order_scores_full_points():
    result = score_ir_sequence(
        scenario_id="s",
        catalog=_catalog(),
        submitted_ids=("contain", "eradicate", "recover"),
        max_points=100,
    )
    assert result.points_earned == 100
    assert result.passed is True


def test_empty_submission_scores_only_the_avoided_harm_share():
    # Doing nothing includes no correct actions (coverage=0, order=0) but also
    # no harmful ones, so only the "avoided harmful actions" share is earned.
    result = score_ir_sequence(scenario_id="s", catalog=_catalog(), submitted_ids=(), max_points=100)
    coverage = next(fs for fs in result.field_scores if fs.field == "action coverage")
    order = next(fs for fs in result.field_scores if fs.field == "action ordering")
    penalty = next(fs for fs in result.field_scores if "harmful" in fs.field)
    assert coverage.points_earned == 0
    assert order.points_earned == 0
    assert penalty.points_earned == penalty.points_possible
    assert result.passed is False


def test_correct_actions_wrong_order_loses_order_points_only():
    result = score_ir_sequence(
        scenario_id="s",
        catalog=_catalog(),
        submitted_ids=("recover", "contain", "eradicate"),
        max_points=100,
    )
    coverage = next(fs for fs in result.field_scores if fs.field == "action coverage")
    order = next(fs for fs in result.field_scores if fs.field == "action ordering")
    assert coverage.ratio == 1.0
    assert order.ratio < 1.0
    assert result.points_earned < 100


def test_harmful_action_included_incurs_penalty():
    clean = score_ir_sequence(
        scenario_id="s", catalog=_catalog(), submitted_ids=("contain", "eradicate", "recover"), max_points=100
    )
    with_harm = score_ir_sequence(
        scenario_id="s",
        catalog=_catalog(),
        submitted_ids=("harmful1", "contain", "eradicate", "recover"),
        max_points=100,
    )
    assert with_harm.points_earned < clean.points_earned


def test_two_harmful_actions_zero_out_the_penalty_share():
    result = score_ir_sequence(
        scenario_id="s",
        catalog=_catalog(),
        submitted_ids=("harmful1", "harmful2", "contain", "eradicate", "recover"),
        max_points=100,
    )
    penalty_field = next(fs for fs in result.field_scores if "harmful" in fs.field)
    assert penalty_field.points_earned == 0


def test_partial_coverage_gives_partial_credit():
    result = score_ir_sequence(
        scenario_id="s", catalog=_catalog(), submitted_ids=("contain",), max_points=100
    )
    coverage = next(fs for fs in result.field_scores if fs.field == "action coverage")
    assert 0 < coverage.ratio < 1


def test_unknown_ids_are_ignored():
    result = score_ir_sequence(
        scenario_id="s",
        catalog=_catalog(),
        submitted_ids=("contain", "not-a-real-id", "eradicate", "recover"),
        max_points=100,
    )
    assert result.points_earned == 100


def test_single_correct_action_included_gets_full_order_credit():
    result = score_ir_sequence(
        scenario_id="s", catalog=_catalog(), submitted_ids=("contain",), max_points=100
    )
    order = next(fs for fs in result.field_scores if fs.field == "action ordering")
    assert order.ratio == 1.0


def test_catalog_by_id_lookup():
    catalog = _catalog()
    assert catalog.by_id("contain").phase == "containment"
    assert catalog.by_id("does-not-exist") is None
