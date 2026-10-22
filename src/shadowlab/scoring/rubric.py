"""Generic weighted field-comparison rubric used by log-analysis scenarios.

A scenario's ground truth is a plain ``dict`` (produced by a real detector
running against the bundled fixture, never a hand-typed answer key -- see
``shadowlab.scoring.logs`` / ``shadowlab.scoring.flow``). A learner's
submission is compared field-by-field against that ground truth using a
declarative list of :class:`FieldSpec`, each contributing a weighted share
of the scenario's points. Every field produces a plain-English explanation
of why it earned what it earned, so the rubric is not a black box.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from shadowlab.models import FieldScore, ScoreResult


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """How one submission field is compared against ground truth."""

    name: str
    weight: float
    kind: str  # "exact_ci" | "int_tolerance" | "str_set_ci" | "optional_exact_ci"
    label: str = ""
    tolerance: int = 0

    def describe(self) -> str:
        return self.label or self.name


def _norm_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _score_exact_ci(gt: Any, submitted: Any) -> tuple[float, str]:
    gt_norm, sub_norm = _norm_str(gt), _norm_str(submitted)
    if gt_norm == sub_norm and gt_norm != "":
        return 1.0, f"correct ({gt!r})"
    if gt_norm == "" and sub_norm == "":
        return 1.0, "correctly left blank"
    return 0.0, f"expected {gt!r}, got {submitted!r}"


def _score_optional_exact_ci(gt: Any, submitted: Any) -> tuple[float, str]:
    if gt is None:
        if submitted in (None, "", []):
            return 1.0, "correctly identified no finding"
        return 0.0, f"expected no finding, but got {submitted!r}"
    return _score_exact_ci(gt, submitted)


def _score_int_tolerance(gt: Any, submitted: Any, tolerance: int) -> tuple[float, str]:
    try:
        gt_n = int(gt)
        sub_n = int(submitted)
    except (TypeError, ValueError, OverflowError):  # OverflowError: JSON 1e999 -> inf
        return 0.0, f"expected an integer near {gt!r}, got {submitted!r}"
    diff = abs(gt_n - sub_n)
    if diff <= tolerance:
        return 1.0, f"within tolerance (expected {gt_n}, got {sub_n})"
    # linear partial credit that reaches zero at 4x the tolerance window
    spread = max(tolerance, 1) * 4
    ratio = max(0.0, 1.0 - diff / spread)
    return ratio, f"expected {gt_n} (+/-{tolerance}), got {sub_n}, off by {diff}"


def _score_str_set_ci(gt: Any, submitted: Any) -> tuple[float, str]:
    if submitted is not None and not isinstance(submitted, (list, tuple)):
        # A bare string would otherwise be iterated character by character,
        # and a number would raise TypeError.
        return 0.0, f"expected a list of strings, got {type(submitted).__name__}"
    gt_set = {_norm_str(v) for v in (gt or ())} - {""}
    sub_set = {_norm_str(v) for v in (submitted or ())} - {""}
    if not gt_set and not sub_set:
        return 1.0, "correctly empty"
    if not gt_set:
        return 0.0, f"expected an empty set, got {sorted(sub_set)}"
    intersection = gt_set & sub_set
    union = gt_set | sub_set
    ratio = len(intersection) / len(union) if union else 1.0
    missing = sorted(gt_set - sub_set)
    extra = sorted(sub_set - gt_set)
    detail = f"{len(intersection)}/{len(gt_set)} matched"
    if missing:
        detail += f", missing {missing}"
    if extra:
        detail += f", unexpected {extra}"
    return ratio, detail


_SCORERS: dict[str, Callable[[Any, Any, int], tuple[float, str]]] = {
    "exact_ci": lambda gt, sub, tol: _score_exact_ci(gt, sub),
    "optional_exact_ci": lambda gt, sub, tol: _score_optional_exact_ci(gt, sub),
    "int_tolerance": lambda gt, sub, tol: _score_int_tolerance(gt, sub, tol),
    "str_set_ci": lambda gt, sub, tol: _score_str_set_ci(gt, sub),
}


def score_fields(
    *,
    scenario_id: str,
    ground_truth: dict[str, Any],
    submission: dict[str, Any],
    specs: tuple[FieldSpec, ...],
    max_points: float,
    pass_threshold: float = 0.7,
) -> ScoreResult:
    """Score a submission dict against a ground-truth dict, field by field."""
    total_weight = sum(spec.weight for spec in specs) or 1.0
    field_scores: list[FieldScore] = []
    for spec in specs:
        scorer = _SCORERS[spec.kind]
        ratio, detail = scorer(ground_truth.get(spec.name), submission.get(spec.name), spec.tolerance)
        ratio = max(0.0, min(1.0, ratio))
        points_possible = round(spec.weight / total_weight * max_points, 4)
        points_earned = round(points_possible * ratio, 4)
        field_scores.append(
            FieldScore(
                field=spec.describe(),
                points_earned=points_earned,
                points_possible=points_possible,
                detail=detail,
            )
        )
    points_earned = round(sum(f.points_earned for f in field_scores), 2)
    points_possible = round(sum(f.points_possible for f in field_scores), 2)
    percent = (points_earned / points_possible) if points_possible else 0.0
    return ScoreResult(
        scenario_id=scenario_id,
        points_earned=points_earned,
        points_possible=points_possible,
        field_scores=tuple(field_scores),
        passed=percent >= pass_threshold,
    )
