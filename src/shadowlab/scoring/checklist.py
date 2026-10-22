"""Weighted checklist rubric used by config-audit scenarios.

Ground truth for a config-audit scenario is a real list of :class:`Finding`
produced by a genuine auditor function (see ``shadowlab.scoring.config_audit``)
run against the bundled config fixture -- not a hand-typed answer key. A
learner submits the set of rule ids they believe are findings. Each real
finding is worth points proportional to its severity; each id the learner
flags that is *not* a real finding (a false positive) costs a flat penalty,
so guessing everything is not a winning strategy.
"""

from __future__ import annotations

from dataclasses import dataclass

from shadowlab.models import FieldScore, Finding, ScoreResult

_SEVERITY_WEIGHT = {
    "info": 1.0,
    "low": 2.0,
    "medium": 3.0,
    "high": 5.0,
    "critical": 8.0,
}

# Share of the scenario's max points lost per incorrectly-flagged id. It is a
# fixed share (not scaled by the findings' severity weights) so that flagging
# every catalog id can never pass: with the bundled catalogs, "select all"
# previously scored 75% and 88.57% (both PASS).
_FALSE_POSITIVE_PENALTY_SHARE = 0.20


@dataclass(frozen=True, slots=True)
class ChecklistCatalog:
    """All rule ids a learner may choose from for one config-audit scenario."""

    all_ids: tuple[str, ...]
    descriptions: dict[str, str]


def score_checklist(
    *,
    scenario_id: str,
    findings: tuple[Finding, ...],
    submitted_ids: tuple[str, ...],
    catalog: ChecklistCatalog,
    max_points: float,
    pass_threshold: float = 0.7,
) -> ScoreResult:
    real_ids = {f.rule_id: f for f in findings}
    submitted = {rid for rid in submitted_ids if rid in catalog.all_ids}

    weight_total = sum(_SEVERITY_WEIGHT[f.severity.value] for f in findings) or 1.0
    field_scores: list[FieldScore] = []

    earned_raw = 0.0
    for rule_id, finding in real_ids.items():
        weight = _SEVERITY_WEIGHT[finding.severity.value]
        points_possible = round(weight / weight_total * max_points, 4)
        if rule_id in submitted:
            earned_raw += weight
            field_scores.append(
                FieldScore(
                    field=rule_id,
                    points_earned=points_possible,
                    points_possible=points_possible,
                    detail=f"found it: {finding.message} ({finding.severity.value})",
                )
            )
        else:
            field_scores.append(
                FieldScore(
                    field=rule_id,
                    points_earned=0.0,
                    points_possible=points_possible,
                    detail=f"missed: {finding.message} ({finding.severity.value})",
                )
            )

    false_positives = sorted(submitted - real_ids.keys())
    penalty_points = 0.0
    for fp_id in false_positives:
        penalty = round(_FALSE_POSITIVE_PENALTY_SHARE * max_points, 4)
        penalty_points += penalty
        field_scores.append(
            FieldScore(
                field=fp_id,
                points_earned=-penalty,
                points_possible=0.0,
                detail=f"flagged {catalog.descriptions.get(fp_id, fp_id)}, which is not a real finding here",
            )
        )

    points_earned = round(max(0.0, earned_raw / weight_total * max_points - penalty_points), 2)
    points_possible = round(max_points, 2)
    percent = points_earned / points_possible if points_possible else 0.0
    return ScoreResult(
        scenario_id=scenario_id,
        points_earned=points_earned,
        points_possible=points_possible,
        field_scores=tuple(field_scores),
        passed=percent >= pass_threshold,
    )
