"""Incident-response scenario rubric: scored, ordered action selection.

Each IR scenario ships an ``ActionCatalog`` -- a mix of genuinely correct
response actions (each tagged with its IR phase) and deliberately wrong or
harmful distractors. A learner submits an ordered list of catalog action
ids. Scoring rewards three independent things, each explained on its own
line:

1. Coverage -- how many of the truly-correct actions were included at all.
2. Ordering -- among the correct actions the learner included, how many
   pairs respect the correct relative order (earlier phases before later
   ones, per NIST-style Identification -> Containment -> Eradication ->
   Recovery -> Lessons Learned).
3. Harm avoidance -- a share that is lost (half per action) when
   harmful/incorrect actions are included, plus a further flat deduction of
   10% of the scenario's points per harmful action, since a real responder
   is graded down for doing the wrong thing even if they also did some
   right things.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from shadowlab.models import FieldScore, ScoreResult

_COVERAGE_SHARE = 0.55
_ORDER_SHARE = 0.30
_PENALTY_SHARE = 0.15
# Additionally deducted from the total for *each* harmful/incorrect action
# included. Without it the three shares above cap the cost of harmful actions
# at 15 points, so submitting the whole catalog (paying the ransom included)
# scored 85% and passed.
_HARMFUL_DEDUCTION_SHARE = 0.10


@dataclass(frozen=True, slots=True)
class ActionCatalogEntry:
    id: str
    text: str
    phase: str
    correct: bool  # False => a distractor: wrong, harmful, or out-of-scope


@dataclass(frozen=True, slots=True)
class ActionCatalog:
    entries: tuple[ActionCatalogEntry, ...]
    correct_order: tuple[str, ...]  # ideal ordering of the correct-only ids

    def by_id(self, action_id: str) -> ActionCatalogEntry | None:
        for e in self.entries:
            if e.id == action_id:
                return e
        return None


def score_ir_sequence(
    *,
    scenario_id: str,
    catalog: ActionCatalog,
    submitted_ids: tuple[str, ...],
    max_points: float,
    pass_threshold: float = 0.7,
) -> ScoreResult:
    correct_ids = set(catalog.correct_order)
    known_ids = {e.id for e in catalog.entries}
    submitted = [aid for aid in submitted_ids if aid in known_ids]

    included_correct = [aid for aid in submitted if aid in correct_ids]
    coverage_ratio = len(set(included_correct)) / len(correct_ids) if correct_ids else 1.0

    # Order score: fraction of pairs of included-correct actions whose
    # relative order in the submission matches the ideal order.
    rank = {aid: i for i, aid in enumerate(catalog.correct_order)}
    pairs = list(combinations(dict.fromkeys(included_correct), 2))
    if pairs:
        concordant = sum(
            1
            for a, b in pairs
            if (submitted.index(a) < submitted.index(b)) == (rank[a] < rank[b])
        )
        order_ratio = concordant / len(pairs)
    else:
        order_ratio = 1.0 if included_correct else 0.0

    harmful_included = [aid for aid in submitted if aid not in correct_ids]
    penalty_ratio = max(0.0, 1.0 - 0.5 * len(harmful_included))

    coverage_points = round(coverage_ratio * _COVERAGE_SHARE * max_points, 2)
    order_points = round(order_ratio * _ORDER_SHARE * max_points, 2)
    penalty_points = round(penalty_ratio * _PENALTY_SHARE * max_points, 2)

    field_scores: tuple[FieldScore, ...] = (
        FieldScore(
            field="action coverage",
            points_earned=coverage_points,
            points_possible=round(_COVERAGE_SHARE * max_points, 2),
            detail=(
                f"included {len(set(included_correct))}/{len(correct_ids)} of the correct "
                f"response actions"
            ),
        ),
        FieldScore(
            field="action ordering",
            points_earned=order_points,
            points_possible=round(_ORDER_SHARE * max_points, 2),
            detail=(
                f"{round(order_ratio * 100)}% of ordering constraints respected among the "
                "correct actions you included (containment before eradication before recovery)"
            ),
        ),
        FieldScore(
            field="avoided harmful actions",
            points_earned=penalty_points,
            points_possible=round(_PENALTY_SHARE * max_points, 2),
            detail=(
                "no incorrect/harmful actions included"
                if not harmful_included
                else f"included {len(harmful_included)} incorrect or harmful action(s): "
                + ", ".join(sorted(harmful_included))
            ),
        ),
    )
    deduction = round(_HARMFUL_DEDUCTION_SHARE * max_points * len(harmful_included), 2)
    if harmful_included:
        field_scores = (
            *field_scores,
            FieldScore(
                field="unsafe-action deduction",
                points_earned=-deduction,
                points_possible=0.0,
                detail=(
                    f"-{_HARMFUL_DEDUCTION_SHARE * max_points:g} per incorrect or harmful action "
                    f"({len(harmful_included)} included)"
                ),
            ),
        )
    points_earned = round(max(0.0, coverage_points + order_points + penalty_points - deduction), 2)
    points_possible = round(max_points, 2)
    percent = points_earned / points_possible if points_possible else 0.0
    return ScoreResult(
        scenario_id=scenario_id,
        points_earned=points_earned,
        points_possible=points_possible,
        field_scores=field_scores,
        passed=percent >= pass_threshold,
    )
