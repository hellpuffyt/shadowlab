"""The scenario engine: the one entry point CLI and tests should use.

Loads scenario metadata, computes real ground truth on demand (never at
import time, so tests can exercise the detectors independently), and grades
a learner's submission against the appropriate rubric.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shadowlab.models import Category, Scenario, ScoreResult
from shadowlab.scenarios.registry import ScenarioDef, get_scenario_def, list_scenario_defs
from shadowlab.scoring.checklist import score_checklist
from shadowlab.scoring.ir import score_ir_sequence
from shadowlab.scoring.rubric import score_fields


class UnknownScenarioError(KeyError):
    """Raised when a scenario id doesn't exist in the registry."""

    def __str__(self) -> str:
        # KeyError.__str__ repr()s its argument, which quoted the message
        # twice once the registry's KeyError was re-wrapped here.
        return str(self.args[0]) if self.args else ""


class InvalidSubmissionError(ValueError):
    """Raised when a submission doesn't match the shape a scenario expects."""


@dataclass(frozen=True, slots=True)
class ScenarioBundle:
    """A scenario ready to present to a learner: metadata + its raw fixture text."""

    scenario: Scenario
    data: dict[str, str]  # filename -> file contents


def list_scenarios(category: Category | None = None) -> tuple[Scenario, ...]:
    defs = list_scenario_defs()
    if category is not None:
        defs = tuple(d for d in defs if d.scenario.category == category)
    return tuple(d.scenario for d in defs)


def load_scenario(scenario_id: str) -> ScenarioBundle:
    try:
        sdef = get_scenario_def(scenario_id)
    except KeyError as exc:
        raise UnknownScenarioError(exc.args[0] if exc.args else str(exc)) from exc
    data = {fname: sdef.read_data(fname) for fname in sdef.scenario.data_files}
    return ScenarioBundle(scenario=sdef.scenario, data=data)


def grade(scenario_id: str, submission: dict[str, Any]) -> ScoreResult:
    """Grade a learner's submission dict against one scenario's rubric.

    The expected shape of ``submission`` depends on the scenario kind:

    - log-analysis scenarios: a flat dict of field name -> value, matching
      ``scenario.submission_schema``.
    - config-audit scenarios: ``{"selected_ids": [...]}``.
    - incident-response scenarios: ``{"ordered_ids": [...]}``.
    """
    try:
        sdef = get_scenario_def(scenario_id)
    except KeyError as exc:
        raise UnknownScenarioError(exc.args[0] if exc.args else str(exc)) from exc

    if not isinstance(submission, dict):
        raise InvalidSubmissionError(f"submission must be a JSON object, got {type(submission).__name__}")

    if sdef.kind == "log_fields":
        assert sdef.ground_truth_fn is not None
        raw_text = sdef.read_data(sdef.scenario.data_files[0])
        ground_truth = sdef.ground_truth_fn(raw_text)
        return score_fields(
            scenario_id=scenario_id,
            ground_truth=ground_truth,
            submission=submission,
            specs=sdef.field_specs,
            max_points=sdef.scenario.max_points,
        )

    if sdef.kind == "checklist":
        assert sdef.ground_truth_fn is not None
        raw_text = sdef.read_data(sdef.scenario.data_files[0])
        findings = sdef.ground_truth_fn(raw_text)
        selected = submission.get("selected_ids", [])
        if not isinstance(selected, list) or not all(isinstance(x, str) for x in selected):
            raise InvalidSubmissionError("'selected_ids' must be a list of strings")
        assert sdef.checklist_catalog is not None
        return score_checklist(
            scenario_id=scenario_id,
            findings=findings,
            submitted_ids=tuple(selected),
            catalog=sdef.checklist_catalog,
            max_points=sdef.scenario.max_points,
        )

    if sdef.kind == "ir_sequence":
        ordered = submission.get("ordered_ids", [])
        if not isinstance(ordered, list) or not all(isinstance(x, str) for x in ordered):
            raise InvalidSubmissionError("'ordered_ids' must be a list of strings")
        assert sdef.action_catalog is not None
        return score_ir_sequence(
            scenario_id=scenario_id,
            catalog=sdef.action_catalog,
            submitted_ids=tuple(ordered),
            max_points=sdef.scenario.max_points,
        )

    raise AssertionError(f"unhandled scenario kind: {sdef.kind!r}")  # pragma: no cover


def scenario_def_for(scenario_id: str) -> ScenarioDef:
    """Expose the full ScenarioDef (catalogs, specs) for CLI display purposes."""
    try:
        return get_scenario_def(scenario_id)
    except KeyError as exc:
        raise UnknownScenarioError(exc.args[0] if exc.args else str(exc)) from exc
