"""Consistency checks over the scenario registry itself.

These guard against a common authoring mistake: adding a scenario, catalog
entry, or field spec that silently doesn't line up with the rest of its
definition.
"""

from __future__ import annotations

from shadowlab.models import Category
from shadowlab.scenarios.registry import list_scenario_defs


def test_at_least_six_scenarios_registered():
    assert len(list_scenario_defs()) >= 6


def test_all_three_categories_represented():
    categories = {d.scenario.category for d in list_scenario_defs()}
    assert categories == set(Category)


def test_scenario_ids_are_unique():
    ids = [d.scenario.id for d in list_scenario_defs()]
    assert len(ids) == len(set(ids))


def test_every_scenario_directory_and_data_files_exist():
    for d in list_scenario_defs():
        for fname in d.scenario.data_files:
            path = d.data_path(fname)
            assert path.is_file(), f"{d.scenario.id}: missing data file {path}"


def test_log_fields_scenarios_have_matching_submission_schema_and_specs():
    for d in list_scenario_defs():
        if d.kind != "log_fields":
            continue
        schema_keys = set(d.scenario.submission_schema)
        spec_names = {spec.name for spec in d.field_specs}
        assert schema_keys == spec_names, d.scenario.id


def test_log_fields_scenarios_have_a_ground_truth_fn():
    for d in list_scenario_defs():
        if d.kind == "log_fields":
            assert d.ground_truth_fn is not None


def test_checklist_scenarios_have_a_catalog_and_ground_truth_fn():
    for d in list_scenario_defs():
        if d.kind == "checklist":
            assert d.checklist_catalog is not None
            assert d.ground_truth_fn is not None


def test_ir_scenarios_have_an_action_catalog_with_correct_order():
    for d in list_scenario_defs():
        if d.kind == "ir_sequence":
            assert d.action_catalog is not None
            assert len(d.action_catalog.correct_order) > 0
            all_ids = {e.id for e in d.action_catalog.entries}
            assert set(d.action_catalog.correct_order) <= all_ids


def test_ir_scenarios_have_at_least_one_harmful_distractor():
    for d in list_scenario_defs():
        if d.kind == "ir_sequence":
            assert any(not e.correct for e in d.action_catalog.entries), d.scenario.id


def test_checklist_scenarios_have_at_least_one_decoy_id():
    for d in list_scenario_defs():
        if d.kind != "checklist":
            continue
        real_ids = {f.rule_id for f in d.ground_truth_fn(d.read_data(d.scenario.data_files[0]))}
        decoys = set(d.checklist_catalog.all_ids) - real_ids
        assert decoys, d.scenario.id


def test_every_scenario_has_a_nonempty_prompt_and_positive_max_points():
    for d in list_scenario_defs():
        assert d.scenario.prompt.strip()
        assert d.scenario.max_points > 0


def test_ransomware_and_bec_prompts_reference_action_catalog():
    for sid in ("ransomware_ir", "phishing_bec_ir"):
        d = next(d for d in list_scenario_defs() if d.scenario.id == sid)
        assert "action_catalog" in d.scenario.prompt
