# Contributing to shadowlab

Thanks for considering a contribution. shadowlab is a defensive-only
teaching lab: every fixture is synthetic, every scoring path runs locally,
and nothing in this repository should ever perform an offensive or
destructive action against a real target. Contributions that would change
that (real network calls, actual exploit payloads, credential harvesting,
etc.) will not be accepted.

## Setting up

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Running the checks locally

```bash
ruff check .                                   # lint
mypy src/shadowlab                             # strict type-check
pytest --cov=shadowlab --cov-report=term-missing  # tests + coverage
```

All three must pass cleanly (zero warnings) before a PR is merged; CI runs
the same three commands across Python 3.11-3.13 on Linux, Windows, and
macOS.

## Adding a new scenario

1. Pick a category: `log-analysis`, `config-audit`, or `incident-response`.
2. Add synthetic fixture data under `src/shadowlab/scenarios/<id>/data/`.
   Never reuse real logs, real hostnames/IPs from your own infrastructure,
   or real incident data -- write clearly fictional but plausible fixtures.
3. For `log-analysis`, write a *real* detector in `shadowlab.scoring` that
   computes the answer from the fixture (see `scoring/logs.py` and
   `scoring/flow.py`) -- ground truth must never be a hand-typed answer key
   with no corresponding algorithm.
4. For `config-audit`, add rule checks to `scoring/config_audit.py` and
   register a `ChecklistCatalog` including at least one decoy id that is
   *not* a real finding, so flagging everything isn't a winning strategy.
5. For `incident-response`, write an `ActionCatalog` with an ordered list of
   correct actions and at least one harmful/wrong distractor.
6. Register the scenario in `src/shadowlab/scenarios/registry.py`.
7. Add a golden-file test pinning your detector's output against your
   fixture (see `tests/test_scoring_logs.py` for the pattern), plus
   registry-consistency assertions will run automatically via
   `tests/test_registry.py`.

## Code style

- Type hints everywhere; the codebase is `mypy --strict` clean.
- `ruff` (line length 130) is the formatter/linter of record.
- Prefer small, pure functions in `shadowlab.scoring` that are easy to unit
  test in isolation from the CLI and engine.

## Reporting issues

Open a GitHub issue describing the scenario/behavior you expected vs. what
you saw. Since everything here is local and synthetic, please include the
exact CLI command and JSON submission that reproduces the problem.
