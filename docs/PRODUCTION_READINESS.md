# Production readiness — shadowlab

Audit date: 2026-10-22. Tested code commit: `c64eaa1` (branch
`audit/production-readiness`); later commits change documentation and
repository metadata only.

## Scope

A local CLI (`list` / `show` / `submit` / `report`) that presents seven
synthetic blue-team exercises (log analysis, config audit, incident
response) and grades JSON answers with partial credit. Ground truth for
log/config scenarios is computed at grading time by detector functions run
over bundled fixtures; IR scenarios use an authored ideal action order plus
distractors. Architecture: `scenarios/registry.py` (metadata + wiring) →
`engine.py` (`grade`) → `scoring/` (rubric, checklist, IR scorers) →
`cli.py` (Rich terminal output) and `report.py` (static HTML).

"Sandboxed" is a property of the design, not an OS sandbox: nothing
submitted is executed, and no network or process access exists (verified
by test, below).

## Platforms and prerequisites

Python ≥ 3.10, dependency `rich`. Verified on macOS 27 (Apple Silicon) with
Python 3.12 (full CI steps + clean clone), 3.11 and 3.13 (test suite).
Linux/Windows legs of CI were not run for this audit. No services,
credentials or network needed.

## Clean-clone verification (README Quickstart + Development, literally)

```bash
git clone -b audit/production-readiness <repo> shadowlab && cd shadowlab
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .                                   # exit 0
shadowlab list                                     # 7 scenarios, exit 0
shadowlab --no-color show ransomware_ir            # exit 0, no phase column
shadowlab --no-color submit brute_force_ssh --answers ../sl-answers.json --history ../sl-h.json  # 100%, exit 0
shadowlab --no-color report --history ../sl-h.json --out ../sl-report.html                     # exit 0
pip install -e ".[dev]"
ruff check .                                       # exit 0
mypy src/shadowlab                                 # no issues in 14 files
pytest --cov=shadowlab --cov-report=term-missing   # 156 passed, 97% coverage
```

## Commands and outcomes

| Step | Command | Exit | Result |
|---|---|---:|---|
| Baseline (main `eec2352`) | `pytest -q --cov=shadowlab --cov-fail-under=90` | 0 | 124 passed, 0 failed, 0 skipped; 97.5% |
| Baseline lint/types | `ruff check .` / `mypy src/shadowlab` | 0 / 0 | clean |
| Final (3.12) | same as CI | 0 | 156 passed, 0 failed, 0 skipped; 97.0% |
| Final (3.11, 3.13) | `pytest -q` | 0 / 0 | 156 passed each |
| Final lint/types | `ruff check .` / `mypy src/shadowlab` | 0 / 0 | clean |
| Dependency audit | `uvx pip-audit -r <frozen env> --disable-pip --no-deps --strict` | 0 | no known vulnerabilities (rich 15.0.0, markdown-it-py 4.2.0, mdurl, pygments 2.21.0) |
| Secret scan, tree | `detect-secrets scan --all-files` | – | 1 hit: the string "PermitEmptyPasswords yes" (false positive) |
| Secret scan, history | credential-pattern `git grep` over all revisions; filenames | – | none |

The new tests were also run against the original code: 23 of 32 fail
there (the 9 that pass assert behaviour that was already correct, e.g. HTML
escaping and the no-network property).

CI: default branch `main`: **success** (run on `eec2352`). Audit branch:
pending until pushed.

## Bugs found and fixed (each with regression tests in `tests/test_audit_regressions.py`)

| # | Severity | Defect | Fix |
|---|---|---|---|
| 1 | High (grading integrity) | Selecting every config-audit id passed (75% / 88.57%), contradicting the README | false positive costs 20% of points each |
| 2 | High (grading integrity) | Submitting the whole IR catalog in display order passed at 85%, including "pay the ransom" | each harmful action deducts a further 10% of points |
| 3 | High (answer-key leak) | `show` printed a phase column that labelled every distractor `harmful`, in the ideal order | alphabetical listing, no phase |
| 4 | Medium (crash) | Rich markup in an answer (`[/x]`) raised `MarkupError` | escape learner text |
| 5 | Medium (data loss) | Corrupt history silently replaced → all recorded attempts lost; non-object history crashed | refuse to record, leave file untouched; atomic writes |
| 6 | Low (crash) | number/`1e999`/nested lists in answers → `TypeError`/`OverflowError`; bare string split into characters | score 0 with explanation, or "invalid submission" |
| 7 | Low (crash) | `report` crashed on a malformed history record | skip and warn |

Expected values in existing tests were **not** changed. The scoring change
is a deliberate behaviour change justified by the README's own claims
("submitting every possible id is not a winning strategy"; harmful actions
"cost you points"). Known design choices left as-is: an empty IR plan still
earns the 15% "avoided harmful actions" share, and a single correct action
earns full ordering credit (both still fail).

## Security review

- No `eval`/`exec`/`pickle`/`yaml`/`subprocess`/socket use in `src/`
  (static grep), and a runtime test runs every command for every scenario
  with sockets, `subprocess.Popen`, `os.system`, `exec*`/`spawn*`/`fork`
  patched to fail, asserting only `--history`/`--out` files are written.
- Scenario ids are dictionary keys; fixture paths come only from the
  registry, so `show ../../x` cannot traverse.
- Terminal: Rich strips control characters; markup is escaped (test).
  HTML report: all text `html.escape`d; numbers type-checked when loaded
  from history (test with `<script>` / `<img onerror>` payloads).
- CI workflow now has `permissions: contents: read`.
- History hits: none. No rotation needed.

## Known limitations and risks

- Detectors are verified only against the bundled fixtures.
- IR ground truth is an authored order; alternative valid orders lose points.
- Ground truth ships with the package; this is a self-study tool, not an
  exam platform.
- Linux/Windows not executed in this audit.

## Acceptance checklist

| Item | Expected | Command / test | Result | Actual | Reference |
|---|---|---|---|---|---|
| A1 | Clean install + quick start | README Quickstart | pass | exit 0 | clean clone |
| A2 | CI steps green | ruff, mypy, pytest --cov-fail-under=90 | pass | 156 passed, 97% | CI config |
| A3 | Correct answers score 100 for every scenario kind | tests | pass | yes | `test_exact_findings_*`, `test_ideal_ir_plan_*`, existing tests |
| A4 | Guessing all ids / whole catalog fails | tests | pass | FAIL in all orders | `test_selecting_every_*`, `test_submitting_the_whole_ir_catalog_*` |
| A5 | `show` does not leak the answer key | test | pass | no phase, alphabetical | `test_show_does_not_reveal_*` |
| A6 | No network/process; only named files written | test | pass | yes | `test_no_command_opens_*` |
| A7 | Hostile text cannot crash or inject (terminal/HTML) | tests | pass | yes | markup/escape/HTML tests |
| A8 | History never lost on bad input | tests | pass | file unchanged, exit 1 | `test_unreadable_history_*` |

## Classification proposal

**Partially Verified** — documented features work and are tested on macOS
with Python 3.11–3.13, guessing loopholes and the answer-key leak are fixed,
and the clean clone passes. Not verified: Linux/Windows CI on the audit
branch (pending push).
