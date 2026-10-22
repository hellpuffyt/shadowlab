# Changelog

All notable changes to this project are documented in this file.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Guessing strategies passed: selecting every config-audit id scored 75% /
  88.57% (PASS); submitting the whole IR catalog in display order scored
  85% (PASS) including the harmful actions. False positives now cost 20% of
  the points each, and each harmful IR action deducts a further 10%.
- `shadowlab show` revealed the IR answer key: a "phase" column labelled
  every distractor `harmful`, and rows were printed in the ideal order.
  Catalogs are now listed alphabetically without phases.
- A submitted answer containing Rich markup (e.g. `[/x]`) crashed the CLI;
  learner text is now escaped.
- Wrongly-typed answers (a number or bare string for a list field, `1e999`
  for a count, non-string ids) raised tracebacks or were split into
  characters; they now score zero or are rejected as invalid submissions.
- A corrupt or non-object history file was silently replaced (losing all
  recorded attempts) or crashed `submit`; it is now left untouched and
  reported. `report` skips malformed records instead of crashing. History
  writes are atomic.

### Added

- Tests for the "no network / no process / writes only named files" claim.
- `SECURITY.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.

## [0.1.0] - 2026-09-02

### Added

- Scenario engine (`shadowlab.engine`) that loads bundled synthetic
  fixtures, computes real ground truth, and grades learner submissions.
- Seven scenarios across all three exercise families:
  - **log-analysis**: `brute_force_ssh` (sliding-window SSH credential
    stuffing + breach detection), `web_scanner_probe` (automated scanner +
    webshell-upload detection over an nginx-style access log),
    `exfil_flow_logs` (data-exfiltration pattern in NetFlow-style flow logs).
  - **config-audit**: `firewall_audit` (iptables-save ruleset review),
    `sshd_hardening` (sshd_config hardening review).
  - **incident-response**: `ransomware_ir` (file-server ransomware triage,
    ordered response actions), `phishing_bec_ir` (business email
    compromise / attempted wire fraud, ordered response actions).
- Real, independently-testable detectors (`shadowlab.scoring.logs`,
  `.flow`, `.config_audit`) -- scenario "ground truth" is always the
  verified output of an algorithm run against the bundled fixture, never a
  hand-typed answer key.
- Three grading rubrics with partial credit and per-item explanations:
  weighted field comparison (`scoring.rubric`), a severity-weighted
  checklist with a false-positive penalty (`scoring.checklist`), and an
  ordered-action rubric that scores coverage, ordering, and avoidance of
  harmful actions independently (`scoring.ir`).
- A `rich`-powered terminal experience (`shadowlab list`, `show`, `submit`,
  `report`) and a self-contained, dark-themed HTML report-card export.
- 124 tests (98% line coverage), `ruff` lint-clean, and `mypy --strict`
  clean across the whole `src/shadowlab` package.
