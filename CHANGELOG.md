# Changelog

All notable changes to this project are documented in this file.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
