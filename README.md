# shadowlab

**A sandboxed defensive-security exercise runner.** Log-analysis,
config-audit, and incident-response scenarios, each scored with partial
credit and a plain-English explanation for every point earned or lost.
Everything is local and synthetic -- there is no network call, no exploit
code, and no destructive technique anywhere in this repository. This is a
teaching lab for the blue team, not a red-team tool.

```
shadowlab list                       # what's in the box
shadowlab show brute_force_ssh       # read the fixture, know the schema
shadowlab submit brute_force_ssh --answers answers.json
shadowlab report --out report.html   # a report card you can hand to someone
```

## Why

Most "SOC training" content is either a paid platform behind a login wall,
or a CTF that rewards exploitation. shadowlab is neither: it's a `pip
install`-able local grader you can point at synthetic fixtures, get honest
partial credit, and see *why* you lost points -- the same way a real
findings report reads. Every scenario's "ground truth" is the verified
output of a real detection algorithm or a genuinely reasoned incident
response playbook, not a hardcoded answer key -- see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how new scenarios are held to that
bar.

## Quickstart

```bash
git clone https://github.com/hellpuffyt/shadowlab.git
cd shadowlab
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e .

shadowlab list
```

## What it looks like

`shadowlab list`:

```
                                             shadowlab scenarios
+---------------------------------------------------------------------------------------------------------+
| id                | category          | difficulty | title                                       | points |
|-------------------+-------------------+------------+---------------------------------------------+--------|
| firewall_audit    | config-audit      | easy       | Misconfigured Perimeter Firewall Audit      |    100 |
| sshd_hardening    | config-audit      | medium     | SSH Daemon Hardening Review                 |    100 |
| phishing_bec_ir   | incident-response | hard       | Business Email Compromise: Attempted Wire   |    100 |
|                   |                   |            | Fraud                                       |        |
| ransomware_ir     | incident-response | hard       | Ransomware Triage: File Server Encryption   |    100 |
| brute_force_ssh   | log-analysis      | easy       | Credential-Stuffing Brute Force Against SSH |    100 |
| exfil_flow_logs   | log-analysis      | medium     | Data Exfiltration Pattern in Network Flow   |    100 |
|                   |                   |            | Logs                                        |        |
| web_scanner_probe | log-analysis      | medium     | Automated Scanner and Webshell Upload in    |    100 |
|                   |                   |            | Access Logs                                 |        |
+---------------------------------------------------------------------------------------------------------+
```

`shadowlab submit brute_force_ssh --answers answers.json` -- a near-miss
submission (wrong breach timestamp by 13 seconds, half the username list)
graded with partial credit and an explanation per rubric item:

```
brute_force_ssh -- Credential-Stuffing Brute Force Against SSH: 71.72% (71.72/100 pts) PASS
+-------------------------------------------------------------------------------------------------------+
| rubric item          |          points | explanation                                                  |
|----------------------+-----------------+---------------------------------------------------------------|
| attacker IP          | 27.2727/27.2727 | correct ('203.0.113.55')                                     |
| compromised user     | 27.2727/27.2727 | correct ('root')                                              |
| breach timestamp     |       0/18.1818 | expected 'Jan 15 03:18:47', got 'Jan 15 03:19:00'             |
| failed attempt count |   9.0909/9.0909 | within tolerance (expected 9, got 9)                          |
| usernames tried      |  8.0808/18.1818 | 4/9 matched, missing ['deploy','guest','postgres','root',...] |
+-------------------------------------------------------------------------------------------------------+
recorded to shadowlab_history.json
```

`shadowlab report --out report.html` renders every recorded attempt into a
dark-themed, self-contained HTML report card with a per-rubric-item
breakdown -- open it in a browser, or attach it to a training write-up.

## The 7 bundled scenarios

| id | category | what you're finding |
|---|---|---|
| `brute_force_ssh` | log-analysis | An attacker credential-stuffs `sshd` from one IP and finally breaks in. Find the IP, the breached account, the breach timestamp, and every username tried. |
| `web_scanner_probe` | log-analysis | An automated scanner (SQLi + path traversal + a known tool user-agent) sweeps an nginx-style access log and uploads a webshell. |
| `exfil_flow_logs` | log-analysis | Buried in ordinary DNS/HTTPS chatter, one workstation moves ~780MB to a single external IP over a non-standard port -- classic exfiltration shape. |
| `firewall_audit` | config-audit | Review an `iptables-save` capture and pick out the real exposure risks (telnet open, a backdoor-shaped port, RDP open to the world) without flagging the fine stuff. |
| `sshd_hardening` | config-audit | Review a captured `sshd_config` for real hardening gaps (root login, empty passwords, weak ciphers/MACs) without flagging settings that are already correct. |
| `ransomware_ir` | incident-response | A file server gets encrypted after a phished workstation RDPs in with a shared service account. Submit an ordered response plan; harmful/wrong actions (paying the ransom, reconnecting early) cost you points. |
| `phishing_bec_ir` | incident-response | A spoofed-CFO wire-fraud email is caught before money moves, but the real mailbox is compromised with a malicious forwarding rule. Submit an ordered containment-through-lessons-learned plan. |

Run `shadowlab show <id>` for the full prompt, the bundled fixture, and the
exact submission schema (which fields to submit, or which catalog ids are
available to choose from).

## Architecture

```
shadowlab/
├── models.py              # Category, Severity, Finding, Scenario, ScoreResult (shared dataclasses)
├── engine.py               # list_scenarios() / load_scenario() / grade() -- the one entry point
├── cli.py                  # rich-powered `list` / `show` / `submit` / `report` commands
├── report.py                # self-contained HTML report-card renderer
├── scenarios/
│   ├── registry.py         # the 7 scenarios: metadata + which rubric grades each one
│   └── <scenario_id>/data/ # the synthetic fixture(s) for that scenario
└── scoring/
    ├── logs.py              # real detectors: SSH brute-force + scanner/webshell (log-analysis)
    ├── flow.py               # real detector: flow-log exfiltration pattern (log-analysis)
    ├── config_audit.py       # real auditors: iptables + sshd_config static analysis (config-audit)
    ├── rubric.py             # weighted field-comparison scorer, used by log-analysis scenarios
    ├── checklist.py          # severity-weighted checklist scorer w/ false-positive penalty (config-audit)
    └── ir.py                 # ordered-action scorer: coverage + ordering + harm avoidance (incident-response)
```

**The key design choice:** a scenario's "ground truth" is never a hand-typed
answer key sitting next to the fixture. For log-analysis and config-audit
scenarios it is the live output of a real detector/auditor function run
against the bundled fixture at grading time -- the same function is
golden-file tested against that fixture in `tests/`, so fixture and
detector can never silently drift apart. For incident-response scenarios,
"ground truth" is a hand-authored but explicitly-documented ideal action
sequence plus a set of clearly-labeled harmful distractors.

## Scoring rubric

Every scenario is scored out of 100 points with three separate rubric
strategies, chosen per scenario kind:

- **Weighted field comparison** (log-analysis): each expected field (an
  IP, a timestamp, a byte count, a set of usernames) carries a weight and a
  comparator -- exact match, numeric tolerance with linear decay, or set
  overlap (Jaccard) for list fields. Every field reports the ratio earned
  and why.
- **Severity-weighted checklist** (config-audit): each real finding is
  worth points proportional to its severity (`info` through `critical`);
  flagging something that *isn't* a real finding costs a flat penalty, so
  submitting every possible id is not a winning strategy.
- **Ordered-action scoring** (incident-response): three independently
  reported components -- how many correct actions you included
  (coverage), whether you did them in the right relative order (Preparation
  -> Identification -> Containment -> Eradication -> Recovery -> Lessons
  Learned), and whether you avoided the harmful/wrong distractors mixed
  into the catalog.

## Development

```bash
pip install -e ".[dev]"
ruff check .                                        # lint, zero warnings
mypy src/shadowlab                                   # strict type-check, zero errors
pytest --cov=shadowlab --cov-report=term-missing     # 124 tests, 98% line coverage
```

CI (`.github/workflows/ci.yml`) runs all three across Python 3.11-3.13 on
Linux, Windows, and macOS, plus a CLI smoke test that submits a real
answer and asserts the exported HTML report contains it.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the checklist to follow when
adding a new scenario, and [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## Safety

Every log line, config file, and incident brief in this repository is
synthetic, invented for this project. No fixture was copied from a real
breach, a real customer environment, or real personal data. No code path in
`src/shadowlab` performs a network call, executes a payload, or otherwise
acts on a real target -- the entire tool reads bundled text files and
writes local JSON/HTML. If you're looking for offensive tooling, this
isn't it, by design.

## License

MIT (c) 2026 Prabesh Sharma -- see [`LICENSE`](LICENSE).
