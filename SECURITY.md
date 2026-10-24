# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's advisory form:
<https://github.com/hellpuffyt/shadowlab/security/advisories/new>

Please do not open a public issue for a vulnerability.

In scope, for example:

- any code path that executes, evaluates or imports learner-submitted
  content, opens a network connection, or starts a process;
- reading or writing files other than the bundled fixtures and the
  `--answers` / `--history` / `--out` paths;
- terminal-escape or HTML/script injection from a submission or history
  file into the CLI output or the HTML report;
- a crafted submission or history file that crashes the tool, hangs it, or
  destroys recorded history.

Scoring loopholes (a strategy that passes without solving the scenario)
are bugs too; a normal issue is fine for those.

## Supported versions

Only the latest release on the default branch receives fixes.
