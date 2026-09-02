"""Real config auditors for the config-audit scenario family.

These parse and evaluate actual config syntax (iptables-save/restore rule
sets, sshd_config directives) against a small set of well-known hardening
rules. They are genuine static-analysis checks, not answer keys copy-pasted
from the fixture -- see ``tests/test_scoring_config_audit.py`` for the
golden-file regression that keeps them honest against the bundled fixtures.
"""

from __future__ import annotations

import re

from shadowlab.models import Finding, Severity

# --------------------------------------------------------------------------
# iptables / firewall rule audit
# --------------------------------------------------------------------------

_ACCEPT_RULE = re.compile(
    r"^-A\s+INPUT\s+-p\s+tcp\s+-m\s+tcp\s+--dport\s+(?P<port>\d+)"
    r"(?:\s+-s\s+(?P<src>\S+))?\s+-j\s+ACCEPT"
)

_KNOWN_RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    23: (
        "fw-telnet-open",
        Severity.CRITICAL,
        "Telnet (port 23) is accepted -- it transmits credentials in plaintext and should be "
        "disabled, not firewalled-in.",
    ),
    4444: (
        "fw-metasploit-port-open",
        Severity.CRITICAL,
        "Port 4444 is accepted inbound with no source restriction -- this is a classic "
        "default handler/backdoor port and has no legitimate reason to be open to everyone.",
    ),
    3389: (
        "fw-rdp-open-to-any",
        Severity.HIGH,
        "RDP (port 3389) is accepted from 0.0.0.0/0 -- remote desktop should never be exposed "
        "to the entire internet; restrict to a VPN/bastion source range.",
    ),
}


def audit_firewall_rules(text: str) -> tuple[Finding, ...]:
    """Audit an iptables-save-style ruleset for common exposure mistakes."""
    findings: list[Finding] = []
    lines = text.splitlines()
    saw_catchall_accept = False

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = _ACCEPT_RULE.match(line)
        if m:
            port = int(m.group("port"))
            src = m.group("src") or "0.0.0.0/0"
            if port in _KNOWN_RISKY_PORTS:
                rule_id, severity, message = _KNOWN_RISKY_PORTS[port]
                if port == 3389 and src not in ("0.0.0.0/0",):
                    continue  # restricted source: not the risky case we flag
                findings.append(
                    Finding(rule_id=rule_id, severity=severity, message=message, line=lineno, evidence=line)
                )
            continue

        if re.match(r"^-A\s+INPUT\s+-j\s+ACCEPT\s*$", line):
            saw_catchall_accept = True
            findings.append(
                Finding(
                    rule_id="fw-default-accept-catchall",
                    severity=Severity.MEDIUM,
                    message=(
                        "A trailing bare '-A INPUT -j ACCEPT' accepts anything not matched "
                        "above -- this silently defeats every rule before it and should be a "
                        "default DROP instead."
                    ),
                    line=lineno,
                    evidence=line,
                )
            )

    if not saw_catchall_accept and re.search(r":INPUT ACCEPT", text):
        findings.append(
            Finding(
                rule_id="fw-input-default-policy-accept",
                severity=Severity.MEDIUM,
                message="The INPUT chain's default policy is ACCEPT rather than DROP.",
                line=1,
                evidence=":INPUT ACCEPT [0:0]",
            )
        )

    return tuple(findings)


# --------------------------------------------------------------------------
# sshd_config audit
# --------------------------------------------------------------------------

_WEAK_CIPHERS = {"3des-cbc", "aes128-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"}
_WEAK_MACS = {"hmac-md5", "hmac-sha1", "hmac-md5-96", "hmac-sha1-96"}


def _directives(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        values[key] = value.strip()
    return values


def audit_sshd_config(text: str) -> tuple[Finding, ...]:
    """Audit an sshd_config for common hardening gaps."""
    d = _directives(text)
    findings: list[Finding] = []

    if d.get("PermitRootLogin", "").lower() == "yes":
        findings.append(
            Finding(
                rule_id="ssh-permit-root-login",
                severity=Severity.CRITICAL,
                message="PermitRootLogin yes -- root can log in directly over SSH; set to 'no' "
                "or 'prohibit-password'.",
                evidence="PermitRootLogin yes",
            )
        )

    if d.get("PermitEmptyPasswords", "").lower() == "yes":
        findings.append(
            Finding(
                rule_id="ssh-permit-empty-passwords",
                severity=Severity.CRITICAL,
                message="PermitEmptyPasswords yes -- accounts with no password set can log in.",
                evidence="PermitEmptyPasswords yes",
            )
        )

    ciphers = {c.strip().lower() for c in d.get("Ciphers", "").split(",") if c.strip()}
    weak_ciphers = ciphers & _WEAK_CIPHERS
    if weak_ciphers:
        findings.append(
            Finding(
                rule_id="ssh-weak-ciphers",
                severity=Severity.HIGH,
                message=f"Weak/legacy ciphers enabled: {', '.join(sorted(weak_ciphers))}.",
                evidence=d.get("Ciphers", ""),
            )
        )

    macs = {m.strip().lower() for m in d.get("MACs", "").split(",") if m.strip()}
    weak_macs = macs & _WEAK_MACS
    if weak_macs:
        findings.append(
            Finding(
                rule_id="ssh-weak-macs",
                severity=Severity.HIGH,
                message=f"Weak MAC algorithms enabled: {', '.join(sorted(weak_macs))}.",
                evidence=d.get("MACs", ""),
            )
        )

    try:
        max_auth_tries = int(d.get("MaxAuthTries", "6"))
    except ValueError:
        max_auth_tries = 6
    if max_auth_tries > 6:
        findings.append(
            Finding(
                rule_id="ssh-max-auth-tries-too-high",
                severity=Severity.MEDIUM,
                message=f"MaxAuthTries {max_auth_tries} is too permissive for online guessing; 3-6 is typical.",
                evidence=f"MaxAuthTries {max_auth_tries}",
            )
        )

    if d.get("ClientAliveInterval", "") == "0":
        findings.append(
            Finding(
                rule_id="ssh-no-idle-timeout",
                severity=Severity.LOW,
                message="ClientAliveInterval 0 disables idle-session timeout entirely.",
                evidence="ClientAliveInterval 0",
            )
        )

    if d.get("X11Forwarding", "").lower() == "yes":
        findings.append(
            Finding(
                rule_id="ssh-x11-forwarding-enabled",
                severity=Severity.LOW,
                message="X11Forwarding yes is rarely needed on a server and expands attack surface.",
                evidence="X11Forwarding yes",
            )
        )

    if d.get("AllowTcpForwarding", "").lower() == "yes" and d.get("PermitTunnel", "").lower() == "yes":
        findings.append(
            Finding(
                rule_id="ssh-tunneling-enabled",
                severity=Severity.LOW,
                message="AllowTcpForwarding and PermitTunnel are both enabled, letting SSH be "
                "used as a general-purpose VPN/pivot.",
                evidence="AllowTcpForwarding yes / PermitTunnel yes",
            )
        )

    return tuple(findings)
