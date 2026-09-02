"""Golden-file + unit tests for the config-audit static analyzers."""

from __future__ import annotations

from pathlib import Path

from shadowlab.scoring.config_audit import audit_firewall_rules, audit_sshd_config

_SCEN = Path(__file__).parent.parent / "src" / "shadowlab" / "scenarios"


def _read(*parts: str) -> str:
    return _SCEN.joinpath(*parts).read_text(encoding="utf-8")


# --- firewall_audit golden fixture ----------------------------------------

def test_firewall_golden_fixture_ids():
    findings = audit_firewall_rules(_read("firewall_audit", "data", "rules.v4"))
    ids = {f.rule_id for f in findings}
    assert ids == {
        "fw-telnet-open",
        "fw-metasploit-port-open",
        "fw-rdp-open-to-any",
        "fw-default-accept-catchall",
    }


def test_firewall_does_not_flag_ssh_or_http():
    findings = audit_firewall_rules(_read("firewall_audit", "data", "rules.v4"))
    ids = {f.rule_id for f in findings}
    assert "fw-ssh-open-to-any" not in ids
    assert "fw-http-open" not in ids


def test_firewall_rdp_restricted_source_not_flagged():
    text = (
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -p tcp -m tcp --dport 3389 -s 10.0.0.0/8 -j ACCEPT\n"
        "COMMIT\n"
    )
    findings = audit_firewall_rules(text)
    assert not any(f.rule_id == "fw-rdp-open-to-any" for f in findings)


def test_firewall_no_findings_on_clean_ruleset():
    text = (
        "*filter\n:INPUT DROP [0:0]\n"
        "-A INPUT -p tcp -m tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT\n"
        "-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )
    findings = audit_firewall_rules(text)
    assert findings == ()


def test_firewall_ignores_comments_and_blank_lines():
    text = "# comment\n\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    findings = audit_firewall_rules(text)
    assert any(f.rule_id == "fw-input-default-policy-accept" for f in findings)


def test_firewall_finding_has_line_number_and_evidence():
    findings = audit_firewall_rules(_read("firewall_audit", "data", "rules.v4"))
    telnet = next(f for f in findings if f.rule_id == "fw-telnet-open")
    assert telnet.line is not None
    assert "23" in telnet.evidence


# --- sshd_hardening golden fixture ----------------------------------------

def test_sshd_golden_fixture_ids():
    findings = audit_sshd_config(_read("sshd_hardening", "data", "sshd_config"))
    ids = {f.rule_id for f in findings}
    assert ids == {
        "ssh-permit-root-login",
        "ssh-permit-empty-passwords",
        "ssh-weak-ciphers",
        "ssh-weak-macs",
        "ssh-max-auth-tries-too-high",
        "ssh-no-idle-timeout",
        "ssh-x11-forwarding-enabled",
        "ssh-tunneling-enabled",
    }


def test_sshd_does_not_flag_protocol_2_or_pubkey_auth():
    findings = audit_sshd_config(_read("sshd_hardening", "data", "sshd_config"))
    ids = {f.rule_id for f in findings}
    assert "ssh-protocol-2" not in ids
    assert "ssh-pubkey-auth-enabled" not in ids


def test_sshd_hardened_config_has_no_findings():
    text = (
        "PermitRootLogin no\n"
        "PermitEmptyPasswords no\n"
        "Ciphers aes256-ctr,chacha20-poly1305@openssh.com\n"
        "MACs hmac-sha2-512-etm@openssh.com\n"
        "MaxAuthTries 3\n"
        "ClientAliveInterval 300\n"
        "X11Forwarding no\n"
        "AllowTcpForwarding no\n"
        "PermitTunnel no\n"
    )
    assert audit_sshd_config(text) == ()


def test_sshd_default_max_auth_tries_not_flagged_when_absent():
    findings = audit_sshd_config("PermitRootLogin no\n")
    assert not any(f.rule_id == "ssh-max-auth-tries-too-high" for f in findings)


def test_sshd_tunneling_requires_both_directives():
    text = "AllowTcpForwarding yes\nPermitTunnel no\n"
    findings = audit_sshd_config(text)
    assert not any(f.rule_id == "ssh-tunneling-enabled" for f in findings)


def test_sshd_weak_ciphers_lists_only_the_weak_ones():
    text = "Ciphers aes256-ctr,3des-cbc\n"
    findings = audit_sshd_config(text)
    weak = next(f for f in findings if f.rule_id == "ssh-weak-ciphers")
    assert "3des-cbc" in weak.message
    assert "aes256-ctr" not in weak.message
