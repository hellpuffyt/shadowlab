"""The scenario catalog: static metadata + grading wiring for every exercise.

Each scenario bundles synthetic fixture data and a *real* ground-truth
computation -- either a detector run against a log/config fixture, or a
hand-authored (but clearly documented) ideal answer for the incident
response scenarios, where "ground truth" means "the graded rubric", not "a
detector output". Nothing here reaches a network or performs any
offensive/destructive action; every fixture is synthetic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadowlab.models import Category, Scenario
from shadowlab.scoring.checklist import ChecklistCatalog
from shadowlab.scoring.config_audit import audit_firewall_rules, audit_sshd_config
from shadowlab.scoring.flow import detect_exfiltration
from shadowlab.scoring.ir import ActionCatalog, ActionCatalogEntry
from shadowlab.scoring.logs import detect_scanner_probe, detect_ssh_brute_force
from shadowlab.scoring.rubric import FieldSpec

_PKG_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True, slots=True)
class ScenarioDef:
    """Everything the engine needs to present and grade one scenario."""

    scenario: Scenario
    kind: str  # "log_fields" | "checklist" | "ir_sequence"
    field_specs: tuple[FieldSpec, ...] = ()
    ground_truth_fn: Callable[[str], Any] | None = None
    checklist_catalog: ChecklistCatalog | None = None
    action_catalog: ActionCatalog | None = None

    def data_path(self, filename: str) -> Path:
        return _PKG_DIR / self.scenario.directory / "data" / filename

    def read_data(self, filename: str) -> str:
        return self.data_path(filename).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 1. brute_force_ssh -- log-analysis
# --------------------------------------------------------------------------

_BRUTE_FORCE = ScenarioDef(
    scenario=Scenario(
        id="brute_force_ssh",
        category=Category.LOG_ANALYSIS,
        title="Credential-Stuffing Brute Force Against SSH",
        difficulty="easy",
        prompt=(
            "A staging web host's sshd auth log (`auth.log`) is bundled below. Somewhere in "
            "it, an attacker credential-stuffs a list of usernames from a single IP and "
            "eventually breaks in. Find the attacker's IP, the account they compromised, the "
            "timestamp of the successful breach login, how many failed attempts preceded it "
            "within the attack window, and every username they tried."
        ),
        data_files=("auth.log",),
        directory="brute_force_ssh",
        submission_schema={
            "attacker_ip": "string, e.g. '203.0.113.55'",
            "compromised_user": "string, the account that was finally breached",
            "breach_time": "string, syslog-style timestamp of the successful login, e.g. 'Jan 15 03:18:47'",
            "failed_attempt_count": "integer, failed attempts from that IP in the attack window",
            "usernames_tried": "list of strings, every username the attacker attempted",
        },
        max_points=100.0,
    ),
    kind="log_fields",
    field_specs=(
        FieldSpec("attacker_ip", weight=3, kind="exact_ci", label="attacker IP"),
        FieldSpec("compromised_user", weight=3, kind="exact_ci", label="compromised user"),
        FieldSpec("breach_time", weight=2, kind="exact_ci", label="breach timestamp"),
        FieldSpec("failed_attempt_count", weight=1, kind="int_tolerance", tolerance=0, label="failed attempt count"),
        FieldSpec("usernames_tried", weight=2, kind="str_set_ci", label="usernames tried"),
    ),
    ground_truth_fn=lambda text: detect_ssh_brute_force(text).as_dict(),
)


# --------------------------------------------------------------------------
# 2. web_scanner_probe -- log-analysis
# --------------------------------------------------------------------------

_WEB_SCANNER = ScenarioDef(
    scenario=Scenario(
        id="web_scanner_probe",
        category=Category.LOG_ANALYSIS,
        title="Automated Scanner and Webshell Upload in Access Logs",
        difficulty="medium",
        prompt=(
            "An nginx-style access log (`access.log`) is bundled below, capturing a few "
            "minutes around a web app compromise. One IP runs an automated scan (SQLi and "
            "path-traversal payloads, a known scanner tool user-agent) and appears to succeed "
            "in uploading a webshell. Identify the attacker's IP, the scanner's user-agent "
            "string, how many suspicious requests it made, the path of the uploaded webshell "
            "(if any), and the timestamp of its first probe."
        ),
        data_files=("access.log",),
        directory="web_scanner_probe",
        submission_schema={
            "attacker_ip": "string",
            "scanner_user_agent": "string, the exact User-Agent header value",
            "suspicious_request_count": "integer",
            "webshell_path": "string, the request path with no query string (or null if none found)",
            "first_probe_time": "string, the access-log timestamp of the first suspicious request",
        },
        max_points=100.0,
    ),
    kind="log_fields",
    field_specs=(
        FieldSpec("attacker_ip", weight=3, kind="exact_ci", label="attacker IP"),
        FieldSpec("scanner_user_agent", weight=2, kind="exact_ci", label="scanner user-agent"),
        FieldSpec("suspicious_request_count", weight=2, kind="int_tolerance", tolerance=0, label="suspicious request count"),
        FieldSpec("webshell_path", weight=2, kind="optional_exact_ci", label="webshell path"),
        FieldSpec("first_probe_time", weight=1, kind="exact_ci", label="first probe time"),
    ),
    ground_truth_fn=lambda text: detect_scanner_probe(text).as_dict(),
)


# --------------------------------------------------------------------------
# 3. exfil_flow_logs -- log-analysis
# --------------------------------------------------------------------------

_EXFIL_FLOW = ScenarioDef(
    scenario=Scenario(
        id="exfil_flow_logs",
        category=Category.LOG_ANALYSIS,
        title="Data Exfiltration Pattern in Network Flow Logs",
        difficulty="medium",
        prompt=(
            "A NetFlow-style CSV export (`flows.csv`) is bundled below, covering about 45 "
            "minutes of traffic from a small office network. Buried in ordinary DNS lookups "
            "and HTTPS browsing is a sustained, unusually large outbound transfer from one "
            "internal workstation to a single external IP over a non-standard port. Identify "
            "the internal host, the external destination, the destination port, the total "
            "bytes transferred, and the timestamp the transfer started."
        ),
        data_files=("flows.csv",),
        directory="exfil_flow_logs",
        submission_schema={
            "internal_host": "string, the internal (RFC1918) source IP",
            "exfil_destination": "string, the external destination IP",
            "dest_port": "integer, the destination port used for the transfer",
            "bytes_transferred": "integer, total bytes moved in the flagged transfer",
            "start_time": "string, timestamp of the first flow record in the transfer",
        },
        max_points=100.0,
    ),
    kind="log_fields",
    field_specs=(
        FieldSpec("internal_host", weight=3, kind="exact_ci", label="internal host"),
        FieldSpec("exfil_destination", weight=3, kind="exact_ci", label="exfil destination"),
        FieldSpec("dest_port", weight=1, kind="int_tolerance", tolerance=0, label="destination port"),
        FieldSpec("bytes_transferred", weight=2, kind="int_tolerance", tolerance=5_000_000, label="bytes transferred"),
        FieldSpec("start_time", weight=1, kind="exact_ci", label="start time"),
    ),
    ground_truth_fn=lambda text: detect_exfiltration(text).as_dict(),
)


# --------------------------------------------------------------------------
# 4. firewall_audit -- config-audit
# --------------------------------------------------------------------------

_FIREWALL_ALL_IDS = (
    "fw-telnet-open",
    "fw-metasploit-port-open",
    "fw-rdp-open-to-any",
    "fw-default-accept-catchall",
    "fw-input-default-policy-accept",
    "fw-ssh-open-to-any",  # distractor: SSH-to-any is common/acceptable, not flagged by the auditor
    "fw-http-open",  # distractor: plain HTTP/HTTPS open is expected for a web-facing host
)
_FIREWALL_DESCRIPTIONS = {
    "fw-telnet-open": "Telnet (port 23) accepted",
    "fw-metasploit-port-open": "Port 4444 accepted with no source restriction",
    "fw-rdp-open-to-any": "RDP (3389) accepted from 0.0.0.0/0",
    "fw-default-accept-catchall": "Trailing bare ACCEPT rule",
    "fw-input-default-policy-accept": "INPUT chain default policy is ACCEPT",
    "fw-ssh-open-to-any": "SSH (22) accepted from 0.0.0.0/0",
    "fw-http-open": "HTTP/HTTPS (80/443) accepted",
}

_FIREWALL_AUDIT = ScenarioDef(
    scenario=Scenario(
        id="firewall_audit",
        category=Category.CONFIG_AUDIT,
        title="Misconfigured Perimeter Firewall Audit",
        difficulty="easy",
        prompt=(
            "An `iptables-save` capture from a staging firewall (`rules.v4`) is bundled below. "
            "Review it like a security engineer doing a config audit: which rules represent "
            "real exposure risks? Submit the list of rule ids (from the catalog shown by "
            "`shadowlab show firewall_audit`) that you believe are genuine findings. Not every "
            "open port is a finding -- flagging something that is fine will cost you points."
        ),
        data_files=("rules.v4",),
        directory="firewall_audit",
        submission_schema={"selected_ids": "list of rule-catalog ids you believe are findings"},
        max_points=100.0,
    ),
    kind="checklist",
    ground_truth_fn=lambda text: audit_firewall_rules(text),
    checklist_catalog=ChecklistCatalog(all_ids=_FIREWALL_ALL_IDS, descriptions=_FIREWALL_DESCRIPTIONS),
)


# --------------------------------------------------------------------------
# 5. sshd_hardening -- config-audit
# --------------------------------------------------------------------------

_SSHD_ALL_IDS = (
    "ssh-permit-root-login",
    "ssh-permit-empty-passwords",
    "ssh-weak-ciphers",
    "ssh-weak-macs",
    "ssh-max-auth-tries-too-high",
    "ssh-no-idle-timeout",
    "ssh-x11-forwarding-enabled",
    "ssh-tunneling-enabled",
    "ssh-protocol-2",  # distractor: Protocol 2 is the modern, correct setting
    "ssh-pubkey-auth-enabled",  # distractor: PubkeyAuthentication yes is desirable
)
_SSHD_DESCRIPTIONS = {
    "ssh-permit-root-login": "PermitRootLogin yes",
    "ssh-permit-empty-passwords": "PermitEmptyPasswords yes",
    "ssh-weak-ciphers": "Weak/legacy ciphers enabled",
    "ssh-weak-macs": "Weak MAC algorithms enabled",
    "ssh-max-auth-tries-too-high": "MaxAuthTries too high",
    "ssh-no-idle-timeout": "ClientAliveInterval 0",
    "ssh-x11-forwarding-enabled": "X11Forwarding yes",
    "ssh-tunneling-enabled": "AllowTcpForwarding + PermitTunnel yes",
    "ssh-protocol-2": "Protocol 2",
    "ssh-pubkey-auth-enabled": "PubkeyAuthentication yes",
}

_SSHD_HARDENING = ScenarioDef(
    scenario=Scenario(
        id="sshd_hardening",
        category=Category.CONFIG_AUDIT,
        title="SSH Daemon Hardening Review",
        difficulty="medium",
        prompt=(
            "An `sshd_config` captured from a staging host is bundled below. Review it like a "
            "security engineer doing a hardening audit and submit the list of rule-catalog ids "
            "(from `shadowlab show sshd_hardening`) you believe represent real weaknesses. Some "
            "catalog entries describe settings that are actually fine or already best practice "
            "-- flagging those costs you points."
        ),
        data_files=("sshd_config",),
        directory="sshd_hardening",
        submission_schema={"selected_ids": "list of rule-catalog ids you believe are findings"},
        max_points=100.0,
    ),
    kind="checklist",
    ground_truth_fn=lambda text: audit_sshd_config(text),
    checklist_catalog=ChecklistCatalog(all_ids=_SSHD_ALL_IDS, descriptions=_SSHD_DESCRIPTIONS),
)


# --------------------------------------------------------------------------
# 6. ransomware_ir -- incident-response
# --------------------------------------------------------------------------

_RANSOMWARE_ENTRIES = (
    ActionCatalogEntry(
        "ir-isolate-host", "Confirm FILES01 is isolated from the network (disable its switchport centrally)", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-preserve-evidence", "Capture a forensic disk/memory image of FILES01 before any remediation", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-disable-svc-backup", "Disable the svc_backup account and revoke its active sessions", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-hunt-lateral", "Hunt for lateral movement or other compromised accounts/hosts", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-identify-strain", "Identify the ransomware strain/IOCs from the note and encrypted samples", "eradication", True,
    ),
    ActionCatalogEntry(
        "ir-remove-persistence", "Rebuild/reimage FILES01 from known-clean media, removing persistence", "eradication", True,
    ),
    ActionCatalogEntry(
        "ir-restore-from-backup", "Restore the finance share from the verified clean backup", "recovery", True,
    ),
    ActionCatalogEntry(
        "ir-validate-restore", "Validate restored data integrity and monitor before reconnecting", "recovery", True,
    ),
    ActionCatalogEntry(
        "ir-notify-stakeholders", "Notify affected stakeholders and regulators/law enforcement per policy", "recovery", True,
    ),
    ActionCatalogEntry(
        "ir-lessons-learned",
        "Run a post-incident review; rotate svc_backup and disable its interactive logon", "lessons_learned", True,
    ),
    ActionCatalogEntry("ir-pay-ransom", "Pay the ransom to obtain the decryption key", "harmful", False),
    ActionCatalogEntry(
        "ir-reconnect-immediately", "Reconnect FILES01 to the network immediately to reduce downtime", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-delete-logs", "Delete the ransom note and encrypted files right away to \"clean up\"", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-skip-backup-verify", "Restore from backup without verifying it is clean first", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-public-blame", "Publicly blame the finance team on social media for clicking the link", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-reuse-svc-backup-password",
        "Keep the existing svc_backup password since rotating it is inconvenient", "harmful", False,
    ),
)
_RANSOMWARE_ORDER = tuple(e.id for e in _RANSOMWARE_ENTRIES if e.correct)

_RANSOMWARE_IR = ScenarioDef(
    scenario=Scenario(
        id="ransomware_ir",
        category=Category.INCIDENT_RESPONSE,
        title="Ransomware Triage: File Server Encryption",
        difficulty="hard",
        prompt=Path(_PKG_DIR / "ransomware_ir" / "data" / "incident_brief.md").read_text(encoding="utf-8"),
        data_files=("incident_brief.md",),
        directory="ransomware_ir",
        submission_schema={"ordered_ids": "ordered list of action-catalog ids, from first action to last"},
        max_points=100.0,
    ),
    kind="ir_sequence",
    action_catalog=ActionCatalog(entries=_RANSOMWARE_ENTRIES, correct_order=_RANSOMWARE_ORDER),
)


# --------------------------------------------------------------------------
# 7. phishing_bec_ir -- incident-response
# --------------------------------------------------------------------------

_BEC_ENTRIES = (
    ActionCatalogEntry(
        "ir-force-password-reset-cfo",
        "Force an immediate password reset and revoke sessions/tokens for the CFO's mailbox", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-remove-mail-rule", "Locate and remove the malicious auto-forwarding inbox rule", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-enable-mfa-cfo", "Enable MFA on the CFO's account and require re-authentication", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-block-lookalike-domain",
        "Block the look-alike sending domain and external forwarding address at the mail gateway", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-warn-ap-team",
        "Alert accounts-payable/finance to hold pending wires and verify requests out-of-band", "containment", True,
    ),
    ActionCatalogEntry(
        "ir-hunt-other-mailboxes",
        "Search mail logs for the same inbox-rule pattern or sender across other mailboxes", "identification", True,
    ),
    ActionCatalogEntry(
        "ir-identify-phish-source",
        "Identify the phishing link/kit and check the CFO's workstation for compromise", "eradication", True,
    ),
    ActionCatalogEntry(
        "ir-audit-sent-items", "Review the CFO mailbox's Sent/Deleted items for further fraudulent messages", "eradication", True,
    ),
    ActionCatalogEntry(
        "ir-enforce-mfa-finance-wide", "Roll out MFA enforcement across all finance-team accounts", "recovery", True,
    ),
    ActionCatalogEntry(
        "ir-report-to-bank-and-authorities",
        "Notify the bank of the attempted fraud and file with authorities/insurance per policy", "recovery", True,
    ),
    ActionCatalogEntry(
        "ir-lessons-learned-bec",
        "Run a post-incident review; require out-of-band verification for wire changes; train finance staff",
        "lessons_learned", True,
    ),
    ActionCatalogEntry(
        "ir-send-the-wire", "Process the wire transfer anyway, to \"test\" whether it's legitimate", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-reply-to-attacker", "Reply directly to the suspicious email asking the CFO to confirm the request", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-ignore-since-no-loss", "Close the ticket since no money was actually lost", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-share-credentials-clerk",
        "Ask the AP clerk to share their own password so IT can \"check for similar rules\"", "harmful", False,
    ),
    ActionCatalogEntry(
        "ir-public-domain-shame",
        "Post the phishing domain and screenshots publicly before blocking it internally", "harmful", False,
    ),
)
_BEC_ORDER = tuple(e.id for e in _BEC_ENTRIES if e.correct)

_PHISHING_BEC_IR = ScenarioDef(
    scenario=Scenario(
        id="phishing_bec_ir",
        category=Category.INCIDENT_RESPONSE,
        title="Business Email Compromise: Attempted Wire Fraud",
        difficulty="hard",
        prompt=Path(_PKG_DIR / "phishing_bec_ir" / "data" / "incident_brief.md").read_text(encoding="utf-8"),
        data_files=("incident_brief.md",),
        directory="phishing_bec_ir",
        submission_schema={"ordered_ids": "ordered list of action-catalog ids, from first action to last"},
        max_points=100.0,
    ),
    kind="ir_sequence",
    action_catalog=ActionCatalog(entries=_BEC_ENTRIES, correct_order=_BEC_ORDER),
)


SCENARIOS: dict[str, ScenarioDef] = {
    d.scenario.id: d
    for d in (
        _BRUTE_FORCE,
        _WEB_SCANNER,
        _EXFIL_FLOW,
        _FIREWALL_AUDIT,
        _SSHD_HARDENING,
        _RANSOMWARE_IR,
        _PHISHING_BEC_IR,
    )
}


def list_scenario_defs() -> tuple[ScenarioDef, ...]:
    return tuple(SCENARIOS.values())


def get_scenario_def(scenario_id: str) -> ScenarioDef:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        known = ", ".join(sorted(SCENARIOS))
        raise KeyError(f"unknown scenario id {scenario_id!r}; known scenarios: {known}") from exc
