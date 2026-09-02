"""Real log-analysis detectors for the log-analysis scenario family.

These are genuine (if intentionally simple) detection algorithms — sliding-
window brute-force detection over sshd auth logs, and scanner/webshell
detection over nginx-style access logs — not hardcoded answer keys. The
bundled scenario answer keys are the verified output of running these
detectors against the bundled fixtures (see tests/test_scoring_logs.py for
the golden-file regression that keeps them honest).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote

_AUTH_LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<outcome>Accepted|Failed)\s+(?P<method>password|publickey)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+\d+"
)

_DUMMY_YEAR = 2000  # any non-leap year; only used for relative ordering within one fixture


@dataclass(frozen=True, slots=True)
class AuthEvent:
    when: datetime
    raw_ts: str
    outcome: str  # "Accepted" | "Failed"
    method: str
    user: str
    ip: str
    invalid_user: bool


def parse_auth_log(text: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _AUTH_LINE.match(line)
        if not m:
            continue
        ts = datetime.strptime(f"{_DUMMY_YEAR} {m.group('ts')}", "%Y %b %d %H:%M:%S")
        events.append(
            AuthEvent(
                when=ts,
                raw_ts=m.group("ts"),
                outcome=m.group("outcome"),
                method=m.group("method"),
                user=m.group("user"),
                ip=m.group("ip"),
                invalid_user=m.group("invalid") is not None,
            )
        )
    events.sort(key=lambda e: e.when)
    return events


@dataclass(frozen=True, slots=True)
class BruteForceReport:
    attacker_ip: str | None
    compromised_user: str | None
    breach_time: str | None
    failed_attempt_count: int
    usernames_tried: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "attacker_ip": self.attacker_ip,
            "compromised_user": self.compromised_user,
            "breach_time": self.breach_time,
            "failed_attempt_count": self.failed_attempt_count,
            "usernames_tried": list(self.usernames_tried),
        }


def detect_ssh_brute_force(
    text: str, *, fail_threshold: int = 5, window_seconds: int = 900
) -> BruteForceReport:
    """Sliding-window brute-force + breach detector over an sshd auth log.

    An IP is flagged once it accrues ``fail_threshold`` failed password
    attempts within any ``window_seconds`` window; if that same IP later logs
    in successfully (still within the window of its most recent failure
    burst), that login is reported as the breach.
    """
    events = parse_auth_log(text)
    failures_by_ip: dict[str, list[AuthEvent]] = {}
    usernames_by_ip: dict[str, list[str]] = {}

    for ev in events:
        if ev.outcome == "Failed":
            window = failures_by_ip.setdefault(ev.ip, [])
            window.append(ev)
            # drop failures outside the trailing window
            cutoff = ev.when.timestamp() - window_seconds
            failures_by_ip[ev.ip] = [f for f in window if f.when.timestamp() >= cutoff]
            names = usernames_by_ip.setdefault(ev.ip, [])
            if ev.user not in names:
                names.append(ev.user)
            continue

        # Accepted: check whether this IP just crossed the brute-force threshold
        recent_failures = failures_by_ip.get(ev.ip, [])
        cutoff = ev.when.timestamp() - window_seconds
        recent_failures = [f for f in recent_failures if f.when.timestamp() >= cutoff]
        if len(recent_failures) >= fail_threshold:
            return BruteForceReport(
                attacker_ip=ev.ip,
                compromised_user=ev.user,
                breach_time=ev.raw_ts,
                failed_attempt_count=len(recent_failures),
                usernames_tried=tuple(sorted(usernames_by_ip.get(ev.ip, []))),
            )

    return BruteForceReport(
        attacker_ip=None,
        compromised_user=None,
        breach_time=None,
        failed_attempt_count=0,
        usernames_tried=(),
    )


_ACCESS_LINE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

_SUSPICIOUS_PATH = re.compile(
    r"(\bunion\s+select\b|'\s*or\s*'|\.\./|%2e%2e|/\.env\b|\.php\.bak\b|/wp-admin/admin-ajax\.php)",
    re.IGNORECASE,
)
_SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nessus|acunetix", re.IGNORECASE)
_WEBSHELL_PATH = re.compile(r"^/(uploads|tmp|files|images)/[^?]*\.(php|phtml|jsp|aspx?)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class AccessEvent:
    ip: str
    raw_ts: str
    method: str
    path: str
    status: int
    user_agent: str


def parse_access_log(text: str) -> list[AccessEvent]:
    events: list[AccessEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ACCESS_LINE.match(line)
        if not m:
            continue
        events.append(
            AccessEvent(
                ip=m.group("ip"),
                raw_ts=m.group("ts"),
                method=m.group("method"),
                path=m.group("path"),
                status=int(m.group("status")),
                user_agent=m.group("ua"),
            )
        )
    return events


@dataclass(frozen=True, slots=True)
class ScannerReport:
    attacker_ip: str | None
    scanner_user_agent: str | None
    suspicious_request_count: int
    webshell_path: str | None
    first_probe_time: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "attacker_ip": self.attacker_ip,
            "scanner_user_agent": self.scanner_user_agent,
            "suspicious_request_count": self.suspicious_request_count,
            "webshell_path": self.webshell_path,
            "first_probe_time": self.first_probe_time,
        }


def detect_scanner_probe(text: str, *, suspicious_threshold: int = 3) -> ScannerReport:
    """Flag an IP running an automated scan: repeated SQLi/traversal/scanner-UA
    requests, then check whether any of its requests reached a known
    webshell-shaped path with a 200 response (successful upload/callback).
    """
    events = parse_access_log(text)
    suspicious_by_ip: dict[str, list[AccessEvent]] = {}

    for ev in events:
        decoded_path = unquote(ev.path)
        is_suspicious = bool(_SUSPICIOUS_PATH.search(decoded_path)) or bool(
            _SCANNER_UA.search(ev.user_agent)
        )
        if is_suspicious:
            suspicious_by_ip.setdefault(ev.ip, []).append(ev)

    if not suspicious_by_ip:
        return ScannerReport(None, None, 0, None, None)

    attacker_ip = max(suspicious_by_ip, key=lambda ip: len(suspicious_by_ip[ip]))
    hits = suspicious_by_ip[attacker_ip]
    if len(hits) < suspicious_threshold:
        return ScannerReport(None, None, 0, None, None)

    webshell_path = None
    for ev in events:
        if ev.ip == attacker_ip and ev.status == 200 and _WEBSHELL_PATH.match(ev.path):
            webshell_path = ev.path.split("?", 1)[0]
            break

    return ScannerReport(
        attacker_ip=attacker_ip,
        scanner_user_agent=hits[0].user_agent,
        suspicious_request_count=len(hits),
        webshell_path=webshell_path,
        first_probe_time=hits[0].raw_ts,
    )
