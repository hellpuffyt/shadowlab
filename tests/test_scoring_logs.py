"""Golden-file regression + unit tests for the log-analysis detectors.

These pin the detector output against the bundled fixtures so a change to
either the fixture or the detection algorithm gets caught, and separately
exercise the algorithms against small synthetic inputs to prove the logic
(sliding window, decoys, thresholds) rather than just the fixture output.
"""

from __future__ import annotations

from pathlib import Path

from shadowlab.scoring.logs import (
    detect_scanner_probe,
    detect_ssh_brute_force,
    parse_access_log,
    parse_auth_log,
)

_FIXTURES = Path(__file__).parent.parent / "src" / "shadowlab" / "scenarios"


def _read(*parts: str) -> str:
    return (_FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


# --- brute_force_ssh golden fixture ---------------------------------------

def test_brute_force_golden_fixture():
    text = _read("brute_force_ssh", "data", "auth.log")
    report = detect_ssh_brute_force(text)
    assert report.attacker_ip == "203.0.113.55"
    assert report.compromised_user == "root"
    assert report.breach_time == "Jan 15 03:18:47"
    assert report.failed_attempt_count == 9
    assert report.usernames_tried == (
        "admin", "deploy", "git", "guest", "oracle", "postgres", "root", "test", "ubuntu",
    )


def test_brute_force_as_dict_roundtrip():
    text = _read("brute_force_ssh", "data", "auth.log")
    d = detect_ssh_brute_force(text).as_dict()
    assert d["attacker_ip"] == "203.0.113.55"
    assert isinstance(d["usernames_tried"], list)


def test_parse_auth_log_ignores_blank_and_comment_lines():
    text = "\n# a comment\nJan 15 03:05:19 web01 sshd[1]: Failed password for bob from 1.2.3.4 port 1 ssh2\n"
    events = parse_auth_log(text)
    assert len(events) == 1
    assert events[0].user == "bob"
    assert events[0].outcome == "Failed"


def test_parse_auth_log_skips_unmatched_lines():
    text = "this is not an sshd line at all\n"
    assert parse_auth_log(text) == []


def test_no_brute_force_below_threshold():
    # A single failed+accepted pair should never trigger a breach report.
    text = (
        "Jan 15 03:05:19 web01 sshd[1]: Failed password for bob from 9.9.9.9 port 1 ssh2\n"
        "Jan 15 03:05:26 web01 sshd[2]: Accepted password for bob from 9.9.9.9 port 1 ssh2\n"
    )
    report = detect_ssh_brute_force(text)
    assert report.attacker_ip is None
    assert report.compromised_user is None
    assert report.failed_attempt_count == 0
    assert report.usernames_tried == ()


def test_brute_force_failures_outside_window_are_not_counted():
    lines = []
    pid = 1
    # 5 failures, but spaced far enough apart to fall outside a 900s window
    for i in range(5):
        minute = i * 20  # every 20 minutes: window of 900s (15 min) never holds more than one
        ts = f"Jan 15 0{2 + minute // 60}:{minute % 60:02d}:00"
        lines.append(f"{ts} web01 sshd[{pid}]: Failed password for x from 5.5.5.5 port 1 ssh2")
        pid += 1
    lines.append("Jan 15 05:00:00 web01 sshd[99]: Accepted password for x from 5.5.5.5 port 1 ssh2")
    report = detect_ssh_brute_force("\n".join(lines), fail_threshold=5, window_seconds=900)
    assert report.attacker_ip is None


def test_brute_force_custom_threshold_triggers_earlier():
    text = (
        "Jan 15 03:00:00 web01 sshd[1]: Failed password for x from 7.7.7.7 port 1 ssh2\n"
        "Jan 15 03:00:05 web01 sshd[2]: Failed password for x from 7.7.7.7 port 1 ssh2\n"
        "Jan 15 03:00:10 web01 sshd[3]: Accepted password for x from 7.7.7.7 port 1 ssh2\n"
    )
    report = detect_ssh_brute_force(text, fail_threshold=2, window_seconds=900)
    assert report.attacker_ip == "7.7.7.7"
    assert report.failed_attempt_count == 2


def test_brute_force_multiple_ips_only_flags_the_breaching_one():
    text = (
        "Jan 15 03:00:00 web01 sshd[1]: Failed password for x from 1.1.1.1 port 1 ssh2\n"
        "Jan 15 03:00:05 web01 sshd[2]: Failed password for x from 1.1.1.1 port 1 ssh2\n"
        "Jan 15 03:00:10 web01 sshd[3]: Failed password for x from 2.2.2.2 port 1 ssh2\n"
        "Jan 15 03:00:15 web01 sshd[4]: Failed password for x from 2.2.2.2 port 1 ssh2\n"
        "Jan 15 03:00:20 web01 sshd[5]: Accepted password for x from 2.2.2.2 port 1 ssh2\n"
    )
    report = detect_ssh_brute_force(text, fail_threshold=2, window_seconds=900)
    assert report.attacker_ip == "2.2.2.2"


# --- web_scanner_probe golden fixture -------------------------------------

def test_scanner_probe_golden_fixture():
    text = _read("web_scanner_probe", "data", "access.log")
    report = detect_scanner_probe(text)
    assert report.attacker_ip == "198.51.100.77"
    assert report.scanner_user_agent == "sqlmap/1.7.2#stable (http://sqlmap.org)"
    assert report.suspicious_request_count == 9
    assert report.webshell_path == "/uploads/shell.php"
    assert report.first_probe_time == "15/Jan/2026:04:02:11 +0000"


def test_scanner_probe_as_dict_roundtrip():
    text = _read("web_scanner_probe", "data", "access.log")
    d = detect_scanner_probe(text).as_dict()
    assert d["webshell_path"] == "/uploads/shell.php"


def test_parse_access_log_basic():
    line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    events = parse_access_log(line)
    assert len(events) == 1
    assert events[0].status == 200
    assert events[0].user_agent == "curl/8.0"


def test_scanner_probe_no_suspicious_traffic():
    text = (
        '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"\n'
    )
    report = detect_scanner_probe(text)
    assert report.attacker_ip is None
    assert report.webshell_path is None


def test_scanner_probe_below_threshold_not_flagged():
    ua = "sqlmap/1.0"
    lines = [
        f'9.9.9.9 - - [01/Jan/2026:00:00:0{i} +0000] "GET /?id=1%27%20OR%201=1 HTTP/1.1" 403 1 "-" "{ua}"'
        for i in range(2)
    ]
    report = detect_scanner_probe("\n".join(lines), suspicious_threshold=3)
    assert report.attacker_ip is None


def test_scanner_probe_webshell_requires_200_status():
    ua = "nikto"
    lines = [
        f'9.9.9.9 - - [01/Jan/2026:00:00:0{i} +0000] "GET /?a=../../etc/passwd HTTP/1.1" 404 1 "-" "{ua}"'
        for i in range(3)
    ]
    lines.append('9.9.9.9 - - [01/Jan/2026:00:00:10 +0000] "POST /uploads/shell.php HTTP/1.1" 500 1 "-" "nikto"')
    report = detect_scanner_probe("\n".join(lines))
    assert report.attacker_ip == "9.9.9.9"
    assert report.webshell_path is None  # 500, not 200, so not confirmed


def test_scanner_probe_url_decodes_path_traversal():
    ua = "gobuster"
    lines = [
        f'8.8.4.4 - - [01/Jan/2026:00:00:0{i} +0000] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 404 1 "-" "{ua}"'
        for i in range(3)
    ]
    report = detect_scanner_probe("\n".join(lines))
    assert report.attacker_ip == "8.8.4.4"
