"""Tests for the flow-log exfiltration detector."""

from __future__ import annotations

from pathlib import Path

from shadowlab.scoring.flow import detect_exfiltration, parse_flow_log

_FIXTURE = (
    Path(__file__).parent.parent
    / "src" / "shadowlab" / "scenarios" / "exfil_flow_logs" / "data" / "flows.csv"
).read_text(encoding="utf-8")


def test_exfil_golden_fixture():
    report = detect_exfiltration(_FIXTURE)
    assert report.internal_host == "10.20.6.44"
    assert report.exfil_destination == "185.199.108.153"
    assert report.dest_port == 8443
    assert report.bytes_transferred == 781_500_000
    assert report.start_time == "Jan 15 02:14:03"


def test_exfil_as_dict_roundtrip():
    d = detect_exfiltration(_FIXTURE).as_dict()
    assert d["bytes_transferred"] == 781_500_000


def test_parse_flow_log_skips_header_and_blank_lines():
    text = "timestamp,src_ip,dst_ip,src_port,dst_port,proto,bytes\n\nJan 01 00:00:00,10.0.0.1,10.0.0.2,1,2,tcp,100\n"
    records = parse_flow_log(text)
    assert len(records) == 1
    assert records[0].src_ip == "10.0.0.1"


def test_no_exfil_when_all_traffic_is_internal():
    text = "Jan 01 00:00:00,10.0.0.1,10.0.0.2,1,2,tcp,999999999\n"
    report = detect_exfiltration(text)
    assert report.internal_host is None
    assert report.bytes_transferred == 0


def test_no_exfil_below_byte_threshold():
    text = "Jan 01 00:00:00,10.0.0.1,8.8.8.8,1,53,udp,1000\n"
    report = detect_exfiltration(text, byte_threshold=50_000_000)
    assert report.internal_host is None


def test_exfil_picks_largest_candidate_pair():
    text = (
        "Jan 01 00:00:00,10.0.0.1,1.1.1.1,1,443,tcp,60000000\n"
        "Jan 01 00:01:00,10.0.0.2,2.2.2.2,1,443,tcp,90000000\n"
    )
    report = detect_exfiltration(text, byte_threshold=50_000_000)
    assert report.internal_host == "10.0.0.2"
    assert report.exfil_destination == "2.2.2.2"


def test_exfil_dominant_port_is_the_one_with_most_bytes():
    text = (
        "Jan 01 00:00:00,10.0.0.1,9.9.9.9,1,22,tcp,10000000\n"
        "Jan 01 00:01:00,10.0.0.1,9.9.9.9,1,8443,tcp,80000000\n"
    )
    report = detect_exfiltration(text, byte_threshold=50_000_000)
    assert report.dest_port == 8443
    assert report.bytes_transferred == 90_000_000


def test_exfil_ignores_ipv6_gracefully():
    # ipaddress handles IPv6 fine; ensure no crash and that a non-RFC1918 v6
    # source is simply not treated as "internal".
    text = "Jan 01 00:00:00,::1,9.9.9.9,1,443,tcp,60000000\n"
    report = detect_exfiltration(text, byte_threshold=1)
    # ::1 (loopback) is_private is True in Python's ipaddress, so this *is* internal
    assert report.internal_host == "::1"
