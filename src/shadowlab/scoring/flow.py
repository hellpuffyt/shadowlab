"""Real flow-log exfiltration detector for the exfil_flow_logs scenario.

Parses simple CSV-style flow records (``timestamp,src_ip,dst_ip,src_port,
dst_port,proto,bytes``) as a NetFlow/VPC-flow-log style collector might
export them, and flags a sustained large outbound transfer from an internal
host to an external destination -- an exfiltration pattern, as distinct
from ordinary small-byte external chatter (DNS lookups, HTTPS page loads).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime

_DUMMY_YEAR = 2000


@dataclass(frozen=True, slots=True)
class FlowRecord:
    when: datetime
    raw_ts: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    num_bytes: int


def _is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def parse_flow_log(text: str) -> list[FlowRecord]:
    records: list[FlowRecord] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("timestamp"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 7:
            continue
        ts, src_ip, dst_ip, src_port, dst_port, proto, num_bytes = parts
        when = datetime.strptime(f"{_DUMMY_YEAR} {ts}", "%Y %b %d %H:%M:%S")
        records.append(
            FlowRecord(
                when=when,
                raw_ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(src_port),
                dst_port=int(dst_port),
                proto=proto,
                num_bytes=int(num_bytes),
            )
        )
    records.sort(key=lambda r: r.when)
    return records


@dataclass(frozen=True, slots=True)
class ExfilReport:
    internal_host: str | None
    exfil_destination: str | None
    dest_port: int | None
    bytes_transferred: int
    start_time: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "internal_host": self.internal_host,
            "exfil_destination": self.exfil_destination,
            "dest_port": self.dest_port,
            "bytes_transferred": self.bytes_transferred,
            "start_time": self.start_time,
        }


def detect_exfiltration(text: str, *, byte_threshold: int = 50_000_000) -> ExfilReport:
    """Flag the (internal-src, external-dst) pair moving the most bytes,
    provided that total exceeds ``byte_threshold``. Ordinary web/DNS traffic
    to external IPs stays far below the threshold and is ignored."""
    records = parse_flow_log(text)
    totals: dict[tuple[str, str], int] = {}
    ports: dict[tuple[str, str], dict[int, int]] = {}
    first_seen: dict[tuple[str, str], str] = {}

    for rec in records:
        if not _is_internal(rec.src_ip) or _is_internal(rec.dst_ip):
            continue
        key = (rec.src_ip, rec.dst_ip)
        totals[key] = totals.get(key, 0) + rec.num_bytes
        port_counts = ports.setdefault(key, {})
        port_counts[rec.dst_port] = port_counts.get(rec.dst_port, 0) + rec.num_bytes
        first_seen.setdefault(key, rec.raw_ts)

    if not totals:
        return ExfilReport(None, None, None, 0, None)

    best_key = max(totals, key=lambda k: totals[k])
    if totals[best_key] < byte_threshold:
        return ExfilReport(None, None, None, 0, None)

    src_ip, dst_ip = best_key
    dominant_port = max(ports[best_key], key=lambda p: ports[best_key][p])
    return ExfilReport(
        internal_host=src_ip,
        exfil_destination=dst_ip,
        dest_port=dominant_port,
        bytes_transferred=totals[best_key],
        start_time=first_seen[best_key],
    )
