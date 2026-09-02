"""One-off generator for the bundled exfil_flow_logs fixture (synthetic, local only).

Run manually; output is committed as a static fixture, not regenerated at runtime.
"""

lines = ["timestamp,src_ip,dst_ip,src_port,dst_port,proto,bytes"]


def add(ts: str, src: str, dst: str, sport: int, dport: int, proto: str, num_bytes: int) -> None:
    lines.append(f"{ts},{src},{dst},{sport},{dport},{proto},{num_bytes}")


# --- benign background: DNS lookups, ordinary HTTPS browsing, internal DB chatter ---
add("Jan 15 01:58:02", "10.20.6.10", "8.8.8.8", 54211, 53, "udp", 88)
add("Jan 15 01:58:44", "10.20.6.44", "172.217.16.68", 51122, 443, "tcp", 214000)
add("Jan 15 01:59:10", "10.20.6.44", "10.20.6.5", 51130, 5432, "tcp", 44200)
add("Jan 15 02:00:02", "10.20.6.10", "8.8.8.8", 54233, 53, "udp", 92)
add("Jan 15 02:01:15", "10.20.6.51", "172.217.16.68", 50811, 443, "tcp", 188400)
add("Jan 15 02:02:47", "10.20.6.44", "10.20.6.5", 51188, 5432, "tcp", 51200)

# --- attack: sustained large outbound transfer from a workstation to a rare
#     external IP over a non-standard port, well past midnight ---
exfil_dst = "185.199.108.153"
for ts, sport, num_bytes in [
    ("Jan 15 02:14:03", 52142, 158_200_000),
    ("Jan 15 02:15:07", 52142, 161_400_000),
    ("Jan 15 02:16:11", 52142, 159_900_000),
    ("Jan 15 02:17:16", 52144, 152_300_000),
    ("Jan 15 02:18:20", 52144, 149_700_000),
]:
    add(ts, "10.20.6.44", exfil_dst, sport, 8443, "tcp", num_bytes)

# --- more benign trailing traffic ---
add("Jan 15 02:20:05", "10.20.6.10", "8.8.8.8", 54290, 53, "udp", 101)
add("Jan 15 02:21:33", "10.20.6.51", "172.217.16.68", 50902, 443, "tcp", 97300)
add("Jan 15 02:44:12", "10.20.6.44", "10.20.6.5", 51244, 5432, "tcp", 38900)

print("\n".join(lines))
