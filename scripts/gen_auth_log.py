"""One-off generator for the bundled brute_force_ssh fixture (synthetic, local only).

Run manually; output is committed as a static fixture, not regenerated at runtime.
"""

lines = []


def add(ts: str, pid: int, msg: str) -> None:
    lines.append(f"{ts} web01 sshd[{pid}]: {msg}")


# --- benign background noise: normal admins logging in from internal IPs ---
add("Jan 15 02:58:11", 1001, "Accepted publickey for deploy from 10.0.0.5 port 51322 ssh2: RSA SHA256:9fK2...")
add("Jan 15 03:02:45", 1002, "Accepted publickey for deploy from 10.0.0.9 port 40110 ssh2: RSA SHA256:9fK2...")

# --- decoy: a single typo'd password, not a brute force (below threshold) ---
add("Jan 15 03:05:19", 1003, "Failed password for bob from 198.51.100.20 port 33212 ssh2")
add("Jan 15 03:05:26", 1004, "Accepted password for bob from 198.51.100.20 port 33212 ssh2")

# --- attack: credential-stuffing brute force from 203.0.113.55 ---
attacker = "203.0.113.55"
usernames = ["admin", "test", "oracle", "git", "ubuntu", "postgres", "deploy", "guest", "root"]
ts_seq = [
    "Jan 15 03:14:02",
    "Jan 15 03:14:19",
    "Jan 15 03:14:37",
    "Jan 15 03:15:03",
    "Jan 15 03:15:41",
    "Jan 15 03:16:20",
    "Jan 15 03:17:02",
    "Jan 15 03:17:48",
    "Jan 15 03:18:22",
]
pid = 2001
for user, ts in zip(usernames, ts_seq, strict=True):
    invalid = "invalid user " if user != "root" else ""
    add(ts, pid, f"Failed password for {invalid}{user} from {attacker} port 51422 ssh2")
    pid += 1

# breach: attacker finally succeeds as root
add("Jan 15 03:18:47", pid, f"Accepted password for root from {attacker} port 51422 ssh2")
pid += 1

# post-compromise noise: attacker opens a second session moments later
add("Jan 15 03:21:05", pid, f"Accepted password for root from {attacker} port 51500 ssh2")
pid += 1

# --- more benign noise after the breach, to make naive "last accepted" wrong ---
add("Jan 15 03:40:12", pid, "Accepted publickey for deploy from 10.0.0.5 port 55210 ssh2: RSA SHA256:9fK2...")

print("\n".join(lines))
print(f"\n# total lines: {len(lines)}", )
