"""One-off generator for the bundled web_scanner_probe fixture (synthetic, local only)."""

lines = []


def add(ip: str, ts: str, method: str, path: str, status: int, size: int, ref: str, ua: str) -> None:
    lines.append(f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"')


benign_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

# benign background traffic
add("203.0.113.9", "15/Jan/2026:04:00:01 +0000", "GET", "/", 200, 1820, "-", benign_ua)
add("203.0.113.9", "15/Jan/2026:04:00:04 +0000", "GET", "/static/app.css", 200, 4210, "/", benign_ua)
add("198.51.100.4", "15/Jan/2026:04:00:47 +0000", "GET", "/products?id=42", 200, 3110, "/", benign_ua)
add("198.51.100.4", "15/Jan/2026:04:00:52 +0000", "GET", "/cart", 200, 990, "/products", benign_ua)

# scanner sweep from a single IP, tight timing, malicious payloads + tool UA
scanner_ip = "198.51.100.77"
scanner_ua = "sqlmap/1.7.2#stable (http://sqlmap.org)"
probes = [
    ("GET", "/products?id=1'%20OR%20'1'='1", 403, 210),
    ("GET", "/products?id=1'%20UNION%20SELECT%20NULL--", 403, 210),
    ("GET", "/../../../../etc/passwd", 404, 178),
    ("GET", "/..%2f..%2f..%2fetc%2fpasswd", 404, 178),
    ("GET", "/wp-admin/admin-ajax.php", 404, 178),
    ("GET", "/.env", 404, 178),
    ("GET", "/admin/config.php.bak", 404, 178),
    ("POST", "/uploads/shell.php", 200, 44),
]
ts_seq = [
    "15/Jan/2026:04:02:11 +0000",
    "15/Jan/2026:04:02:13 +0000",
    "15/Jan/2026:04:02:15 +0000",
    "15/Jan/2026:04:02:16 +0000",
    "15/Jan/2026:04:02:18 +0000",
    "15/Jan/2026:04:02:20 +0000",
    "15/Jan/2026:04:02:22 +0000",
    "15/Jan/2026:04:02:25 +0000",
]
for (method, path, status, size), ts in zip(probes, ts_seq, strict=True):
    add(scanner_ip, ts, method, path, status, size, "-", scanner_ua)

# webshell callback moments later, confirming compromise
add(scanner_ip, "15/Jan/2026:04:03:40 +0000", "GET", "/uploads/shell.php?cmd=id", 200, 32, "-", scanner_ua)

# more benign trailing traffic
add("203.0.113.9", "15/Jan/2026:04:05:00 +0000", "GET", "/logout", 200, 512, "/cart", benign_ua)

print("\n".join(lines))
