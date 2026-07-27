# dns-verify

CLI tool to test DNS resolution across multiple resolvers (TM Unifi, TIME Internet, Cloudflare, Google) and check propagation status in parallel.

This script is also used to verify **MCMC CNAME redirection** functionality in Malaysia when ISP DNS providers configure domain filtering or block redirects.

## Scripts in this Repo

- **`dns_verify.py`** (Recommended): Main tool. Uses parallel thread queries, supports all record types (`A`, `AAAA`, `MX`, `TXT`, `NS`, `PTR`), auto-formats PTR reverse IPs, aligns dynamic tables, and handles `Ctrl+C` exits cleanly.
- **`dns_verify.sh`**: Legacy shell fallback for environments without Python 3. Runs basic sequential `A`/`CNAME` checks.

## Example Output

```text
⚡ Running DNS queries (2 domains × 2 servers = 4 checks)...

┌────────────────┬──────────────┬───────┬────────────────┬────────────────────────────────┐
│ DOMAIN         │ SERVER       │ QTIME │ REDIRECT-CNAME │ RESOLVED-IP                    │
├────────────────┼──────────────┼───────┼────────────────┼────────────────────────────────┤
│ youtube.com    │ 1.1.1.1      │ 12ms  │ -              │ ✔ 142.250.193.206              │
│                │ 8.8.8.8      │ 15ms  │ -              │ ✔ 142.250.193.206              │
├────────────────┼──────────────┼───────┼────────────────┼────────────────────────────────┤
│ vapeshop2u.com │ 210.19.6.81  │ 10ms  │ mcmc.time.net  │ ✔ 175.139.142.25               │
│                │ 210.19.6.82  │ 12ms  │ mcmc.time.net  │ ✔ 175.139.142.25               │
└────────────────┴──────────────┴───────┴────────────────┴────────────────────────────────┘
 Summary: 4 OK, 0 Failed/Timeout
```

## Usage

Run interactively:
```bash
python3 dns_verify.py
```

Or query directly from CLI:
```bash
python3 dns_verify.py youtube.com vapeshop2u.com
python3 dns_verify.py youtube.com -t MX
```

One-line install:
```bash
curl -sSL https://raw.githubusercontent.com/barun-labs/dns-verify/master/dns_verify.py -o dns-verify && chmod +x dns-verify && ./dns-verify
```

## Requirements

- Python 3.8+
- `dig` (installed via `bind-utils` / `bind9-utils` / `bind` package)

## License

MIT
