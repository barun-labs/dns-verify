# dns-verify

CLI tool to test DNS resolution across multiple resolvers (TM Unifi, TIME Internet, Cloudflare, Google) and check propagation status in parallel.

This script is also used to verify **MCMC CNAME redirection** functionality in Malaysia when ISP DNS providers configure domain filtering or block redirects.

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

## Features

- **Record Types**: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`.
- **MCMC Redirection Inspection**: Audit Malaysian ISP DNS filtering and CNAME redirects (`mcmc.time.net.my` / `mcmc.unifi.my`).
- **PTR Auto-Reverse**: Passing an IP like `1.1.1.1` under PTR mode automatically formats it to `1.1.1.1.in-addr.arpa`.
- **Presets**: TM Unifi, TIME Internet, Cloudflare, Google, Quad9, OpenDNS, AdGuard DNS included.
- **Parallel Checks**: Uses thread pools for fast multi-server queries.
- **Clean Table Output**: Formatted Unicode table with query response times and status flags.

## License

MIT
