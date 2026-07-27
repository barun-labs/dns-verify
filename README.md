# dns-verify

CLI tool to test DNS resolution across multiple resolvers (TM Unifi, TIME Internet, Cloudflare, Google) and check propagation status in parallel.

## Example Output

```text
⚡ Running DNS queries (2 domains × 2 servers = 4 checks)...

┌──────────────────┬──────────────┬───────┬────────────────┬────────────────────────────────┐
│ DOMAIN           │ SERVER       │ QTIME │ REDIRECT-CNAME │ RESOLVED-IP                    │
├──────────────────┼──────────────┼───────┼────────────────┼────────────────────────────────┤
│ example.com      │ 1.1.1.1      │ 12ms  │ -              │ ✔ 93.184.216.34                │
│                  │ 8.8.8.8      │ 15ms  │ -              │ ✔ 93.184.216.34                │
├──────────────────┼──────────────┼───────┼────────────────┼────────────────────────────────┤
│ nlkperformance   │ 210.19.6.81  │ 10ms  │ -              │ ✔ 145.79.24.207, 145.79.29.231 │
│                  │ 210.19.6.82  │ 12ms  │ -              │ ✔ 145.79.29.231, 145.79.24.207 │
└──────────────────┴──────────────┴───────┴────────────────┴────────────────────────────────┘
 Summary: 4 OK, 0 Failed/Timeout
```

## Usage

Run interactively:
```bash
python3 dns_verify.py
```

Or query directly from CLI:
```bash
python3 dns_verify.py example.com google.com
python3 dns_verify.py example.com -t MX
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
- **PTR Auto-Reverse**: Passing an IP like `1.1.1.1` under PTR mode automatically formats it to `1.1.1.1.in-addr.arpa`.
- **Presets**: TM Unifi, TIME Internet, Cloudflare, Google, Quad9, OpenDNS, AdGuard DNS included.
- **Parallel Checks**: Uses thread pools for fast multi-server queries.
- **Clean Table Output**: Formatted Unicode table with query response times and status flags.

## License

MIT
