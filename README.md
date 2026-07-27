# dns-verify

CLI tool to test DNS resolution across multiple resolvers (TM Unifi, TIME Internet, Cloudflare, Google) and check propagation status in parallel.

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
- **Presets**: TM Unifi, TIME Internet, Cloudflare, and Google DNS servers included.
- **Parallel Checks**: Uses thread pools for fast multi-server queries.
- **Clean Table Output**: Formatted Unicode table with query response times and status flags.

## License

MIT
