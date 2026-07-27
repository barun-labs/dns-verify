# 🌐 DNS Verification & Propagation Multi-Query Tool

A lightweight, zero-dependency interactive CLI tool for multi-domain DNS verification, record inspection (A, AAAA, CNAME, MX, TXT, NS, PTR), preset ISP server queries (TM Unifi, TIME Internet, Cloudflare, Google), and propagation mismatch analysis.

---

## ⚡ Quick Start

### 1. Requirements
* **Python 3.8+**
* **`dig`** CLI utility (included in `bind-utils` / `bind9-utils` / `bind`)

### 2. Execution

**Interactive Mode:**
```bash
python3 dns_verify.py
```

**Direct CLI Queries:**
```bash
python3 dns_verify.py example.com google.com
python3 dns_verify.py -d example.com -t MX --public
```

---

## 🛠️ Features

* **Multi-Record Querying:** Supports `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, and `PTR` (Reverse DNS).
* **Automatic PTR Reverse IP Lookup:** Auto-formats IP addresses (`1.1.1.1` → `1.1.1.1.in-addr.arpa`).
* **Malaysian & Public DNS Presets:** Built-in TM Unifi, TIME Internet, Cloudflare, and Google DNS servers.
* **Propagation Mismatch Analysis:** Detects inconsistencies across recursive resolvers per domain.
* **Parallel Execution:** Concurrent thread pool for rapid multi-server checks.
* **Formatted Box Table:** Clean Unicode borders, status badges (`✔`, `✖`, `⚠️`), and dynamic column alignment.
* **File Exporting:** Save colorless plain text or structured results to file.

---

## 📄 License
MIT License
