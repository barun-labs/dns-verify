# 🌐 DNS Verification & Propagation Multi-Query Tool

A lightweight, zero-dependency interactive CLI tool for multi-domain DNS verification, record inspection (A, AAAA, CNAME, MX, TXT, NS, PTR), preset ISP server queries (TM Unifi, TIME Internet, Cloudflare, Google), and propagation mismatch analysis.

---

## 📌 Recommended Script: `dns_verify.py`

> **Note for Users:** Always download and use **`dns_verify.py`**.
> It is the full-featured, parallel-execution tool. `dns_verify.sh` is a legacy fallback script for environments without Python 3.

### 🌟 Script Comparison

| Feature | `dns_verify.py` (Recommended) | `dns_verify.sh` (Legacy Bash) |
|---|---|---|
| **Speed** | ⚡ Parallel thread pool | Sequential execution |
| **Supported Records** | `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR` | Basic `A` / `CNAME` only |
| **UI & Alignment** | Dynamic Unicode box tables (`┌─┬─┐`), status badges (`✔`, `✖`, `⚠️`) | Basic terminal text |
| **PTR Auto-Reverse** | Auto-formats IP (`1.1.1.1` → `in-addr.arpa`) | Manual input required |
| **Error Handling** | Graceful `Ctrl+C` handling | Default shell output |

---

## ⚡ Quick Start

### 1. Requirements
* **Python 3.8+**
* **`dig`** CLI utility (included in `bind-utils` / `bind9-utils` / `bind`)

### 2. Execution

**Interactive Mode (Recommended):**
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

---

## 📄 License
MIT License
