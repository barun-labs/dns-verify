#!/usr/bin/env python3
"""DNS verification & multi-server propagation query tool."""

import sys
import os
import re
import shutil
import subprocess
import concurrent.futures
import argparse
from typing import List, Dict, Any, Tuple

# ANSI Colors for terminal output
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_CYAN = "\033[96m"
COLOR_BLUE = "\033[94m"
COLOR_DIM = "\033[2m"

# Preset DNS Servers
PRESET_SERVERS = {
    "1": {
        "name": "TM Unifi / Telekom Malaysia",
        "servers": [
            "202.188.0.132",
            "202.188.18.188",
            "1.9.1.9",
            "202.188.1.5",
            "202.188.0.133"
        ]
    },
    "2": {
        "name": "TIME Internet Malaysia",
        "servers": [
            "210.19.6.103",
            "210.19.6.106",
            "210.19.6.109",
            "210.19.6.135",
            "210.19.6.141",
            "210.19.6.81",
            "210.19.6.82"
        ]
    },
    "3": {
        "name": "Cloudflare (1.1.1.1, 1.0.0.1)",
        "servers": ["1.1.1.1", "1.0.0.1"]
    },
    "4": {
        "name": "Google (8.8.8.8, 8.8.4.4)",
        "servers": ["8.8.8.8", "8.8.4.4"]
    }
}

# Preset Domains Example
PRESET_DOMAINS = [
    "pornhub.com",
    "vapeshop2u.com",
    "google.com",
    "tiktok.com"
]

def parse_dig_output(domain: str, server: str, output: str, return_code: int, qtype: str = "A") -> Dict[str, Any]:
    """Parse output of dig command for any DNS record type."""
    if return_code != 0 or not output.strip():
        return {
            "domain": domain,
            "server": server,
            "qtime": "TIMEOUT",
            "cname": "-",
            "ip": "TIMEOUT / ERROR",
            "raw_ips": [],
            "status": "TIMEOUT"
        }

    status_match = re.search(r'status:\s*([A-Z]+)', output)
    status = status_match.group(1) if status_match else "UNKNOWN"

    qtime_match = re.search(r';;\s*Query time:\s*(\d+)\s*msec', output)
    qtime = f"{qtime_match.group(1)}ms" if qtime_match else "-"

    # Extract CNAME
    cname = "-"
    cname_matches = re.findall(r'\s+IN\s+CNAME\s+(\S+)', output, re.IGNORECASE)
    if cname_matches:
        cname = cname_matches[0].rstrip('.')

    # Extract all record data from ANSWER SECTION
    records = []
    in_answer = False
    for line in output.splitlines():
        line_s = line.strip()
        if line_s.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        elif line_s.startswith(";;") or not line_s:
            in_answer = False
            continue

        if in_answer:
            parts = line_s.split(None, 4)
            if len(parts) >= 5 and parts[2].upper() == "IN":
                rtype, rdata = parts[3].upper(), parts[4].rstrip('.')
                if rtype != "CNAME":
                    records.append(rdata)

    if status != "NOERROR":
        ip_str = f"[{status}]"
    elif records:
        if len(records) > 3:
            ip_str = ", ".join(records[:3]) + f" (+{len(records)-3} more)"
        else:
            ip_str = ", ".join(records)
    elif cname != "-":
        ip_str = f"[CNAME ONLY]"
    else:
        ip_str = "[NO RECORD]"

    return {
        "domain": domain,
        "server": server,
        "qtime": qtime,
        "cname": cname,
        "ip": ip_str,
        "raw_ips": records,
        "status": status
    }

def query_single_dns(domain: str, server: str, qtype: str = "A", timeout: int = 2) -> Dict[str, Any]:
    """Execute dig command for a domain against a specific DNS server."""
    target = domain
    if qtype.upper() == "PTR" and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        target = f"{'.'.join(reversed(domain.split('.')))}.in-addr.arpa"

    cmd = ["dig", "+tries=1", f"+time={timeout}", f"@{server}", target, qtype]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout+2)
        return parse_dig_output(domain, server, res.stdout, res.returncode, qtype)
    except subprocess.TimeoutExpired:
        return {
            "domain": domain,
            "server": server,
            "qtime": "TIMEOUT",
            "cname": "-",
            "ip": "TIMEOUT",
            "raw_ips": [],
            "status": "TIMEOUT"
        }
    except Exception as e:
        return {
            "domain": domain,
            "server": server,
            "qtime": "ERR",
            "cname": "-",
            "ip": f"ERROR: {e}",
            "raw_ips": [],
            "status": "ERROR"
        }

def run_dns_verification(domains: List[str], servers: List[str], qtype: str = "A") -> List[Dict[str, Any]]:
    """Run DNS queries in parallel for all domains and servers."""
    results = []

    print(f"\n{COLOR_CYAN}⚡ Running DNS queries ({len(domains)} domains × {len(servers)} servers = {len(domains)*len(servers)} checks)...{COLOR_RESET}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_query = {
            executor.submit(query_single_dns, d, s, qtype): (d, s)
            for d in domains for s in servers
        }
        for future in concurrent.futures.as_completed(future_to_query):
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                d, s = future_to_query[future]
                results.append({
                    "domain": d,
                    "server": s,
                    "qtime": "ERR",
                    "cname": "-",
                    "ip": f"ERR: {exc}",
                    "raw_ips": [],
                    "status": "ERROR"
                })

    # Sort results to preserve domain order and server order
    domain_order = {d: i for i, d in enumerate(domains)}
    server_order = {s: i for i, s in enumerate(servers)}
    results.sort(key=lambda x: (domain_order.get(x["domain"], 999), server_order.get(x["server"], 999)))

    return results

def print_table(results: List[Dict[str, Any]], domains: List[str], use_colors: bool = True, qtype: str = "A"):
    """Print results in clean formatted table with dynamic column sizing."""
    if not results:
        return

    header_map = {
        "A": "RESOLVED-IP",
        "AAAA": "RESOLVED-IPV6",
        "MX": "MX-RECORDS",
        "TXT": "TXT-RECORDS",
        "NS": "NAME-SERVERS",
        "PTR": "PTR-DOMAINS",
        "CNAME": "CNAME-TARGETS"
    }
    rec_header = header_map.get(qtype.upper(), f"{qtype.upper()}-RECORDS")

    w_dom = max(len("DOMAIN"), max(len(r["domain"]) for r in results))
    w_srv = max(len("SERVER"), max(len(r["server"]) for r in results))
    w_time = max(len("QTIME"), max(len(r["qtime"]) for r in results))
    w_cn = max(len("REDIRECT-CNAME"), max(len(r["cname"]) for r in results))
    w_ip = max(len(rec_header), max(len(r["ip"]) + 2 for r in results))

    top = f"┌{'─' * (w_dom+2)}┬{'─' * (w_srv+2)}┬{'─' * (w_time+2)}┬{'─' * (w_cn+2)}┬{'─' * (w_ip+2)}┐"
    sep = f"├{'─' * (w_dom+2)}┼{'─' * (w_srv+2)}┼{'─' * (w_time+2)}┼{'─' * (w_cn+2)}┼{'─' * (w_ip+2)}┤"
    bot = f"└{'─' * (w_dom+2)}┴{'─' * (w_srv+2)}┴{'─' * (w_time+2)}┴{'─' * (w_cn+2)}┴{'─' * (w_ip+2)}┘"

    if not use_colors:
        fmt = f"│ {{:<{w_dom}}} │ {{:<{w_srv}}} │ {{:<{w_time}}} │ {{:<{w_cn}}} │ {{:<{w_ip}}} │"
        print(top)
        print(fmt.format("DOMAIN", "SERVER", "QTIME", "REDIRECT-CNAME", rec_header))
        print(sep)
        for r in results:
            print(fmt.format(r["domain"], r["server"], r["qtime"], r["cname"], r["ip"]))
        print(bot + "\n")
        return

    header = (
        f"│ {COLOR_BOLD}{'DOMAIN':<{w_dom}}{COLOR_RESET} │ "
        f"{COLOR_BOLD}{'SERVER':<{w_srv}}{COLOR_RESET} │ "
        f"{COLOR_BOLD}{'QTIME':<{w_time}}{COLOR_RESET} │ "
        f"{COLOR_BOLD}{'REDIRECT-CNAME':<{w_cn}}{COLOR_RESET} │ "
        f"{COLOR_BOLD}{rec_header:<{w_ip}}{COLOR_RESET} │"
    )

    print(top)
    print(header)
    print(sep)

    curr_dom = None
    for r in results:
        is_first = (r["domain"] != curr_dom)
        if curr_dom is not None and is_first:
            print(sep)
        curr_dom = r["domain"]

        status, ip_str, qtime, cname = r["status"], r["ip"], r["qtime"], r["cname"]

        if "TIMEOUT" in ip_str or "ERROR" in ip_str or status in ["SERVFAIL", "REFUSED"]:
            icon = "✖ "
            c_ip, c_qt = COLOR_RED, COLOR_RED
        elif "NXDOMAIN" in ip_str:
            icon = "⚠️ "
            c_ip, c_qt = COLOR_YELLOW, COLOR_YELLOW
        else:
            icon = "✔ "
            c_ip, c_qt = COLOR_GREEN, COLOR_CYAN

        c_cn = COLOR_YELLOW if cname != "-" else COLOR_DIM

        dom_str = r['domain'] if is_first else ""
        dom_c = f"{COLOR_BOLD}{dom_str:<{w_dom}}{COLOR_RESET}"
        srv_c = f"{COLOR_CYAN}{r['server']:<{w_srv}}{COLOR_RESET}"
        qt_c  = f"{c_qt}{qtime:<{w_time}}{COLOR_RESET}"
        cn_c  = f"{c_cn}{cname:<{w_cn}}{COLOR_RESET}"
        ip_c  = f"{c_ip}{(icon + ip_str):<{w_ip}}{COLOR_RESET}"

        print(f"│ {dom_c} │ {srv_c} │ {qt_c} │ {cn_c} │ {ip_c} │")

    print(bot)
    ok_cnt = sum(1 for r in results if r["status"] == "NOERROR")
    fail_cnt = len(results) - ok_cnt
    fail_c = COLOR_RED if fail_cnt else COLOR_DIM
    print(f" {COLOR_DIM}Summary: {COLOR_GREEN}{ok_cnt} OK{COLOR_RESET}{COLOR_DIM}, {fail_c}{fail_cnt} Failed/Timeout{COLOR_RESET}\n")

def check_propagation_diff(results: List[Dict[str, Any]], domains: List[str]):
    """Analyze if DNS answers match across servers per domain."""
    print(f"{COLOR_BOLD}🔍 DNS Propagation & Redirection Analysis:{COLOR_RESET}")
    for d in domains:
        domain_res = [r for r in results if r["domain"] == d]
        ips = set(r["ip"] for r in domain_res)
        cnames = set(r["cname"] for r in domain_res)
        
        if len(ips) == 1 and len(cnames) == 1:
            val = list(ips)[0]
            cn_val = list(cnames)[0]
            cn_info = f" (CNAME: {cn_val})" if cn_val != "-" else ""
            print(f"  • {COLOR_BOLD}{d}{COLOR_RESET}: {COLOR_GREEN}UNIFORM / MATCHED{COLOR_RESET} → {val}{cn_info}")
        else:
            print(f"  • {COLOR_BOLD}{d}{COLOR_RESET}: {COLOR_YELLOW}MISMATCH / REDIRECTED / PROPAGATING{COLOR_RESET}")
            for r in domain_res:
                cn_info = f" [CNAME: {r['cname']}]" if r['cname'] != "-" else ""
                print(f"      └─ Server {r['server']:<15} → {r['ip']}{cn_info}")
    print()

def get_multiline_input(prompt_text: str) -> List[str]:
    """Get multiple lines/pages of input until empty line or done."""
    print(prompt_text)
    print(f"{COLOR_DIM}(Enter domain names separated by space/comma, or paste multiple lines. Press ENTER twice when done):{COLOR_RESET}")
    items = []
    while True:
        try:
            line = input("> ").strip()
            if not line:
                if items:
                    break
                else:
                    print("Input cannot be empty. Please enter at least one entry.")
                    continue
            parts = [p.strip() for p in re.split(r'[\s,]+', line) if p.strip()]
            items.extend(parts)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting input.")
            break
    return list(dict.fromkeys(items))

def interactive_mode():
    """Interactive CLI menu mode."""
    print(f"{COLOR_BOLD}{COLOR_CYAN}====================================================={COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}   🌐 DNS Verification & Propagation Multi-Query Tool{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}====================================================={COLOR_RESET}\n")

    # Step 1: Select or enter Domains
    print(f"{COLOR_BOLD}Step 1: Select Domains / Queries to run{COLOR_RESET}")
    print("  [1] Enter custom domain list (supports multi-line / multi-page entries)")
    print("  [2] Use default example domains (pornhub.com, vapeshop2u.com, google.com, tiktok.com)")
    
    choice = input("\nChoice [1/2] (default: 1): ").strip()
    if choice == "2":
        domains = PRESET_DOMAINS
        print(f"Selected preset domains: {', '.join(domains)}")
    else:
        domains = get_multiline_input("\nEnter domain name(s) to query:")

    # Step 2: Select DNS Servers
    print(f"\n{COLOR_BOLD}Step 2: Choose DNS Server(s){COLOR_RESET}")
    for key, data in PRESET_SERVERS.items():
        print(f"  [{key}] {data['name']} ({', '.join(data['servers'][:3])}{'...' if len(data['servers']) > 3 else ''})")
    print("  [5] Custom DNS Server IP(s) (space/comma separated)")
    print("  [6] Combine Presets + Custom DNS Servers")

    srv_choice = input("\nSelect DNS Server Option [1-6] (default: 1): ").strip()
    if not srv_choice:
        srv_choice = "1"

    servers = []
    if srv_choice in PRESET_SERVERS:
        servers = PRESET_SERVERS[srv_choice]["servers"]
    elif srv_choice == "5":
        custom_input = input("\nEnter DNS Server IP(s): ").strip()
        servers = [s.strip() for s in re.split(r'[\s,]+', custom_input) if s.strip()]
    elif srv_choice == "6":
        print("Select base preset [1-4]: ", end="")
        base_c = input().strip()
        if base_c in PRESET_SERVERS:
            servers.extend(PRESET_SERVERS[base_c]["servers"])
        c_input = input("Enter additional custom DNS IP(s): ").strip()
        if c_input:
            servers.extend([s.strip() for s in re.split(r'[\s,]+', c_input) if s.strip()])
    else:
        servers = PRESET_SERVERS["1"]["servers"]

    servers = list(dict.fromkeys(servers))

    # Step 3: Select Record Type
    print(f"\n{COLOR_BOLD}Step 3: Select Record Type{COLOR_RESET}")
    record_types = {
        "1": ("A", "IPv4 address"),
        "2": ("AAAA", "IPv6 address"),
        "3": ("CNAME", "Canonical name / domain alias"),
        "4": ("MX", "Mail server records"),
        "5": ("TXT", "Text records (SPF, DKIM, verification)"),
        "6": ("NS", "Name server records"),
        "7": ("PTR", "Pointer record / Reverse DNS (IP → Domain)")
    }
    for key, (rtype, desc) in record_types.items():
        rec_tag = f" {COLOR_GREEN}(Recommended){COLOR_RESET}" if key == "1" else ""
        print(f"  [{key}] {rtype:<6} - {desc}{rec_tag}")

    q_choice = input("\nSelect Record Type [1-7] (default: 1): ").strip()
    qtype = record_types.get(q_choice, record_types["1"])[0] if q_choice in record_types else "A"

    # Step 4: Optional Propagation Analysis
    prop_opt = input("\nRun DNS Propagation / Mismatch Analysis? [y/N]: ").strip().lower()
    run_prop = (prop_opt == 'y')

    # Execute
    results = run_dns_verification(domains, servers, qtype)
    print_table(results, domains, qtype=qtype)
    
    if run_prop:
        check_propagation_diff(results, domains)

    # Save option
    save_opt = input("Save results to file? [y/N]: ").strip().lower()
    if save_opt == 'y':
        filename = input("Enter filename (default: dns_results.txt): ").strip()
        if not filename:
            filename = "dns_results.txt"
        with open(filename, "w") as f:
            sys.stdout = f
            print_table(results, domains, use_colors=False, qtype=qtype)
            if run_prop:
                check_propagation_diff(results, domains)
            sys.stdout = sys.__stdout__
        print(f"{COLOR_GREEN}✓ Results saved to {filename}{COLOR_RESET}\n")

def check_dependencies():
    """Verify required system binaries before running."""
    if not shutil.which("dig"):
        print(f"\n{COLOR_RED}✖ Error: 'dig' command not found.{COLOR_RESET}")
        print("This script requires Python 3 and the 'dig' (DNS lookup utility) binary to run.\n")
        sys.exit(1)

def main():
    check_dependencies()
    parser = argparse.ArgumentParser(description="DNS Verification & Multi-Server Query Tool")
    parser.add_argument("targets", nargs="*", help="Domains or IPs to query directly (e.g. dns-verify example.com)")
    parser.add_argument("-d", "--domains", nargs="+", help="Domains to query")
    parser.add_argument("-s", "--servers", nargs="+", help="DNS servers to query")
    parser.add_argument("-t", "--type", default="A", help="Record type (A, CNAME, TXT, MX, etc.)")
    parser.add_argument("--tm", action="store_true", help="Use TM Unifi DNS servers")
    parser.add_argument("--time", action="store_true", help="Use TIME Internet DNS servers")
    parser.add_argument("--public", action="store_true", help="Use Public DNS servers (1.1.1.1, 8.8.8.8, 9.9.9.9)")
    parser.add_argument("-p", "--prop", "--propagation", action="store_true", help="Run DNS Propagation & Mismatch Analysis")

    args = parser.parse_args()
    cli_domains = (args.targets or []) + (args.domains or [])

    if cli_domains or args.servers:
        domains = cli_domains or PRESET_DOMAINS
        servers = []
        if args.servers:
            servers.extend(args.servers)
        if args.tm:
            servers.extend(PRESET_SERVERS["1"]["servers"])
        if args.time:
            servers.extend(PRESET_SERVERS["2"]["servers"])
        if args.public:
            servers.extend(PRESET_SERVERS["3"]["servers"] + PRESET_SERVERS["4"]["servers"])
        if not servers:
            servers = PRESET_SERVERS["1"]["servers"]
        servers = list(dict.fromkeys(servers))

        results = run_dns_verification(domains, servers, args.type)
        print_table(results, domains, qtype=args.type)
        if args.prop:
            check_propagation_diff(results, domains)
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{COLOR_DIM}Cancelled.{COLOR_RESET}\n")
        sys.exit(0)
