#!/usr/bin/env python3
"""DNS verification & multi-server propagation query tool."""

import sys
import os
import re
import shutil
import subprocess
import concurrent.futures
import argparse
import json
import csv
import statistics
import time

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from rich.console import Console
    from rich.table import Table
    import questionary
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
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
        "name": "TIME Internet Malaysia",
        "servers": [
            "210.19.6.81",
            "210.19.6.82",
            "210.19.6.103",
            "210.19.6.106",
            "210.19.6.109",
            "210.19.6.135",
            "210.19.6.138",
            "210.19.6.141"
        ]
    },
    "2": {
        "name": "Cloudflare & Google (1.1.1.1, 8.8.8.8)",
        "servers": ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]
    },
    "3": {
        "name": "TM Unifi / Telekom Malaysia",
        "servers": [
            "202.188.0.132",
            "202.188.18.188",
            "1.9.1.9",
            "202.188.1.5",
            "202.188.0.133"
        ]
    },
    "4": {
        "name": "Quad9 (9.9.9.9, 149.112.112.112)",
        "servers": ["9.9.9.9", "149.112.112.112"]
    },
    "5": {
        "name": "OpenDNS (208.67.222.222, 208.67.220.220)",
        "servers": ["208.67.222.222", "208.67.220.220"]
    },
    "6": {
        "name": "AdGuard DNS (94.140.14.14, 94.140.15.15)",
        "servers": ["94.140.14.14", "94.140.15.15"]
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

def query_single_dns(domain: str, server: str, qtype: str = "A", timeout: int = 2, subnet: str = None, use_doh: bool = False, use_dot: bool = False) -> Dict[str, Any]:
    """Execute dig command for a domain against a specific DNS server."""
    target = domain
    if qtype.upper() == "PTR" and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        target = f"{'.'.join(reversed(domain.split('.')))}.in-addr.arpa"

    cmd = ["dig", "+tries=1", f"+time={timeout}", f"@{server}", target, qtype]
    if subnet:
        cmd.append(f"+subnet={subnet}")
    if use_doh:
        cmd.append("+https")
    if use_dot:
        cmd.append("+tls")
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

def run_benchmark_queries(domain: str, server: str, qtype: str, timeout: int, subnet: str, use_doh: bool, use_dot: bool, runs: int) -> Dict[str, Any]:
    qtimes = []
    last_res = None
    for _ in range(runs):
        res = query_single_dns(domain, server, qtype, timeout, subnet, use_doh, use_dot)
        last_res = res
        if res["qtime"] not in ["TIMEOUT", "ERR", "-"]:
            qtimes.append(int(res["qtime"].replace("ms", "")))
    if last_res and qtimes:
        avg = sum(qtimes) / len(qtimes)
        last_res["qtime"] = f"{min(qtimes)}/{int(avg)}/{max(qtimes)}ms"
    return last_res

def run_dns_verification(domains: List[str], servers: List[str], qtype: str = "A", subnet: str = None, use_doh: bool = False, use_dot: bool = False, benchmark: int = 0) -> List[Dict[str, Any]]:
    """Run DNS queries in parallel for all domains and servers."""
    results = []

    print(f"\n{COLOR_CYAN}Running DNS queries ({len(domains)} domains × {len(servers)} servers = {len(domains)*len(servers)} checks)...{COLOR_RESET}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        if benchmark > 0:
            future_to_query = {
                executor.submit(run_benchmark_queries, d, s, qtype, 2, subnet, use_doh, use_dot, benchmark): (d, s)
                for d in domains for s in servers
            }
        else:
            future_to_query = {
                executor.submit(query_single_dns, d, s, qtype, 2, subnet, use_doh, use_dot): (d, s)
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
        "A": "RESOLVED-IP", "AAAA": "RESOLVED-IPV6", "MX": "MX-RECORDS",
        "TXT": "TXT-RECORDS", "NS": "NAME-SERVERS", "PTR": "PTR-DOMAINS",
        "CNAME": "CNAME-TARGETS", "SOA": "SOA-RECORDS", "SRV": "SRV-RECORDS",
        "CAA": "CAA-RECORDS"
    }
    rec_header = header_map.get(qtype.upper(), f"{qtype.upper()}-RECORDS")

    if HAS_RICH and use_colors:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("DOMAIN", style="bold")
        table.add_column("SERVER", style="cyan")
        table.add_column("QTIME")
        table.add_column("REDIRECT-CNAME", style="yellow")
        table.add_column(rec_header)

        curr_dom = None
        for r in results:
            is_first = (r["domain"] != curr_dom)
            curr_dom = r["domain"]
            
            dom_str = r['domain'] if is_first else ""
            status, ip_str, qtime, cname = r["status"], r["ip"], r["qtime"], r["cname"]
            
            if "TIMEOUT" in ip_str or "ERROR" in ip_str or status in ["SERVFAIL", "REFUSED"]:
                ip_fmt = f"[red]✖ {ip_str}[/red]"
                qtime_fmt = f"[red]{qtime}[/red]"
            elif "NXDOMAIN" in ip_str:
                ip_fmt = f"[yellow]⚠️ {ip_str}[/yellow]"
                qtime_fmt = f"[yellow]{qtime}[/yellow]"
            else:
                ip_fmt = f"[green]✔ {ip_str}[/green]"
                qtime_fmt = f"[cyan]{qtime}[/cyan]"
                
            cname_fmt = f"[yellow]{cname}[/yellow]" if cname != "-" else f"[dim]{cname}[/dim]"
            
            if is_first and r != results[0]:
                table.add_section()
                
            table.add_row(dom_str, r['server'], qtime_fmt, cname_fmt, ip_fmt)
            
        console.print(table)
        
        ok_cnt = sum(1 for r in results if r["status"] == "NOERROR")
        fail_cnt = len(results) - ok_cnt
        fail_c = "red" if fail_cnt else "dim"
        console.print(f" [dim]Summary: [green]{ok_cnt} OK[/green], [{fail_c}]{fail_cnt} Failed/Timeout[/{fail_c}]\\n")
        return

    # Fallback to plain text
    w_dom = max(len("DOMAIN"), max(len(r["domain"]) for r in results))
    w_srv = max(len("SERVER"), max(len(r["server"]) for r in results))
    w_time = max(len("QTIME"), max(len(r["qtime"]) for r in results))
    w_cn = max(len("REDIRECT-CNAME"), max(len(r["cname"]) for r in results))
    w_ip = max(len(rec_header), max(len(r["ip"]) + 2 for r in results))

    fmt = f"│ {{:<{w_dom}}} │ {{:<{w_srv}}} │ {{:<{w_time}}} │ {{:<{w_cn}}} │ {{:<{w_ip}}} │"
    top = f"┌{'─' * (w_dom+2)}┬{'─' * (w_srv+2)}┬{'─' * (w_time+2)}┬{'─' * (w_cn+2)}┬{'─' * (w_ip+2)}┐"
    sep = f"├{'─' * (w_dom+2)}┼{'─' * (w_srv+2)}┼{'─' * (w_time+2)}┼{'─' * (w_cn+2)}┼{'─' * (w_ip+2)}┤"
    bot = f"└{'─' * (w_dom+2)}┴{'─' * (w_srv+2)}┴{'─' * (w_time+2)}┴{'─' * (w_cn+2)}┴{'─' * (w_ip+2)}┘"

    print(top)
    print(fmt.format("DOMAIN", "SERVER", "QTIME", "REDIRECT-CNAME", rec_header))
    print(sep)
    for r in results:
        print(fmt.format(r["domain"], r["server"], r["qtime"], r["cname"], r["ip"]))
    print(bot + "\n")

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

try:
    import tty, termios
except ImportError:
    pass

def getch():
    if not sys.stdin.isatty():
        ch = sys.stdin.read(1)
        if ch == '': raise EOFError
        return ch
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    if ch == '\x03':  # Ctrl+C
        raise KeyboardInterrupt
    return ch

def prompt_instant(title, choices, default=None):
    console.print(f"\n[bold]{title}[/bold]")
    for k, v in choices.items():
        console.print(f"  [[cyan]{k}[/cyan]] {v}")
    
    valid_keys = list(choices.keys())
    
    while True:
        sys.stdout.write("Choice: ")
        sys.stdout.flush()
        ch = getch()
        
        if ch in valid_keys:
            sys.stdout.write(f"{ch}\n")
            return ch
        elif ch in ('\r', '\n') and default:
            sys.stdout.write(f"{default}\n")
            return default
        else:
            sys.stdout.write(f"{ch}\n")
            console.print(f"[red]Invalid choice. Press one of: {', '.join(valid_keys)}[/red]")

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
    """Fast Single-Keystroke CLI menu mode."""
    if not HAS_RICH:
        print("rich package is required for the new TUI.")
        sys.exit(1)
        
    console.print("[bold cyan]=====================================================[/bold cyan]")
    console.print("[bold cyan]   🌐 DNS Verification & Propagation Multi-Query Tool[/bold cyan]")
    console.print("[bold cyan]=====================================================[/bold cyan]\n")

    # Step 1: Select Domains
    dom_choice = prompt_instant(
        "Step 1: Select Domains / Queries to run",
        {"1": f"Use default example domains ({', '.join(PRESET_DOMAINS)})", "2": "Enter custom domain list"},
        default="1"
    )
    if dom_choice == "1":
        domains = PRESET_DOMAINS
        console.print(f"Selected preset domains: {', '.join(domains)}\n")
    else:
        domains = get_multiline_input("\nEnter domain name(s) to query:")

    # Step 2: Select DNS Servers
    srv_choices = {str(k): f"{v['name']} ({', '.join(v['servers'][:2])}...)" for k, v in PRESET_SERVERS.items()}
    srv_choices["8"] = "Custom DNS Server IP(s)"
    srv_choices["9"] = "Combine Presets + Custom DNS Servers"
    
    srv_choice = prompt_instant("Step 2: Choose DNS Server(s)", srv_choices, default="1")
    
    servers = []
    if srv_choice in PRESET_SERVERS:
        servers.extend(PRESET_SERVERS[srv_choice]["servers"])
    elif srv_choice == "8":
        custom_input = input("\nEnter custom DNS IP(s) (comma separated): ").strip()
        if custom_input:
            servers.extend([s.strip() for s in re.split(r'[\s,]+', custom_input) if s.strip()])
    elif srv_choice == "9":
        base_c = prompt_instant("Select base preset", {str(k): v['name'] for k, v in PRESET_SERVERS.items()})
        if base_c in PRESET_SERVERS:
            servers.extend(PRESET_SERVERS[base_c]["servers"])
        custom_input = input("\nEnter additional custom DNS IP(s): ").strip()
        if custom_input:
            servers.extend([s.strip() for s in re.split(r'[\s,]+', custom_input) if s.strip()])

    if not servers:
        servers = PRESET_SERVERS["1"]["servers"]
    servers = list(dict.fromkeys(servers))

    # Step 3: Select Record Type
    record_types = {
        "A": "IPv4 address", "AAAA": "IPv6 address", "CNAME": "Canonical name / domain alias",
        "MX": "Mail server records", "TXT": "Text records (SPF, DKIM, verification)",
        "NS": "Name server records", "PTR": "Pointer record / Reverse DNS",
        "SOA": "Start of Authority", "SRV": "Service record", "CAA": "Certificate Authority Authorization"
    }
    rt_choices = {}
    rt_keys_map = {}
    for i, (k, v) in enumerate(record_types.items()):
        key = str(i+1) if i < 9 else "0"
        rt_choices[key] = f"{k:<5} - {v}"
        rt_keys_map[key] = k
        
    q_choice = prompt_instant("Step 3: Select Record Type", rt_choices, default="1")
    qtype = rt_keys_map.get(q_choice, "A")

    # Step 4: Additional Features
    prop_opt = prompt_instant("Step 4: Run DNS Propagation / Mismatch Analysis?", {"1": "Yes", "2": "No"}, default="2")
    run_prop = (prop_opt == '1')
    
    export_choices = {"1": "None", "2": "CSV", "3": "JSON", "4": "YAML"}
    if not HAS_YAML:
        export_choices["4"] = "YAML (Requires PyYAML)"
        
    export_opt = prompt_instant("Step 5: Export results?", export_choices, default="1")

    # Execute
    results = run_dns_verification(domains, servers, qtype)
    print_table(results, domains, qtype=qtype)
    
    if run_prop:
        check_propagation_diff(results, domains)

    if export_opt == "2":
        filename = input("\nEnter CSV filename [dns_results.csv]: ").strip() or "dns_results.csv"
        with open(filename, "w", newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        console.print(f"[green]✓ CSV output saved to {filename}[/green]")
    elif export_opt == "3":
        filename = input("\nEnter JSON filename [dns_results.json]: ").strip() or "dns_results.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]✓ JSON output saved to {filename}[/green]")
    elif export_opt == "4":
        if not HAS_YAML:
            console.print("[red]PyYAML is not installed. Run: pip install pyyaml[/red]")
        else:
            filename = input("\nEnter YAML filename [dns_results.yaml]: ").strip() or "dns_results.yaml"
            with open(filename, "w") as f:
                yaml.dump(results, f, default_flow_style=False, sort_keys=False)
            console.print(f"[green]✓ YAML output saved to {filename}[/green]")

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
    parser.add_argument("--subnet", help="EDNS Client Subnet to pass (e.g. 1.2.3.0/24)")
    parser.add_argument("--doh", action="store_true", help="Use DNS over HTTPS (requires newer dig)")
    parser.add_argument("--dot", action="store_true", help="Use DNS over TLS (requires newer dig)")
    parser.add_argument("--benchmark", type=int, default=0, metavar="N", help="Run benchmark with N queries per server")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--csv", help="Export results to CSV file")

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

        results = run_dns_verification(domains, servers, args.type, args.subnet, args.doh, args.dot, args.benchmark)
        print_table(results, domains, qtype=args.type)
        if args.prop:
            check_propagation_diff(results, domains)
            
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{COLOR_GREEN}✓ JSON output saved to {args.json}{COLOR_RESET}")
            
        if args.csv:
            with open(args.csv, 'w', newline='') as f:
                if results:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
            print(f"{COLOR_GREEN}✓ CSV output saved to {args.csv}{COLOR_RESET}")
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{COLOR_DIM}Cancelled.{COLOR_RESET}\n")
        sys.exit(0)
