#!/usr/bin/env bash
# ==============================================================================
# Interactive DNS Verification Script (Bash)
# Queries multiple domains across multiple DNS servers with formatted output.
# ==============================================================================

# Default preset lists
DEFAULT_DOMAINS=("pornhub.com" "vapeshop2u.com" "google.com" "tiktok.com")
TM_SERVERS=("202.188.0.132" "202.188.18.188" "1.9.1.9" "202.188.1.5" "202.188.0.133")
TIME_SERVERS=("210.19.6.81" "210.19.6.82")
CLOUDFLARE_SERVERS=("1.1.1.1" "1.0.0.1")
GOOGLE_SERVERS=("8.8.8.8" "8.8.4.4")
QUAD9_SERVERS=("9.9.9.9" "149.112.112.112")
OPENDNS_SERVERS=("208.67.222.222" "208.67.220.220")
ADGUARD_SERVERS=("94.140.14.14" "94.140.15.15")

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${CYAN}=== Interactive DNS Verification Tool ===${NC}\n"

# 1. Ask for Domains
echo -e "${BOLD}Step 1: Specify domain(s) / query target(s)${NC}"
echo "  [1] Enter domain list (space/newline separated)"
echo "  [2] Use default domains (${DEFAULT_DOMAINS[*]})"
read -p "Choice [1/2] (default 1): " d_choice

DOMAINS=()
if [[ "$d_choice" == "2" ]]; then
    DOMAINS=("${DEFAULT_DOMAINS[@]}")
else
    echo -e "\nEnter domain names (press Enter on empty line when done):"
    while true; do
        read -p "> " line
        [[ -z "$line" ]] && break
        for word in $line; do
            DOMAINS+=("$word")
        done
    done
fi

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    echo -e "${RED}No domains specified. Exiting.${NC}"
    exit 1
fi

# 2. Ask for DNS Servers
echo -e "\n${BOLD}Step 2: Specify DNS Server(s)${NC}"
echo "  [1] TM Unifi / Telekom Malaysia (${TM_SERVERS[*]})"
echo "  [2] TIME Internet Malaysia (${TIME_SERVERS[*]})"
echo "  [3] Cloudflare (${CLOUDFLARE_SERVERS[*]})"
echo "  [4] Google (${GOOGLE_SERVERS[*]})"
echo "  [5] Quad9 (${QUAD9_SERVERS[*]})"
echo "  [6] OpenDNS (${OPENDNS_SERVERS[*]})"
echo "  [7] AdGuard DNS (${ADGUARD_SERVERS[*]})"
echo "  [8] Custom DNS Server IP(s)"
echo "  [9] All Presets"
read -p "Choice [1-9] (default 1): " s_choice

SERVERS=()
case "$s_choice" in
    2)
        SERVERS=("${TIME_SERVERS[@]}")
        ;;
    3)
        SERVERS=("${CLOUDFLARE_SERVERS[@]}")
        ;;
    4)
        SERVERS=("${GOOGLE_SERVERS[@]}")
        ;;
    5)
        SERVERS=("${QUAD9_SERVERS[@]}")
        ;;
    6)
        SERVERS=("${OPENDNS_SERVERS[@]}")
        ;;
    7)
        SERVERS=("${ADGUARD_SERVERS[@]}")
        ;;
    8)
        echo -e "\nEnter DNS Server IP(s) (space separated):"
        read -p "> " custom_dns
        SERVERS=($custom_dns)
        ;;
    9)
        SERVERS=("${TM_SERVERS[@]}" "${TIME_SERVERS[@]}" "${CLOUDFLARE_SERVERS[@]}" "${GOOGLE_SERVERS[@]}" "${QUAD9_SERVERS[@]}" "${OPENDNS_SERVERS[@]}" "${ADGUARD_SERVERS[@]}")
        ;;
    *)
        SERVERS=("${TM_SERVERS[@]}")
        ;;
esac

if [[ ${#SERVERS[@]} -eq 0 ]]; then
    echo -e "${RED}No DNS servers specified. Exiting.${NC}"
    exit 1
fi

# 3. Ask for Propagation Analysis
read -p $'\nRun DNS Propagation / Mismatch Analysis? [y/N]: ' p_choice

# Summary before run
echo -e "\n${CYAN}Running query for ${#DOMAINS[@]} domain(s) across ${#SERVERS[@]} server(s)...${NC}\n"

# Output Table Header
printf "%-18s %-16s %-8s %-24s %s\n" "DOMAIN" "SERVER" "QTIME" "REDIRECT-CNAME" "RESOLVED-IP"
printf "%.0s-" {1..84}; echo

# Store output rows for propagation analysis if requested
declare -A DOMAIN_IPS

# Execute DNS Queries
for d in "${DOMAINS[@]}"; do
  for s in "${SERVERS[@]}"; do
    out=$(dig +tries=1 +time=2 @"$s" "$d" 2>&1)
    
    # Extract metrics
    qt=$(echo "$out" | awk -F": " '/Query time/{print $2}' | sed 's/ msec/ms/')
    cn=$(echo "$out" | awk -v D="$d." '$1==D && $4=="CNAME"{print $5; exit}')
    
    # Extract max 3 IPs
    ip_list=$(echo "$out" | awk '$4=="A"{print $5}')
    total_ips=$(echo "$ip_list" | grep -c .)
    ip=$(echo "$ip_list" | head -n 3 | paste -sd "," -)
    if [[ $total_ips -gt 3 ]]; then
        extra=$((total_ips - 3))
        ip="$ip (+$extra more)"
    fi
    
    if [[ -z "$qt" ]]; then
        qt="TIMEOUT"
    fi
    if [[ -z "$ip" ]]; then
        if echo "$out" | grep -q "status: NXDOMAIN"; then
            ip="[NXDOMAIN]"
        elif echo "$out" | grep -q "status: SERVFAIL"; then
            ip="[SERVFAIL]"
        else
            ip="[NO RECORD/TIMEOUT]"
        fi
    fi

    # Record IP for propagation analysis
    DOMAIN_IPS["$d|$s"]="$ip"

    # Print row
    printf "%-18s %-16s %-8s %-24s %s\n" "$d" "$s" "${qt:-TIMEOUT}" "${cn:--}" "${ip}"
  done
  printf "%.0s-" {1..84}; echo
done

# Propagation Analysis (Only if requested)
if [[ "$p_choice" == "y" || "$p_choice" == "Y" ]]; then
    echo -e "\n${BOLD}🔍 DNS Propagation Analysis:${NC}"
    for d in "${DOMAINS[@]}"; do
        echo -e "  • ${BOLD}$d${NC}:"
        for s in "${SERVERS[@]}"; do
            echo -e "      └─ Server $s → ${DOMAIN_IPS["$d|$s"]}"
        done
    done
fi

echo -e "\n${GREEN}✔ Verification complete.${NC}"
