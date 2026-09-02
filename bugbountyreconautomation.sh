#!/bin/bash
# Recon pipeline (Linux-oriented) with tool checks, modular phases, parallelization, and basic error handling.

set -o pipefail

# ==========================================
# Colors
# ==========================================
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ==========================================
# Tool management
# ==========================================
declare -A TOOL_OK

require_tool() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        TOOL_OK["$name"]=1
    else
        TOOL_OK["$name"]=0
        echo -e "${YELLOW}[!] Tool missing: ${RED}$name${YELLOW} — skipping any steps that require it.${NC}"
    fi
}

tool_available() {
    local name="$1"
    [[ "${TOOL_OK[$name]}" == "1" ]]
}

check_core_tools() {
    # Core utilities
    for t in curl jq grep awk sed sort wc nmap; do
        require_tool "$t"
    done

    # Recon stack
    for t in subfinder assetfinder chaos dnsx naabu httpx katana subzy Gxss uro asnmap amass oneforall anew; do
        require_tool "$t"
    done
}

# ==========================================
# Banner
# ==========================================
print_banner() {
    echo -e "${GREEN}######################################################################"
    echo -e "#                                                                    #"
    echo -e "#         BUG BOUNTY RECON METHODOLOGY AUTOMATED BY HEXWYRM          #"
    echo -e "#                                                                    #"
    echo -e "######################################################################${NC}"
}

# ==========================================
# Phase 0: Setup
# ==========================================
setup_target() {
    TARGET="$1"

    if [ -z "$TARGET" ]; then
      echo -e "${RED}[!] Usage: $0 <target.com>${NC}"
      exit 1
    fi

    echo -e "${BLUE}[*] Initializing Recon for: ${YELLOW}$TARGET${NC}"

    mkdir -p "$TARGET" || { echo -e "${RED}[!] Failed to create directory $TARGET${NC}"; exit 1; }
    cd "$TARGET" || { echo -e "${RED}[!] Failed to enter directory $TARGET${NC}"; exit 1; }

    # Download resolvers if not present
    if [ ! -f "resolvers.txt" ]; then
        if tool_available curl; then
            echo -e "${YELLOW}[*] Downloading public resolvers...${NC}"
            if ! curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt; then
                echo -e "${RED}[!] Failed to download resolvers.txt. DNS resolution may fail.${NC}"
            fi
        else
            echo -e "${RED}[!] curl not available; cannot download resolvers.txt.${NC}"
        fi
    fi

    echo -e "${GREEN}[+] Starting Recon. Output directory: $(pwd)${NC}\n"
}

# ==========================================
# Phase 1: Fast Passive Intelligence
# ==========================================
phase1_passive() {
    echo -e "${BLUE}[*] Phase 1: Fast Passive Intelligence${NC}"

    # URLScan IP extraction
    if tool_available curl && tool_available jq; then
        echo -e "${YELLOW}  -> Extracting IPs (URLScan)...${NC}"
        if ! curl -fsSL "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=10000" \
            | jq -r '.results[]?.page?.ip//empty' \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | sort -u > urlscan_ips.txt 2>/dev/null; then
            echo -e "${RED}  [!] URLScan query failed; skipping urlscan_ips.txt.${NC}"
        fi
    else
        echo -e "${YELLOW}  [!] Skipping URLScan (curl/jq missing).${NC}"
    fi

    # Run subdomain tools in parallel where possible
    pids=()

    if tool_available subfinder; then
        echo -e "${YELLOW}  -> Running Subfinder...${NC}"
        subfinder -d "$TARGET" -all -recursive -silent -o sub_subfinder.txt 2>/dev/null &
        pids+=($!)
    else
        echo -e "${YELLOW}  [!] Skipping Subfinder.${NC}"
    fi

    if tool_available assetfinder; then
        echo -e "${YELLOW}  -> Running Assetfinder...${NC}"
        assetfinder --subs-only "$TARGET" > sub_assetfinder.txt 2>/dev/null &
        pids+=($!)
    else
        echo -e "${YELLOW}  [!] Skipping Assetfinder.${NC}"
    fi

    if tool_available curl && tool_available jq; then
        echo -e "${YELLOW}  -> Running CRT.sh...${NC}"
        (
            if ! curl -fsSL "https://crt.sh/?q=%25.$TARGET&output=json" \
                | jq -r '.[].name_value' \
                | sed 's/\*\.//g' \
                | sort -u > sub_crtsh.txt 2>/dev/null; then
                echo -e "${RED}  [!] CRT.sh query failed; skipping sub_crtsh.txt.${NC}"
            fi
        ) &
        pids+=($!)
    else
        echo -e "${YELLOW}  [!] Skipping CRT.sh (curl/jq missing).${NC}"
    fi

    if tool_available chaos; then
        echo -e "${YELLOW}  -> Running Chaos...${NC}"
        chaos -d "$TARGET" -silent > sub_chaos.txt 2>/dev/null &
        pids+=($!)
    else
        echo -e "${YELLOW}  [!] Skipping Chaos.${NC}"
    fi

    # Wait for all background jobs
    if [ "${#pids[@]}" -gt 0 ]; then
        wait "${pids[@]}"
    fi

    # Merge Subdomains
    if tool_available anew; then
        echo -e "${YELLOW}  -> Merging all fast subdomains...${NC}"
        cat sub_*.txt 2>/dev/null | sort -u | anew allsubs_fast.txt 2>/dev/null
        if [ -s allsubs_fast.txt ]; then
            echo -e "${GREEN}[+] Fast Passive Mapping Completed. Found $(wc -l < allsubs_fast.txt) subdomains.${NC}\n"
        else
            echo -e "${RED}[!] No subdomains found in Phase 1.${NC}\n"
        fi
    else
        echo -e "${RED}[!] anew missing; cannot merge subdomain lists into allsubs_fast.txt.${NC}\n"
    fi
}

# ==========================================
# Phase 2: DNS Resolution
# ==========================================
phase2_dns() {
    echo -e "${BLUE}[*] Phase 2: DNS Resolution${NC}"

    if ! tool_available dnsx; then
        echo -e "${YELLOW}  [!] dnsx missing; skipping DNS resolution.${NC}\n"
        return
    fi

    if [ ! -s allsubs_fast.txt ]; then
        echo -e "${YELLOW}  [!] allsubs_fast.txt is empty or missing; skipping DNS resolution.${NC}\n"
        return
    fi

    dnsx -r resolvers.txt -silent < allsubs_fast.txt | anew resolved_subs.txt 2>/dev/null
    if [ -s resolved_subs.txt ]; then
        echo -e "${GREEN}[+] Active Subdomains: $(wc -l < resolved_subs.txt)${NC}\n"
    else
        echo -e "${RED}[!] No active subdomains resolved.${NC}\n"
    fi
}

# ==========================================
# Phase 3: Infrastructure & Port Analysis
# ==========================================
phase3_ports() {
    echo -e "${BLUE}[*] Phase 3: Infrastructure & Port Analysis${NC}"

    if ! tool_available naabu; then
        echo -e "${YELLOW}  [!] naabu missing; skipping port scanning.${NC}\n"
        return
    fi

    if [ ! -s resolved_subs.txt ]; then
        echo -e "${YELLOW}  [!] resolved_subs.txt missing or empty; skipping port scanning.${NC}\n"
        return
    fi

    naabu -list resolved_subs.txt -top-ports 100 -exclude-ports 80,443 -silent -o naabu_ports.txt 2>/dev/null

    if [ -s naabu_ports.txt ] && tool_available nmap; then
        echo -e "${YELLOW}  -> Running Nmap on discovered ports...${NC}"
        if ! nmap -sV -sC -iL naabu_ports.txt -oN nmap_details.txt 2>/dev/null; then
            echo -e "${RED}  [!] Nmap scan failed.${NC}"
        fi
    else
        echo -e "${YELLOW}  [!] No ports found by naabu or nmap missing; skipping Nmap.${NC}"
    fi

    echo -e "${GREEN}[+] Port Scanning Completed.${NC}\n"
}

# ==========================================
# Phase 4: Web Probing & Vulnerability Scanning
# ==========================================
phase4_web() {
    echo -e "${BLUE}[*] Phase 4: Web Probing & Vulnerability Scanning${NC}"

    if ! tool_available httpx; then
        echo -e "${YELLOW}  [!] httpx missing; skipping web probing.${NC}\n"
        return
    fi

    if [ ! -s resolved_subs.txt ]; then
        echo -e "${YELLOW}  [!] resolved_subs.txt missing or empty; skipping web probing.${NC}\n"
        return
    fi

    echo -e "${YELLOW}  -> Running HTTPX...${NC}"
    httpx -list resolved_subs.txt -status-code -title -tech-detect -follow-redirects -silent -o live_web.txt 2>/dev/null
    awk '{print $1}' live_web.txt > live_urls.txt 2>/dev/null

    if tool_available subzy; then
        echo -e "${YELLOW}  -> Checking Subdomain Takeovers...${NC}"
        subzy run --targets resolved_subs.txt > takeover_results.txt 2>/dev/null || \
            echo -e "${RED}  [!] subzy encountered an error.${NC}"
    else
        echo -e "${YELLOW}  [!] subzy missing; skipping takeover checks.${NC}"
    fi

    echo -e "${GREEN}[+] Web Probing Completed.${NC}\n"
}

# ==========================================
# Phase 5: Deep Content & JavaScript Analysis
# ==========================================
phase5_content() {
    echo -e "${BLUE}[*] Phase 5: Deep Content & JavaScript Analysis${NC}"

    if ! tool_available katana; then
        echo -e "${YELLOW}  [!] katana missing; skipping crawling and JS/content mining.${NC}\n"
        return
    fi

    if [ ! -s live_urls.txt ]; then
        echo -e "${YELLOW}  [!] live_urls.txt missing or empty; skipping crawling.${NC}\n"
        return
    fi

    echo -e "${YELLOW}  -> Crawling with Katana...${NC}"
    katana -list live_urls.txt -kf all -silent -o katana_urls.txt 2>/dev/null || \
        echo -e "${RED}  [!] Katana encountered an error.${NC}"

    echo -e "${YELLOW}  -> Extracting sensitive files and JS...${NC}"
    if [ -s katana_urls.txt ]; then
        grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.zip|\.bak|\.config|\.yaml" katana_urls.txt \
            | sort -u > sensitive_files.txt 2>/dev/null
        grep "\.js$" katana_urls.txt | sort -u > js_files.txt 2>/dev/null
    else
        echo -e "${RED}  [!] No URLs crawled. Skipping extraction.${NC}"
    fi

    echo -e "${GREEN}[+] JS & Content Mining Completed.${NC}\n"
}

# ==========================================
# Phase 6: Input & Parameter Fuzzing
# ==========================================
phase6_params() {
    echo -e "${BLUE}[*] Phase 6: Input & Parameter Fuzzing${NC}"

    if [ ! -s katana_urls.txt ]; then
        echo -e "${YELLOW}  [!] katana_urls.txt missing or empty; skipping parameter mining.${NC}\n"
        return
    fi

    if ! tool_available uro || ! tool_available Gxss; then
        echo -e "${YELLOW}  [!] uro or Gxss missing; skipping XSS parameter mining.${NC}\n"
        return
    fi

    echo -e "${YELLOW}  -> Mining parameters for XSS...${NC}"
    cat katana_urls.txt | uro | grep "=" | Gxss -p Rxss -o xss_params.txt 2>/dev/null || \
        echo -e "${RED}  [!] Gxss/uro pipeline encountered an error.${NC}"

    echo -e "${GREEN}[+] Parameter Mining Completed.${NC}\n"
}

# ==========================================
# Phase 7: Slow & Heavy Enumeration
# ==========================================
phase7_heavy() {
    echo -e "${BLUE}[*] Phase 7: Slow & Heavy Enumeration (Running at the end)${NC}"

    if tool_available asnmap; then
        echo -e "${YELLOW}  -> Running ASN mapping (Extracting IPs only)...${NC}"
        asnmap -d "$TARGET" -silent -4 > asn_ips_late.txt 2>/dev/null || \
            echo -e "${RED}  [!] asnmap encountered an error.${NC}"
    else
        echo -e "${YELLOW}  [!] asnmap missing; skipping ASN mapping.${NC}"
    fi

    if tool_available oneforall; then
        echo -e "${YELLOW}  -> Running OneForAll (This takes time)...${NC}"
        oneforall --target "$TARGET" --brute False run > /dev/null 2>&1
        if [ -d "results" ]; then
            grep -oE "([a-zA-Z0-9.-]+)\.$TARGET" results/*.csv | cut -d':' -f2 | sort -u > sub_oneforall_late.txt 2>/dev/null
            rm -rf results
        fi
    else
        echo -e "${YELLOW}  [!] oneforall missing; skipping OneForAll.${NC}"
    fi

    if tool_available amass; then
        echo -e "${YELLOW}  -> Running Amass Passive (This takes the most time)...${NC}"
        amass enum -passive -d "$TARGET" -timeout 10 -o sub_amass_late.txt 2>/dev/null || \
            echo -e "${RED}  [!] amass encountered an error.${NC}"
    else
        echo -e "${YELLOW}  [!] amass missing; skipping Amass.${NC}"
    fi

    if tool_available anew; then
        cat sub_oneforall_late.txt sub_amass_late.txt 2>/dev/null | sort -u | anew allsubs_fast.txt > new_slow_subs.txt 2>/dev/null
        if [ -s new_slow_subs.txt ]; then
            echo -e "${GREEN}[+] Heavy Enumeration found $(wc -l < new_slow_subs.txt) additional subdomains! Saved in new_slow_subs.txt${NC}"
        fi
    else
        echo -e "${RED}  [!] anew missing; cannot merge heavy enumeration results.${NC}"
    fi

    echo -e "${GREEN}######################################################################"
    echo -e "#    🎉 FULL RECON COMPLETED SUCCESSFULLY FOR: $TARGET               #"
    echo -e "#    📂 Data is neatly organized in: $(pwd)                          #"
    echo -e "######################################################################${NC}"
}

# ==========================================
# Main Orchestrator
# ==========================================
main() {
    print_banner
    check_core_tools
    setup_target "$1"

    phase1_passive
    phase2_dns
    phase3_ports
    phase4_web
    phase5_content
    phase6_params

    echo -e "${GREEN}######################################################################"
    echo -e "#    ✅ FAST RECON COMPLETED! YOU CAN START HACKING NOW!             #"
    echo -e "######################################################################${NC}\n"

    phase7_heavy

    cd ..
}

main "$@"
