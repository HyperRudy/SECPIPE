#!/usr/bin/bash 
# =============================================================================
# nmap_scanner.sh — Step 1 of the Security Automation Pipeline
# Purpose : Run a structured nmap scan, save raw output, and parse results
#           into a clean, machine-readable format for downstream tools.
# Author  : Security Pipeline v1.0
# Usage   : ./nmap_scanner.sh <target> [output_dir]
# =============================================================================

set -euo pipefail   # Exit on error, unset vars, pipe failures
IFS=$'\n\t'         # Safer word splitting

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.0.0"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Colour codes (disabled automatically if not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${RESET}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
log_section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
                echo -e "${BOLD}${CYAN}  $*${RESET}"; \
                echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

# ─────────────────────────────────────────────────────────────────────────────
# USAGE / HELP
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME}${RESET} v${SCRIPT_VERSION} — nmap scan + structured parser

${BOLD}USAGE${RESET}
    $SCRIPT_NAME <target> [output_dir]

${BOLD}ARGUMENTS${RESET}
    target      IP address, hostname, or CIDR range  (e.g. 192.168.1.1 or 10.0.0.0/24)
    output_dir  Directory to store results            (default: ./scan_results/<timestamp>)

${BOLD}EXAMPLES${RESET}
    $SCRIPT_NAME 192.168.1.1
    $SCRIPT_NAME scanme.nmap.org ./my_scans
    $SCRIPT_NAME 10.0.0.0/24 /tmp/network_audit

${BOLD}OUTPUT FILES${RESET}
    nmap_raw.txt        — Full nmap terminal output
    nmap_raw.xml        — Full nmap XML output (for tool chaining)
    nmap_raw.gnmap      — Greppable nmap output
    open_ports.txt      — Parsed: port|state|service|version
    web_services.txt    — Parsed: ports running HTTP / HTTPS (for nikto/nuclei)
    scan_summary.txt    — Human-readable summary report

EOF
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_dependencies() {
    local missing=0
    local required_tools=("nmap" "grep" "awk" "sed" "cut" "xmllint")

    log_section "Dependency Check"
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_info "  ✔  $tool  ($(command -v "$tool"))"
        else
            # xmllint is optional — warn, don't fail
            if [[ "$tool" == "xmllint" ]]; then
                log_warn "  ✘  $tool  — optional (XML pretty-print unavailable)"
            else
                log_error "  ✘  $tool  — REQUIRED but not found"
                (( missing++ )) || true
            fi
        fi
    done

    if (( missing > 0 )); then
        log_error "${missing} required tool(s) missing. Aborting."
        log_error "Install nmap:  sudo apt install nmap  |  brew install nmap"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
validate_target() {
    local target="$1"

    # Must not be empty
    if [[ -z "$target" ]]; then
        log_error "No target specified."
        usage
    fi

    # Reject obviously dangerous shell metacharacters
    if [[ "$target" =~ [[:space:]]\;|\||\&|\`|\$\( ]]; then
        log_error "Target contains illegal characters: $target"
        exit 1
    fi

    log_info "Target validated: ${BOLD}${target}${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT DIRECTORY SETUP
# ─────────────────────────────────────────────────────────────────────────────
setup_output_dir() {
    local target="$1"
    local base_dir="${2:-./scan_results}"

    # Sanitise target for use in directory name (replace / and . with _)
    local safe_target
    safe_target="$(echo "$target" | tr '/.' '__')"

    OUTPUT_DIR="${base_dir}/${safe_target}_${TIMESTAMP}"

    if ! mkdir -p "$OUTPUT_DIR"; then
        log_error "Cannot create output directory: $OUTPUT_DIR"
        exit 1
    fi

    log_info "Output directory: ${BOLD}${OUTPUT_DIR}${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN NMAP SCAN
# ─────────────────────────────────────────────────────────────────────────────
# Scan strategy:
#   -sV          : Version detection
#   -sC          : Default scripts (safe, informational)
#   -O           : OS detection  (requires root; skipped gracefully if absent)
#   -p-          : All 65535 ports  ← swap to  -p 1-1024  for a quick scan
#   --open       : Show only open ports (cleaner output)
#   -T4          : Aggressive timing (faster on local nets; reduce to T3 remotely)
#   --reason     : Show why a port is marked open/closed
#   Outputs: normal (-oN), XML (-oX), greppable (-oG)
# ─────────────────────────────────────────────────────────────────────────────
run_nmap_scan() {
    local target="$1"

    log_section "Running nmap Scan"
    log_info "Target  : $target"
    log_info "Strategy: -sV -sC --open -T4 (all ports)"
    log_warn "This may take several minutes for large ranges."

    local raw_txt="${OUTPUT_DIR}/nmap_raw.txt"
    local raw_xml="${OUTPUT_DIR}/nmap_raw.xml"
    local raw_gnmap="${OUTPUT_DIR}/nmap_raw.gnmap"

    # Detect whether we have root/sudo for OS detection
    local os_flag=""
    if [[ $EUID -eq 0 ]]; then
        os_flag="-O"
        log_info "Running as root — OS detection enabled."
    else
        log_warn "Not root — OS detection (-O) skipped."
    fi

    # Build and execute nmap command
    # shellcheck disable=SC2086  # $os_flag must be unquoted to expand correctly
    if ! nmap -sV -sC $os_flag --open -T4 --reason \
              -p- \
              -oN "$raw_txt" \
              -oX "$raw_xml" \
              -oG "$raw_gnmap" \
              "$target" 2>&1 | tee "${OUTPUT_DIR}/nmap_live.log"; then
        log_error "nmap exited with a non-zero status. Check ${OUTPUT_DIR}/nmap_live.log"
        exit 1
    fi

    log_info "nmap scan complete."
    log_info "Raw output saved:"
    log_info "  Normal  → $raw_txt"
    log_info "  XML     → $raw_xml"
    log_info "  Gnmap   → $raw_gnmap"
}

# ─────────────────────────────────────────────────────────────────────────────
# PARSE OPEN PORTS FROM GNMAP (greppable format — most reliable for parsing)
# ─────────────────────────────────────────────────────────────────────────────
# Gnmap open-port lines look like:
#   Host: 192.168.1.1 ()  Ports: 22/open/tcp//ssh//OpenSSH 8.2/, 80/open/tcp//http//nginx 1.18/
# Field layout per port token: port/state/proto//service//version/
# ─────────────────────────────────────────────────────────────────────────────
parse_open_ports() {
    local gnmap_file="${OUTPUT_DIR}/nmap_raw.gnmap"
    local out_file="${OUTPUT_DIR}/open_ports.txt"

    log_section "Parsing Open Ports"

    if [[ ! -f "$gnmap_file" ]]; then
        log_error "Greppable nmap output not found: $gnmap_file"
        exit 1
    fi

    # Write CSV header
    echo "host|port|protocol|state|service|version" > "$out_file"

    local port_count=0

    # Process every "Host:" line that contains open ports
    while IFS= read -r line; do

        # Extract host IP
        local host
        host="$(echo "$line" | grep -oP 'Host:\s+\K[\d\.]+(?=\s)')"
        [[ -z "$host" ]] && continue

        # Extract the Ports: section
        local ports_section
        ports_section="$(echo "$line" | grep -oP 'Ports:\s+\K.+')"
        [[ -z "$ports_section" ]] && continue

        # Split on comma — each token is one port entry
        IFS=',' read -ra port_tokens <<< "$ports_section"

        for token in "${port_tokens[@]}"; do
            token="$(echo "$token" | sed 's/^ *//')"  # trim leading spaces

            # Only keep open ports
            [[ "$token" != *"/open/"* ]] && continue

            # Split token on '/'
            IFS='/' read -ra fields <<< "$token"
            #  fields[0] = port number
            #  fields[1] = state  (open)
            #  fields[2] = protocol  (tcp/udp)
            #  fields[3] = owner  (often empty)
            #  fields[4] = service name
            #  fields[5] = rpc info (often empty)
            #  fields[6] = version string

            local port="${fields[0]:-?}"
            local state="${fields[1]:-?}"
            local proto="${fields[2]:-?}"
            local service="${fields[4]:-unknown}"
            local version="${fields[6]:-}"
            version="$(echo "$version" | sed 's/[[:space:]]*$//')"  # trim trailing

            echo "${host}|${port}|${proto}|${state}|${service}|${version}" >> "$out_file"
            (( port_count++ )) || true
        done

    done < <(grep "^Host:" "$gnmap_file")

    log_info "Parsed ${BOLD}${port_count}${RESET} open port(s) → $out_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# IDENTIFY WEB SERVICES (HTTP/HTTPS) — feed list for nikto / nuclei
# ─────────────────────────────────────────────────────────────────────────────
# Heuristic: flag port as web if:
#   • Service name contains "http"
#   • Port is 80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443
# ─────────────────────────────────────────────────────────────────────────────
identify_web_services() {
    local ports_file="${OUTPUT_DIR}/open_ports.txt"
    local web_file="${OUTPUT_DIR}/web_services.txt"

    log_section "Identifying Web Services"

    local known_web_ports=(80 443 8080 8443 8000 8888 3000 5000 9090 9443)

    # Build a regex from the known-ports array  e.g. ^(80|443|8080|...)$
    local port_regex
    port_regex="^($(IFS='|'; echo "${known_web_ports[*]}"))$"

    echo "# Web service endpoints — input for nikto / nuclei" > "$web_file"
    echo "# Format: scheme://host:port" >> "$web_file"

    local web_count=0

    # Skip header line (line 1)
    while IFS='|' read -r host port proto state service version; do
        [[ "$host" == "host" ]] && continue  # skip CSV header

        local is_web=0

        # Check by service name
        if echo "$service" | grep -qiE 'http|https|ssl/http'; then
            is_web=1
        fi

        # Check by well-known port number
        if [[ "$port" =~ $port_regex ]]; then
            is_web=1
        fi

        if (( is_web )); then
            # Determine scheme
            local scheme="http"
            if echo "$service" | grep -qiE 'https|ssl' || [[ "$port" == "443" || "$port" == "8443" || "$port" == "9443" ]]; then
                scheme="https"
            fi

            local endpoint="${scheme}://${host}:${port}"
            echo "$endpoint" >> "$web_file"
            log_info "  🌐  Web service detected: ${BOLD}${endpoint}${RESET}  (${service} ${version})"
            (( web_count++ )) || true
        fi

    done < "$ports_file"

    if (( web_count == 0 )); then
        log_warn "No web services detected. Nikto / Nuclei stages will be skipped."
    else
        log_info "Found ${BOLD}${web_count}${RESET} web endpoint(s) → $web_file"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE HUMAN-READABLE SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────────────────
generate_summary() {
    local target="$1"
    local summary_file="${OUTPUT_DIR}/scan_summary.txt"

    log_section "Generating Summary Report"

    {
        echo "════════════════════════════════════════════════════════"
        echo "  SECURITY PIPELINE — NMAP SCAN SUMMARY"
        echo "════════════════════════════════════════════════════════"
        echo "  Target      : $target"
        echo "  Scan Time   : $(date)"
        echo "  Output Dir  : $OUTPUT_DIR"
        echo "════════════════════════════════════════════════════════"
        echo ""
        echo "── OPEN PORTS ──────────────────────────────────────────"
        printf "%-18s %-8s %-6s %-20s %s\n" "HOST" "PORT" "PROTO" "SERVICE" "VERSION"
        printf "%-18s %-8s %-6s %-20s %s\n" "────────────────" "──────" "─────" "──────────────────" "───────────"

        # Skip header line
        tail -n +2 "${OUTPUT_DIR}/open_ports.txt" | \
        while IFS='|' read -r host port proto state service version; do
            printf "%-18s %-8s %-6s %-20s %s\n" "$host" "$port" "$proto" "$service" "$version"
        done

        echo ""
        echo "── WEB SERVICES (candidates for nikto / nuclei) ───────"
        if [[ -s "${OUTPUT_DIR}/web_services.txt" ]]; then
            grep -v '^#' "${OUTPUT_DIR}/web_services.txt"
        else
            echo "  (none detected)"
        fi

        echo ""
        echo "── PIPELINE STATUS ─────────────────────────────────────"
        echo "  [✔] Step 1 — nmap scan + parse   COMPLETE"
        echo "  [ ] Step 2 — nikto web scan       PENDING"
        echo "  [ ] Step 3 — nuclei vuln scan     PENDING"
        echo "  [ ] Step 4 — subdomain enum       PENDING"
        echo "════════════════════════════════════════════════════════"
    } | tee "$summary_file"

    log_info "Summary written → $summary_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────
main() {
    # Print banner
    echo -e "${BOLD}${CYAN}"
    echo "  ███████╗███████╗ ██████╗    ██████╗ ██╗██████╗ ███████╗"
    echo "  ██╔════╝██╔════╝██╔════╝    ██╔══██╗██║██╔══██╗██╔════╝"
    echo "  ███████╗█████╗  ██║         ██████╔╝██║██████╔╝█████╗  "
    echo "  ╚════██║██╔══╝  ██║         ██╔═══╝ ██║██╔═══╝ ██╔══╝  "
    echo "  ███████║███████╗╚██████╗    ██║     ██║██║     ███████╗ "
    echo "  ╚══════╝╚══════╝ ╚═════╝    ╚═╝     ╚═╝╚═╝     ╚══════╝"
    echo -e "  Security Pipeline — Step 1: nmap Scanner v${SCRIPT_VERSION}${RESET}"
    echo ""

    # Show help if requested
    [[ "${1:-}" =~ ^(-h|--help)$ ]] && usage

    # Require at least one argument
    if [[ $# -lt 1 ]]; then
        log_error "Missing required argument: <target>"
        usage
    fi

    local target="$1"
    local output_base="${2:-./scan_results}"

    # ── Pipeline stages ──────────────────────────────────────────────────────
    check_dependencies          # 1. Verify all tools are present
    validate_target "$target"   # 2. Sanitise input
    setup_output_dir "$target" "$output_base"  # 3. Prepare output directory
    run_nmap_scan "$target"     # 4. Execute nmap with all output formats
    parse_open_ports            # 5. Parse gnmap → open_ports.txt
    identify_web_services       # 6. Flag HTTP/HTTPS endpoints → web_services.txt
    generate_summary "$target"  # 7. Human-readable summary

    log_section "Step 1 Complete"
    log_info "All files are in: ${BOLD}${OUTPUT_DIR}${RESET}"
    log_info "When ready, confirm to proceed to ${BOLD}Step 2 — Nikto Integration${RESET}."
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry point guard — allows sourcing for unit testing
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
