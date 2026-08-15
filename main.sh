#!/usr/bin/env bash
# =============================================================================
# nmap_scanner.sh — Step 1 of the Security Automation Pipeline
# Purpose : Run a structured nmap scan, save raw output, and parse results
#           into a clean, machine-readable format for downstream tools.
# Author  : Security Pipeline v1.1
# Usage   : ./nmap_scanner.sh <target> [output_dir]
#
# Interactive prompts at startup:
#   1. Pipeline selection  — choose which tools to chain after nmap
#   2. nmap configuration  — port range, timing, and scan options
# =============================================================================

set -euo pipefail   # Exit on error, unset vars, pipe failures
IFS=$'\n\t'         # Safer word splitting

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_VERSION="1.1.0"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Colour codes (disabled automatically if not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE STATE  (populated by interactive menus, consumed by later stages)
# ─────────────────────────────────────────────────────────────────────────────
declare -A PIPELINE_TOOLS=(
    [nikto]=0
    [nuclei]=0
    [ffuf]=0
)

NMAP_FLAGS=()
NMAP_CMD_PREVIEW=""

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
    nikto/               — Per-endpoint nikto scan output (if selected)
    nikto_findings.txt   — Parsed: host|port|finding (if nikto selected)

EOF
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# MENU HELPER  — print a numbered list and return the user's validated choice
# ─────────────────────────────────────────────────────────────────────────────
prompt_menu() {
    local header="$1"; shift
    local options=("$@")
    local choice

    echo -e "\n${BOLD}${CYAN}${header}${RESET}" >&2
    local i=1
    for opt in "${options[@]}"; do
        echo -e "  ${BOLD}[$i]${RESET}  $opt" >&2
        (( i++ )) || true
    done

    while true; do
        printf "${BOLD}  → ${RESET}" >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && \
           (( choice >= 1 && choice <= ${#options[@]} )); then
            echo "${options[$(( choice - 1 ))]}"
            return
        fi
        echo -e "  ${RED}Invalid choice. Enter a number between 1 and ${#options[@]}.${RESET}" >&2
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# FREE-TEXT PROMPT HELPER — validated free-text input with a default value
# ─────────────────────────────────────────────────────────────────────────────
# Usage: prompt_text "Prompt text" "default_value" "^regex_validator$"
# Prints the prompt to stderr, reads from stdin, re-prompts on invalid input,
# returns default_value untouched if the user just presses Enter.
prompt_text() {
    local prompt="$1"
    local default="$2"
    local validator="${3:-.*}"
    local input

    while true; do
        printf "${BOLD}  %s [default: %s]: ${RESET}" "$prompt" "$default" >&2
        read -r input
        [[ -z "$input" ]] && { echo "$default"; return; }
        if [[ "$input" =~ $validator ]]; then
            echo "$input"
            return
        fi
        echo -e "  ${RED}Invalid input. Try again.${RESET}" >&2
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE SELECTION MENU
# ─────────────────────────────────────────────────────────────────────────────
select_pipeline_tools() {
    log_section "Pipeline Configuration"

    echo -e "${BOLD}nmap${RESET} is always the first stage and cannot be deselected."
    echo -e "Select which additional tools to include:\n"

    declare -A TOOL_DESC=(
        [nikto]="nikto   — web server vulnerability scanner (requires web services)"
        [nuclei]="nuclei  — template-based vulnerability scanner (fast, broad coverage)"
        [ffuf]="ffuf    — directory and subdomain fuzzer"
    )

    for tool in nikto nuclei ffuf; do
        local selected
        selected="$(prompt_menu \
            "Include ${BOLD}${tool}${RESET}? — ${TOOL_DESC[$tool]}" \
            "Yes — include in pipeline" \
            "No  — skip this tool")"

        if [[ "$selected" == Yes* ]]; then
            PIPELINE_TOOLS[$tool]=1
            log_info "  ✔  ${tool} added to pipeline"
        else
            PIPELINE_TOOLS[$tool]=0
            log_info "  ✗  ${tool} skipped"
        fi
    done

    echo -e "\n${BOLD}Pipeline plan:${RESET}"
    echo -e "  nmap  ${GREEN}[always]${RESET}"
    for tool in nikto nuclei ffuf; do
        if (( PIPELINE_TOOLS[$tool] )); then
            echo -e "  ${tool}  ${GREEN}[selected]${RESET}"
        else
            echo -e "  ${tool}  ${YELLOW}[skipped]${RESET}"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# NMAP SCAN CONFIGURATION MENU
# ─────────────────────────────────────────────────────────────────────────────
configure_nmap_scan() {
    log_section "nmap Scan Configuration"

    NMAP_FLAGS=()

    local port_choice
    port_choice="$(prompt_menu "Port Range" \
        "Top 1000 (fast, covers most common services)" \
        "All 65535 ports (thorough, slow)" \
        "Common web ports only  (80,443,8080,8443,8000,8888,3000,5000,9090,9443)" \
        "Custom — I will enter the port range")"

    case "$port_choice" in
        "Top 1000"*)
            NMAP_FLAGS+=("--top-ports" "1000")
            ;;
        "All 65535"*)
            NMAP_FLAGS+=("-p-")
            ;;
        "Common web"*)
            NMAP_FLAGS+=("-p" "80,443,8080,8443,8000,8888,3000,5000,9090,9443")
            ;;
        "Custom"*)
            printf "\n  Enter port range (e.g. 1-1024  or  22,80,443  or  1-65535): " >&2
            local custom_ports
            read -r custom_ports
            if [[ ! "$custom_ports" =~ ^[0-9,\-]+$ ]]; then
                log_error "Invalid port range '${custom_ports}'. Defaulting to top 1000."
                NMAP_FLAGS+=("--top-ports" "1000")
            else
                NMAP_FLAGS+=("-p" "$custom_ports")
            fi
            ;;
    esac

    local timing_choice
    timing_choice="$(prompt_menu "Scan Speed / Timing Template" \
        "T1 — Sneaky     (very slow, evades most IDS, long timeouts)" \
        "T2 — Polite     (slow, low bandwidth, minimal noise)" \
        "T3 — Normal     (nmap default, balanced speed and accuracy)" \
        "T4 — Aggressive (fast, assumes reliable LAN, noticeably noisy)" \
        "T5 — Insane     (maximum speed, may miss ports, extremely noisy)")"

    local tnum
    tnum="$(echo "$timing_choice" | grep -oP 'T\K[1-5]')"
    NMAP_FLAGS+=("-T${tnum}")

    local version_choice
    version_choice="$(prompt_menu "Version Detection (-sV)" \
        "Yes — detect service versions (recommended for pipeline accuracy)" \
        "No  — skip version detection (faster, less info for downstream tools)")"

    [[ "$version_choice" == Yes* ]] && NMAP_FLAGS+=("-sV")

    local script_choice
    script_choice="$(prompt_menu "Default Script Scan (-sC)" \
        "Yes — run default safe scripts (banners, headers, basic enumeration)" \
        "No  — skip scripts (faster)")"

    [[ "$script_choice" == Yes* ]] && NMAP_FLAGS+=("-sC")

    if [[ $EUID -eq 0 ]]; then
        local os_choice
        os_choice="$(prompt_menu "OS Detection (-O)  [root detected — available]" \
            "Yes — attempt OS fingerprinting" \
            "No  — skip OS detection")"
        [[ "$os_choice" == Yes* ]] && NMAP_FLAGS+=("-O")
    else
        log_warn "OS detection (-O) requires root — skipped. Re-run with sudo to enable."
    fi

    echo -e "\n${BOLD}  Additional nmap flags${RESET} (leave blank to skip):" >&2
    echo -e "  Examples:  --script vuln   --exclude-ports 9200   --defeat-rst-ratelimit" >&2
    printf "  Extra flags: " >&2
    local extra_flags_raw
    read -r extra_flags_raw

    if [[ -n "$extra_flags_raw" ]]; then
        local saved_ifs="$IFS"
        IFS=' ' read -ra extra_array <<< "$extra_flags_raw"
        IFS="$saved_ifs"
        NMAP_FLAGS+=("${extra_array[@]}")
    fi

    NMAP_FLAGS+=("--open" "--reason")

    local preview_flags
    preview_flags="$(printf '%s ' "${NMAP_FLAGS[@]}")"
    NMAP_CMD_PREVIEW="nmap ${preview_flags}-oN <out>.txt -oX <out>.xml -oG <out>.gnmap <target>"

    echo -e "\n${BOLD}${CYAN}── nmap configuration summary ──────────────────────────${RESET}"
    local pending=""
    local flag
    for flag in "${NMAP_FLAGS[@]}"; do
        if [[ "$flag" == -* ]]; then
            [[ -n "$pending" ]] && echo "  $pending"
            pending="$flag"
        else
            echo "  $pending $flag"
            pending=""
        fi
    done
    [[ -n "$pending" ]] && echo "  $pending"

    echo -e "\n${BOLD}  Full command:${RESET}"
    echo -e "  ${CYAN}${NMAP_CMD_PREVIEW}${RESET}\n"

    local confirm
    confirm="$(prompt_menu "Proceed with this configuration?" \
        "Yes — start the scan" \
        "No  — reconfigure from the start")"

    if [[ "$confirm" == No* ]]; then
        log_info "Re-running configuration..."
        configure_nmap_scan
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# NIKTO SCAN CONFIGURATION MENU  (Step 2)
# ─────────────────────────────────────────────────────────────────────────────
# Populates the NIKTO_* globals consumed by run_nikto_scan().
# Only invoked when PIPELINE_TOOLS[nikto]=1 AND web_services.txt is non-empty.
# ─────────────────────────────────────────────────────────────────────────────
NIKTO_FLAGS=()
NIKTO_FORMAT="txt"
NIKTO_CMD_PREVIEW=""

configure_nikto_scan() {
    log_section "nikto Scan Configuration"

    NIKTO_FLAGS=()

    # ── 1. Tuning (scan scope) ────────────────────────────────────────────────
    # nikto -Tuning restricts which test categories run. Full reference:
    #  1 Interesting File/Seen in logs   2 Misconfiguration/Default File
    #  3 Information Disclosure          4 Injection (XSS/Script/HTML)
    #  5 Remote File Retrieval - Inside  6 Denial of Service
    #  7 Remote File Retrieval - Server  8 Command Execution
    #  9 SQL Injection                   0 File Upload
    #  x Reverse Tuning (exclude the given codes instead of including them)
    local tuning_choice
    tuning_choice="$(prompt_menu "Tuning / Scan Scope" \
        "All tests (default — no -Tuning restriction, most thorough)" \
        "Quick triage — misconfig, info disclosure, default files (2,3)" \
        "Injection focus — XSS, SQLi, command execution (4,8,9)" \
        "Custom — I will enter Nikto tuning codes")"

    case "$tuning_choice" in
        "Quick triage"*)
            NIKTO_FLAGS+=("-Tuning" "2,3")
            ;;
        "Injection focus"*)
            NIKTO_FLAGS+=("-Tuning" "4,8,9")
            ;;
        "Custom"*)
            local custom_tuning
            custom_tuning="$(prompt_text "Enter tuning codes (e.g. 1,2,3 or x6 to exclude DoS)" "" '^[0-9x,]*$')"
            [[ -n "$custom_tuning" ]] && NIKTO_FLAGS+=("-Tuning" "$custom_tuning")
            ;;
        # "All tests" → no flag added
    esac

    # ── 2. Per-host timeout ───────────────────────────────────────────────────
    local timeout_choice
    timeout_choice="$(prompt_menu "Per-request Timeout" \
        "10 seconds (default)" \
        "5 seconds  (faster, may miss slow endpoints)" \
        "30 seconds (patient — for slow/unstable targets)" \
        "Custom — I will enter a value in seconds")"

    case "$timeout_choice" in
        "10 seconds"*) NIKTO_FLAGS+=("-timeout" "10") ;;
        "5 seconds"*)  NIKTO_FLAGS+=("-timeout" "5")  ;;
        "30 seconds"*) NIKTO_FLAGS+=("-timeout" "30") ;;
        "Custom"*)
            local custom_timeout
            custom_timeout="$(prompt_text "Timeout in seconds" "10" '^[0-9]+$')"
            NIKTO_FLAGS+=("-timeout" "$custom_timeout")
            ;;
    esac

    # ── 3. Max scan time per host (-maxtime) ──────────────────────────────────
    local maxtime_choice
    maxtime_choice="$(prompt_menu "Max Scan Time per Host" \
        "No limit (scan runs to completion)" \
        "5 minutes" \
        "15 minutes" \
        "Custom — e.g. 90s, 10m, 1h")"

    case "$maxtime_choice" in
        "5 minutes")  NIKTO_FLAGS+=("-maxtime" "5m")  ;;
        "15 minutes") NIKTO_FLAGS+=("-maxtime" "15m") ;;
        "Custom"*)
            local custom_maxtime
            custom_maxtime="$(prompt_text "Max time (e.g. 90s, 10m, 1h)" "10m" '^[0-9]+[smh]$')"
            NIKTO_FLAGS+=("-maxtime" "$custom_maxtime")
            ;;
        # "No limit" → no flag added
    esac

    # ── 4. Evasion techniques (-evasion) ──────────────────────────────────────
    # 1 Random URI encoding   2 Directory self-reference   3 Premature URL ending
    # 4 Prepend long random string   5 Fake parameter       6 TAB as command separator
    # 7 Change case of URL    8 Use Windows directory separator
    local evasion_choice
    evasion_choice="$(prompt_menu "IDS Evasion (-evasion)" \
        "None (default — cleanest results)" \
        "Light — random URI encoding + case changes (1,7)" \
        "Custom — I will enter evasion codes")"

    case "$evasion_choice" in
        "Light"*) NIKTO_FLAGS+=("-evasion" "1,7") ;;
        "Custom"*)
            local custom_evasion
            custom_evasion="$(prompt_text "Enter evasion codes (1-8)" "" '^[0-9,]*$')"
            [[ -n "$custom_evasion" ]] && NIKTO_FLAGS+=("-evasion" "$custom_evasion")
            ;;
    esac

    # ── 5. SSL certificate errors ─────────────────────────────────────────────
    # Applies automatically per-target below (-ssl passed when scheme=https),
    # this only controls whether to ignore cert validation errors.
    local sslcert_choice
    sslcert_choice="$(prompt_menu "Ignore SSL certificate errors (-nointeractive safe default)" \
        "Yes — ignore cert errors (recommended for internal/self-signed targets)" \
        "No  — validate certificates normally")"

    # ── 6. Output format ──────────────────────────────────────────────────────
    local format_choice
    format_choice="$(prompt_menu "Output Format" \
        "txt  — plain text (default, human-readable)" \
        "html — HTML report" \
        "csv  — comma-separated values" \
        "xml  — XML report (for further tool chaining)")"

    case "$format_choice" in
        txt*)  NIKTO_FORMAT="txt"  ;;
        html*) NIKTO_FORMAT="htm"  ;;
        csv*)  NIKTO_FORMAT="csv"  ;;
        xml*)  NIKTO_FORMAT="xml"  ;;
    esac

    # ── 7. Extra flags (power-user escape hatch) ──────────────────────────────
    echo -e "\n${BOLD}  Additional nikto flags${RESET} (leave blank to skip):" >&2
    echo -e "  Examples:  -Plugins @@ALL   -useragent 'CustomUA/1.0'   -no404" >&2
    printf "  Extra flags: " >&2
    local extra_flags_raw
    read -r extra_flags_raw

    if [[ -n "$extra_flags_raw" ]]; then
        local saved_ifs="$IFS"
        IFS=' ' read -ra extra_array <<< "$extra_flags_raw"
        IFS="$saved_ifs"
        NIKTO_FLAGS+=("${extra_array[@]}")
    fi

    # ── Always-on flags (not user-configurable) ───────────────────────────────
    # -ask no  : never pause for interactive per-item prompts during the scan
    # -nointeractive is deprecated in newer nikto — "-ask no" is the modern flag
    NIKTO_FLAGS+=("-ask" "no")

    # Store the cert-ignore choice for use in run_nikto_scan (per-target -ssl handling)
    NIKTO_IGNORE_CERT=0
    [[ "$sslcert_choice" == Yes* ]] && NIKTO_IGNORE_CERT=1

    # ── Configuration summary ─────────────────────────────────────────────────
    NIKTO_CMD_PREVIEW="nikto -h <host> -p <port> $(printf '%s ' "${NIKTO_FLAGS[@]}")-Format ${NIKTO_FORMAT} -o <out>.${NIKTO_FORMAT}"

    echo -e "\n${BOLD}${CYAN}── nikto configuration summary ─────────────────────────${RESET}"
    local pending=""
    local flag
    for flag in "${NIKTO_FLAGS[@]}"; do
        if [[ "$flag" == -* ]]; then
            [[ -n "$pending" ]] && echo "  $pending"
            pending="$flag"
        else
            echo "  $pending $flag"
            pending=""
        fi
    done
    [[ -n "$pending" ]] && echo "  $pending"
    echo "  Output format: $NIKTO_FORMAT"
    echo "  Ignore SSL cert errors: $(( NIKTO_IGNORE_CERT )) (1=yes, 0=no)"

    echo -e "\n${BOLD}  Full command (per endpoint):${RESET}"
    echo -e "  ${CYAN}${NIKTO_CMD_PREVIEW}${RESET}\n"

    local confirm
    confirm="$(prompt_menu "Proceed with this nikto configuration?" \
        "Yes — use this configuration" \
        "No  — reconfigure from the start")"

    if [[ "$confirm" == No* ]]; then
        log_info "Re-running nikto configuration..."
        configure_nikto_scan
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_dependencies() {
    local missing=0

    local required_tools=("nmap" "grep" "awk" "sed" "cut")

    local tool
    for tool in nikto nuclei ffuf; do
        if (( PIPELINE_TOOLS[$tool] )); then
            required_tools+=("$tool")
        fi
    done

    local optional_tools=("xmllint")

    log_section "Dependency Check"

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_info "  ✔  $tool  ($(command -v "$tool"))"
        else
            log_error "  ✘  $tool  — REQUIRED but not found"
            (( missing++ )) || true
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_info "  ✔  $tool  (optional)"
        else
            log_warn "  ✘  $tool  — optional, not found (XML pretty-print unavailable)"
        fi
    done

    if (( missing > 0 )); then
        log_error "${missing} required tool(s) missing. Aborting."
        log_error "Install missing tools via:  sudo apt install <tool>  |  brew install <tool>"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
validate_target() {
    local target="$1"

    if [[ -z "$target" ]]; then
        log_error "No target specified."
        usage
    fi

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
run_nmap_scan() {
    local target="$1"

    log_section "Running nmap Scan"
    log_info "Target  : $target"
    log_info "Command : nmap ${NMAP_FLAGS[*]} ... $target"
    log_warn "Scan is running — duration depends on port range and timing template."

    local raw_txt="${OUTPUT_DIR}/nmap_raw.txt"
    local raw_xml="${OUTPUT_DIR}/nmap_raw.xml"
    local raw_gnmap="${OUTPUT_DIR}/nmap_raw.gnmap"

    if ! nmap "${NMAP_FLAGS[@]}" \
            -oN "$raw_txt" \
            -oX "$raw_xml" \
            -oG "$raw_gnmap" \
            "$target" 2>&1 | tee "${OUTPUT_DIR}/nmap_live.log"; then
        log_error "nmap exited with a non-zero status. Check ${OUTPUT_DIR}/nmap_live.log"
        exit 1
    fi

    log_info "nmap scan complete."
    log_info "  Normal  → $raw_txt"
    log_info "  XML     → $raw_xml"
    log_info "  Gnmap   → $raw_gnmap"
}

# ─────────────────────────────────────────────────────────────────────────────
# PARSE OPEN PORTS FROM GNMAP
# ─────────────────────────────────────────────────────────────────────────────
parse_open_ports() {
    local gnmap_file="${OUTPUT_DIR}/nmap_raw.gnmap"
    local out_file="${OUTPUT_DIR}/open_ports.txt"

    log_section "Parsing Open Ports"

    if [[ ! -f "$gnmap_file" ]]; then
        log_error "Greppable nmap output not found: $gnmap_file"
        exit 1
    fi

    echo "host|port|protocol|state|service|version" > "$out_file"

    local port_count=0

    while IFS= read -r line; do

        local host
        host="$(echo "$line" | grep -oP 'Host:\s+\K[\d\.]+(?=\s)' || true)"
        [[ -z "$host" ]] && continue

        local ports_section
        ports_section="$(echo "$line" | grep -oP 'Ports:\s+\K.+' || true)"
        [[ -z "$ports_section" ]] && continue

        ports_section="$(echo "$ports_section" | sed 's/[[:space:]]*Ignored State:.*$//')"

        IFS=',' read -ra port_tokens <<< "$ports_section"

        for token in "${port_tokens[@]}"; do
            token="$(echo "$token" | sed 's/^ *//')"

            [[ "$token" != *"/open/"* ]] && continue

            IFS='/' read -ra fields <<< "$token"

            local port="${fields[0]:-?}"
            local state="${fields[1]:-?}"
            local proto="${fields[2]:-?}"
            local service="${fields[4]:-unknown}"
            local version="${fields[6]:-}"
            version="$(echo "$version" | sed 's/[[:space:]]*$//')"

            echo "${host}|${port}|${proto}|${state}|${service}|${version}" >> "$out_file"
            (( port_count++ )) || true
        done

    done < <(grep "^Host:" "$gnmap_file")

    log_info "Parsed ${BOLD}${port_count}${RESET} open port(s) → $out_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# IDENTIFY WEB SERVICES (HTTP/HTTPS) — feed list for nikto / nuclei
# ─────────────────────────────────────────────────────────────────────────────
identify_web_services() {
    local ports_file="${OUTPUT_DIR}/open_ports.txt"
    local web_file="${OUTPUT_DIR}/web_services.txt"

    log_section "Identifying Web Services"

    local known_web_ports=(80 443 8080 8443 8000 8888 3000 5000 9090 9443)

    local port_regex
    port_regex="^($(IFS='|'; echo "${known_web_ports[*]}"))$"

    echo "# Web service endpoints — input for nikto / nuclei" > "$web_file"
    echo "# Format: scheme://host:port" >> "$web_file"

    local web_count=0

    while IFS='|' read -r host port proto state service version; do
        [[ "$host" == "host" ]] && continue

        local is_web=0

        if echo "$service" | grep -qiE 'http|webdav|ssl'; then
            is_web=1
        fi

        if [[ "$port" =~ $port_regex ]]; then
            is_web=1
        fi

        if (( is_web )); then
            local scheme="http"
            if echo "$service" | grep -qiE 'ssl' || \
               [[ "$port" == "443" || "$port" == "8443" || "$port" == "9443" ]]; then
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
# RUN NIKTO SCAN  (Step 2)
# ─────────────────────────────────────────────────────────────────────────────
# Iterates web_services.txt (produced by identify_web_services) and runs one
# nikto scan per endpoint. Skips cleanly — with a clear log message — if the
# nikto stage was not selected, or if no web services were found.
#
# Per-endpoint outputs go to: ${OUTPUT_DIR}/nikto/<host>_<port>.<format>
# A live log of each run is tee'd to:    ${OUTPUT_DIR}/nikto/<host>_<port>.log
# ─────────────────────────────────────────────────────────────────────────────
run_nikto_scan() {
    local web_file="${OUTPUT_DIR}/web_services.txt"
    local nikto_dir="${OUTPUT_DIR}/nikto"

    log_section "Running nikto Scan"

    if (( ! PIPELINE_TOOLS[nikto] )); then
        log_info "nikto was not selected for this pipeline — skipping."
        return 0
    fi

    if [[ ! -s "$web_file" ]] || ! grep -qv '^#' "$web_file"; then
        log_warn "No web services found in $web_file — nothing for nikto to scan."
        return 0
    fi

    mkdir -p "$nikto_dir"

    local endpoint_count=0
    local scan_failures=0

    # grep -v '^#' strips the two header/comment lines written by
    # identify_web_services, leaving one scheme://host:port endpoint per line.
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue

        # endpoint looks like: https://192.168.1.10:8443
        local scheme host port
        scheme="$(echo "$endpoint" | grep -oP '^\K[a-z]+(?=://)')"
        host="$(echo "$endpoint" | grep -oP '(?<=://)[^:]+')"
        port="$(echo "$endpoint" | grep -oP ':\K[0-9]+$')"

        if [[ -z "$host" || -z "$port" ]]; then
            log_warn "  Could not parse endpoint '$endpoint' — skipping."
            continue
        fi

        (( endpoint_count++ )) || true

        local out_base="${nikto_dir}/${host}_${port}"
        local out_file="${out_base}.${NIKTO_FORMAT}"
        local log_file="${out_base}.log"

        # Build the per-target flag set: base NIKTO_FLAGS plus -ssl when the
        # endpoint is https, plus -nossl-ignore-cert if the user opted to
        # ignore certificate validation errors.
        local target_flags=("${NIKTO_FLAGS[@]}")
        [[ "$scheme" == "https" ]] && target_flags+=("-ssl")
        (( NIKTO_IGNORE_CERT )) && target_flags+=("-nointeractive")

        log_info "  🔎  Scanning ${BOLD}${endpoint}${RESET} → $out_file"

        # || true: a single failed/target-unreachable nikto run must not abort
        # the whole pipeline stage — we log it and move to the next endpoint.
        if ! nikto -h "$host" -p "$port" "${target_flags[@]}" \
                -Format "$NIKTO_FORMAT" -o "$out_file" \
                2>&1 | tee "$log_file"; then
            log_warn "  nikto run against ${endpoint} reported a non-zero exit — see $log_file"
            (( scan_failures++ )) || true
        fi

    done < <(grep -v '^#' "$web_file")

    log_info "nikto stage complete: ${BOLD}${endpoint_count}${RESET} endpoint(s) scanned, ${scan_failures} failure(s)."
    log_info "Raw reports → $nikto_dir/"
}

# ─────────────────────────────────────────────────────────────────────────────
# PARSE NIKTO FINDINGS  (Step 2)
# ─────────────────────────────────────────────────────────────────────────────
# Nikto's plain-text (-Format txt) report lines look like:
#   + Server: nginx/1.18.0
#   + /admin/: Admin login page/section found.
#   + OSVDB-3092: /login.php: This might be interesting.
#
# Every finding line starts with "+ ". We only parse the "txt" format files
# here since it's a stable, greppable structure — html/csv/xml reports are
# still saved to disk for manual review but are not auto-parsed in this step.
# ─────────────────────────────────────────────────────────────────────────────
parse_nikto_findings() {
    local nikto_dir="${OUTPUT_DIR}/nikto"
    local out_file="${OUTPUT_DIR}/nikto_findings.txt"

    log_section "Parsing nikto Findings"

    if (( ! PIPELINE_TOOLS[nikto] )); then
        log_info "nikto was not selected — nothing to parse."
        return 0
    fi

    if [[ "$NIKTO_FORMAT" != "txt" ]]; then
        log_warn "Output format is '${NIKTO_FORMAT}', not 'txt' — skipping automated parsing."
        log_warn "Review raw reports manually in $nikto_dir/"
        return 0
    fi

    if [[ ! -d "$nikto_dir" ]] || [[ -z "$(ls -A "$nikto_dir" 2>/dev/null)" ]]; then
        log_warn "No nikto output directory/files found — skipping parse."
        return 0
    fi

    echo "host|port|finding" > "$out_file"

    local finding_count=0
    local report_file
    for report_file in "$nikto_dir"/*.txt; do
        [[ -f "$report_file" ]] || continue

        # Filename convention set in run_nikto_scan: <host>_<port>.txt
        local base host port
        base="$(basename "$report_file" .txt)"
        host="${base%_*}"
        port="${base##*_}"

        while IFS= read -r line; do
            # Finding lines start with "+ " and are not the banner/meta lines
            [[ "$line" == +\ * ]] || continue
            [[ "$line" == *"Target IP:"* || "$line" == *"Target Hostname:"* || \
               "$line" == *"Target Port:"* || "$line" == *"Start Time:"* || \
               "$line" == *"End Time:"* || "$line" == *"requests:"*"item(s) reported"* ]] && continue

            local finding
            finding="${line#+ }"
            # Pipe-delimited output — escape any literal '|' in the finding text
            finding="${finding//|/;}"

            echo "${host}|${port}|${finding}" >> "$out_file"
            (( finding_count++ )) || true
        done < "$report_file"
    done

    log_info "Parsed ${BOLD}${finding_count}${RESET} finding(s) → $out_file"
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
        echo "  SECURITY PIPELINE — SCAN SUMMARY"
        echo "════════════════════════════════════════════════════════"
        echo "  Target      : $target"
        echo "  Scan Time   : $(date)"
        echo "  Output Dir  : $OUTPUT_DIR"
        echo "════════════════════════════════════════════════════════"
        echo ""
        echo "── OPEN PORTS ──────────────────────────────────────────"
        printf "%-18s %-8s %-6s %-20s %s\n" "HOST" "PORT" "PROTO" "SERVICE" "VERSION"
        printf "%-18s %-8s %-6s %-20s %s\n" "────────────────" "──────" "─────" "──────────────────" "───────────"

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

        if (( PIPELINE_TOOLS[nikto] )); then
            echo ""
            echo "── NIKTO FINDINGS ──────────────────────────────────────"
            if [[ -s "${OUTPUT_DIR}/nikto_findings.txt" ]]; then
                local nikto_finding_total
                nikto_finding_total="$(tail -n +2 "${OUTPUT_DIR}/nikto_findings.txt" | wc -l | tr -d ' ')"
                echo "  Total findings: ${nikto_finding_total}"
                echo ""
                printf "%-18s %-6s %s\n" "HOST" "PORT" "FINDING"
                printf "%-18s %-6s %s\n" "────────────────" "─────" "───────────────────────────"
                tail -n +2 "${OUTPUT_DIR}/nikto_findings.txt" | \
                while IFS='|' read -r host port finding; do
                    printf "%-18s %-6s %s\n" "$host" "$port" "$finding"
                done
            else
                echo "  (no parsed findings — check ${OUTPUT_DIR}/nikto/ for raw reports)"
            fi
        fi

        echo ""
        echo "── PIPELINE STATUS ─────────────────────────────────────"
        echo "  [✔] nmap    — scan + parse        COMPLETE"
        if (( PIPELINE_TOOLS[nikto] )); then
            echo "  [✔] nikto   — vuln scan + parse   COMPLETE"
        else
            echo "  [-] nikto   — skipped (not selected)"
        fi
        for _tool in nuclei ffuf; do
            if (( PIPELINE_TOOLS[$_tool] )); then
                printf "  [ ] %-7s — pending\n" "$_tool"
            else
                printf "  [-] %-7s — skipped (not selected)\n" "$_tool"
            fi
        done
        echo "════════════════════════════════════════════════════════"
    } | tee "$summary_file"

    log_info "Summary written → $summary_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────
main() {
    echo -e "${BOLD}${CYAN}"
    echo "  ███████╗███████╗ ██████╗    ██████╗ ██╗██████╗ ███████╗"
    echo "  ██╔════╝██╔════╝██╔════╝    ██╔══██╗██║██╔══██╗██╔════╝"
    echo "  ███████╗█████╗  ██║         ██████╔╝██║██████╔╝█████╗  "
    echo "  ╚════██║██╔══╝  ██║         ██╔═══╝ ██║██╔═══╝ ██╔══╝  "
    echo "  ███████║███████╗╚██████╗    ██║     ██║██║     ███████╗ "
    echo "  ╚══════╝╚══════╝ ╚═════╝    ╚═╝     ╚═╝╚═╝     ╚══════╝"
    echo -e "  Security Pipeline — nmap + nikto v${SCRIPT_VERSION}${RESET}"
    echo ""

    [[ "${1:-}" =~ ^(-h|--help)$ ]] && usage

    if [[ $# -lt 1 ]]; then
        log_error "Missing required argument: <target>"
        usage
    fi

    local target="$1"
    local output_base="${2:-./scan_results}"

    # ── Interactive configuration (runs before any scanning) ─────────────────
    select_pipeline_tools       # 1. Ask which tools to chain
    configure_nmap_scan         # 2. Ask how to run nmap
    if (( PIPELINE_TOOLS[nikto] )); then
        configure_nikto_scan    # 2b. Ask how to run nikto (only if selected)
    fi

    # ── Validation & setup ───────────────────────────────────────────────────
    check_dependencies
    validate_target "$target"
    setup_output_dir "$target" "$output_base"

    # ── Scanning & parsing ───────────────────────────────────────────────────
    run_nmap_scan "$target"
    parse_open_ports
    identify_web_services
    run_nikto_scan              # Step 2: skips internally if not selected / no web services
    parse_nikto_findings
    generate_summary "$target"

    log_section "Pipeline Stage(s) Complete"
    log_info "All files are in: ${BOLD}${OUTPUT_DIR}${RESET}"

    local next_steps=()
    (( PIPELINE_TOOLS[nuclei] )) && next_steps+=("nuclei")
    (( PIPELINE_TOOLS[ffuf]   )) && next_steps+=("ffuf")

    if (( ${#next_steps[@]} > 0 )); then
        log_info "Next stages queued: ${BOLD}${next_steps[*]}${RESET}"
        log_info "Confirm to proceed to Step 3 — Nuclei Integration."
    else
        log_warn "No further tools were selected. Pipeline complete."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry point guard — allows sourcing for unit testing
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
