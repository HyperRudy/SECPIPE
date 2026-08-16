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
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
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
    nuclei/               — nuclei target list + raw JSONL output (if selected)
    nuclei_findings.txt   — Parsed: severity|template-id|host|matched-at|name (if nuclei selected)
    ffuf/                 — Per-endpoint ffuf JSON output (if selected)
    ffuf_findings.txt      — Parsed: host|port|path|status|length|words|url (if ffuf selected)
    ffuf_notable.txt        — High-signal subset: config/secret/admin/backup-style paths (if ffuf selected)

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
# NUCLEI SCAN CONFIGURATION MENU  (Step 3)
# ─────────────────────────────────────────────────────────────────────────────
# Populates the NUCLEI_* globals consumed by run_nuclei_scan().
# Only invoked when PIPELINE_TOOLS[nuclei]=1 AND web_services.txt is non-empty.
# nuclei is invoked once against a target LIST (-l) rather than per-endpoint —
# it has its own internal concurrency, so looping per-host would fight that.
# ─────────────────────────────────────────────────────────────────────────────
NUCLEI_FLAGS=()
NUCLEI_CMD_PREVIEW=""

configure_nuclei_scan() {
    log_section "nuclei Scan Configuration"

    NUCLEI_FLAGS=()

    # ── 1. Severity filter ────────────────────────────────────────────────────
    local severity_choice
    severity_choice="$(prompt_menu "Severity Filter (-severity)" \
        "All severities (default — no filter, most thorough)" \
        "Medium and above (medium,high,critical — reduce noise)" \
        "High and above (high,critical — high-signal only)" \
        "Custom — I will enter severity levels")"

    case "$severity_choice" in
        "Medium and above"*) NUCLEI_FLAGS+=("-severity" "medium,high,critical") ;;
        "High and above"*)   NUCLEI_FLAGS+=("-severity" "high,critical") ;;
        "Custom"*)
            local custom_sev
            custom_sev="$(prompt_text "Enter severities (info,low,medium,high,critical)" "" '^[a-z,]*$')"
            [[ -n "$custom_sev" ]] && NUCLEI_FLAGS+=("-severity" "$custom_sev")
            ;;
    esac

    # ── 2. Template selection ─────────────────────────────────────────────────
    local template_choice
    template_choice="$(prompt_menu "Template Selection" \
        "Full default set (all installed templates — most thorough, slowest)" \
        "CVEs only (-tags cve)" \
        "Exposures & misconfig (-tags exposure,misconfig,default-login)" \
        "Custom — I will enter template tags")"

    case "$template_choice" in
        "CVEs only"*) NUCLEI_FLAGS+=("-tags" "cve") ;;
        "Exposures"*) NUCLEI_FLAGS+=("-tags" "exposure,misconfig,default-login") ;;
        "Custom"*)
            local custom_tags
            custom_tags="$(prompt_text "Enter template tags (comma-separated)" "" '^[a-zA-Z0-9,_-]*$')"
            [[ -n "$custom_tags" ]] && NUCLEI_FLAGS+=("-tags" "$custom_tags")
            ;;
    esac

    # ── 3. Rate limiting (requests per second) ────────────────────────────────
    local rate_choice
    rate_choice="$(prompt_menu "Rate Limit (-rate-limit, requests/sec)" \
        "150 (nuclei default — balanced)" \
        "50  (polite — reduce load on target)" \
        "500 (aggressive — fast, noisy)" \
        "Custom — I will enter a value")"

    case "$rate_choice" in
        "150"*) : ;;
        "50"*)  NUCLEI_FLAGS+=("-rate-limit" "50")  ;;
        "500"*) NUCLEI_FLAGS+=("-rate-limit" "500") ;;
        "Custom"*)
            local custom_rate
            custom_rate="$(prompt_text "Requests per second" "150" '^[0-9]+$')"
            NUCLEI_FLAGS+=("-rate-limit" "$custom_rate")
            ;;
    esac

    # ── 4. Concurrency (parallel templates executed) ──────────────────────────
    local concurrency_choice
    concurrency_choice="$(prompt_menu "Template Concurrency (-c)" \
        "25 (nuclei default)" \
        "10 (lower resource usage)" \
        "Custom — I will enter a value")"

    case "$concurrency_choice" in
        "25"*) : ;;
        "10"*) NUCLEI_FLAGS+=("-c" "10") ;;
        "Custom"*)
            local custom_c
            custom_c="$(prompt_text "Concurrency" "25" '^[0-9]+$')"
            NUCLEI_FLAGS+=("-c" "$custom_c")
            ;;
    esac

    # ── 5. Request timeout ────────────────────────────────────────────────────
    local timeout_choice
    timeout_choice="$(prompt_menu "Per-request Timeout (-timeout, seconds)" \
        "10 seconds (default)" \
        "5 seconds  (faster, may miss slow endpoints)" \
        "Custom — I will enter a value")"

    case "$timeout_choice" in
        "10 seconds"*) : ;;
        "5 seconds"*)  NUCLEI_FLAGS+=("-timeout" "5") ;;
        "Custom"*)
            local custom_timeout
            custom_timeout="$(prompt_text "Timeout in seconds" "10" '^[0-9]+$')"
            NUCLEI_FLAGS+=("-timeout" "$custom_timeout")
            ;;
    esac

    # ── 6. Extra flags (power-user escape hatch) ──────────────────────────────
    echo -e "\n${BOLD}  Additional nuclei flags${RESET} (leave blank to skip):" >&2
    echo -e "  Examples:  -exclude-tags dos   -H 'Authorization: Bearer xyz'   -etags intrusive" >&2
    printf "  Extra flags: " >&2
    local extra_flags_raw
    read -r extra_flags_raw

    if [[ -n "$extra_flags_raw" ]]; then
        local saved_ifs="$IFS"
        IFS=' ' read -ra extra_array <<< "$extra_flags_raw"
        IFS="$saved_ifs"
        NUCLEI_FLAGS+=("${extra_array[@]}")
    fi

    # ── Always-on flags (not user-configurable) ───────────────────────────────
    # -jsonl    : one JSON object per finding, per line — reliable to parse
    #             with jq/grep and stable across nuclei template updates,
    #             unlike the human-readable default output.
    # -no-color : keep output clean when writing to the -o file/log.
    #
    # NOTE: -silent is deliberately NOT forced on. With -silent, nuclei prints
    # absolutely nothing when zero templates match — no banner, no template
    # counts, no confirmation the scan even ran. That makes an empty log
    # indistinguishable from a broken run. Without -silent we still get
    # nuclei's startup stats (templates loaded, targets, etc.) even on a
    # clean/non-vulnerable host, which is the same "always emit something"
    # guarantee nikto gives us via its banner lines.
    NUCLEI_FLAGS+=("-jsonl" "-no-color")

    # ── Configuration summary ─────────────────────────────────────────────────
    NUCLEI_CMD_PREVIEW="nuclei -l <targets>.txt $(printf '%s ' "${NUCLEI_FLAGS[@]}")-o <out>.jsonl"

    echo -e "\n${BOLD}${CYAN}── nuclei configuration summary ────────────────────────${RESET}"
    local pending=""
    local flag
    for flag in "${NUCLEI_FLAGS[@]}"; do
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
    echo -e "  ${CYAN}${NUCLEI_CMD_PREVIEW}${RESET}\n"

    local confirm
    confirm="$(prompt_menu "Proceed with this nuclei configuration?" \
        "Yes — use this configuration" \
        "No  — reconfigure from the start")"

    if [[ "$confirm" == No* ]]; then
        log_info "Re-running nuclei configuration..."
        configure_nuclei_scan
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# FFUF SCAN CONFIGURATION MENU  (Step 4)
# ─────────────────────────────────────────────────────────────────────────────
# Populates the FFUF_* globals consumed by run_ffuf_scan().
# ffuf runs once PER endpoint (like nikto) since -u target/FUZZ is inherently
# single-target — there's no equivalent of nuclei's -l batch mode.
#
# BEST-PRACTICE DEFAULTS BAKED IN (not user-togglable, chosen deliberately):
#   -ic         : ignore commented lines in the wordlist (wordlists routinely
#                 ship with "# comment" header lines that would otherwise be
#                 fuzzed as literal paths)
#   -of json    : structured, parseable output — same rationale as nuclei's
#                 -jsonl and nikto's txt format
#   -se         : stop on spurious errors (too many timeouts/connection resets
#                 in a row) rather than hammering a dead/rate-limiting target
#                 for the full wordlist
# Auto-calibration (-ac) is the single highest-value ffuf flag for cutting
# false positives from "soft 404" pages (servers that return 200 for every
# path with a generic error page) — offered as a strongly-recommended default
# in the menu rather than hard-forced, since a few targets behave oddly with
# it and a user may want to disable it deliberately.
# ─────────────────────────────────────────────────────────────────────────────
FFUF_FLAGS=()
FFUF_WORDLIST=""
FFUF_WORDLIST_IS_TEMP=0
FFUF_CMD_PREVIEW=""

# Candidate wordlist paths, checked in priority order (most curated/signal-
# dense first). These are the standard install locations for dirb/SecLists
# on Kali, Debian/Ubuntu security-tools images, and common manual installs.
_FFUF_WORDLIST_CANDIDATES=(
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/dirb/wordlists/common.txt"
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
)

# Small curated fallback list used ONLY if none of the above are found on
# disk. This is intentionally short and high-signal (config/backup/admin/
# VCS artifacts) rather than a broad brute-force list, so a scan can still
# proceed usefully with zero external dependencies.
_ffuf_write_fallback_wordlist() {
    local dest="$1"
    cat > "$dest" <<'WORDS'
robots.txt
sitemap.xml
.env
.env.local
.env.production
.git/config
.git/HEAD
.gitignore
.svn/entries
.htaccess
.htpasswd
web.config
config.php
config.php.bak
configuration.php
wp-config.php
wp-config.php.bak
wp-login.php
wp-admin
wp-admin/
wp-content
xmlrpc.php
admin
admin/
admin.php
administrator
login
login.php
phpinfo.php
info.php
test.php
server-status
server-info
.well-known/security.txt
backup
backup.zip
backup.tar.gz
backup.sql
database.sql
dump.sql
docker-compose.yml
docker-compose.yaml
Dockerfile
.DS_Store
id_rsa
id_rsa.pub
swagger.json
swagger-ui.html
api-docs
api/v1
api/v2
graphql
actuator
actuator/health
debug
console
.idea
.vscode
composer.json
package.json
readme.html
README.md
CHANGELOG.md
LICENSE
license.txt
crossdomain.xml
WORDS
}

configure_ffuf_scan() {
    log_section "ffuf Scan Configuration"

    FFUF_FLAGS=()
    FFUF_WORDLIST_IS_TEMP=0

    # ── 1. Wordlist selection ─────────────────────────────────────────────────
    local wordlist_choice
    wordlist_choice="$(prompt_menu "Wordlist" \
        "Auto-detect (recommended — uses dirb/SecLists common.txt if installed)" \
        "Custom — I will enter a path to a wordlist file")"

    if [[ "$wordlist_choice" == Auto* ]]; then
        FFUF_WORDLIST=""
        local candidate
        for candidate in "${_FFUF_WORDLIST_CANDIDATES[@]}"; do
            if [[ -f "$candidate" ]]; then
                FFUF_WORDLIST="$candidate"
                break
            fi
        done

        if [[ -z "$FFUF_WORDLIST" ]]; then
            log_warn "No standard wordlist found on disk (checked dirb/SecLists paths)."
            log_warn "Falling back to a small built-in curated list (~70 high-signal paths)."
            FFUF_WORDLIST="$(mktemp /tmp/ffuf_fallback_wordlist.XXXXXX.txt)"
            FFUF_WORDLIST_IS_TEMP=1
            _ffuf_write_fallback_wordlist "$FFUF_WORDLIST"
            log_info "For broader coverage, install SecLists:  sudo apt install seclists"
        else
            log_info "Using wordlist: ${BOLD}${FFUF_WORDLIST}${RESET}"
        fi
    else
        # Manual validated loop — prompt_text's regex validator isn't a good
        # fit for "does this file exist", so we loop explicitly here.
        while true; do
            printf "${BOLD}  Enter wordlist path: ${RESET}" >&2
            read -r FFUF_WORDLIST
            if [[ -f "$FFUF_WORDLIST" ]]; then
                break
            fi
            echo -e "  ${RED}File not found: ${FFUF_WORDLIST}${RESET}" >&2
        done
    fi

    local wc_lines
    wc_lines="$(wc -l < "$FFUF_WORDLIST" | tr -d ' ')"
    log_info "Wordlist size: ${BOLD}${wc_lines}${RESET} lines"

    # ── 2. Extensions to append per-word (-e) ─────────────────────────────────
    local ext_choice
    ext_choice="$(prompt_menu "File Extensions to Append (-e)" \
        "None (default — fuzz wordlist entries as-is)" \
        "Common web (.php,.html,.txt,.js,.json,.bak,.zip,.old)" \
        "Custom — I will enter extensions")"

    case "$ext_choice" in
        "Common web"*) FFUF_FLAGS+=("-e" ".php,.html,.txt,.js,.json,.bak,.zip,.old") ;;
        "Custom"*)
            local custom_ext
            custom_ext="$(prompt_text "Enter extensions, comma-separated (e.g. .php,.asp)" "" '^[a-zA-Z0-9,.]*$')"
            [[ -n "$custom_ext" ]] && FFUF_FLAGS+=("-e" "$custom_ext")
            ;;
    esac

    # ── 3. Match status codes (-mc) ───────────────────────────────────────────
    # Default excludes bare 404s (the whole point of fuzzing) but deliberately
    # KEEPS 401/403 — a path that exists but is access-controlled is one of
    # the most useful signals ffuf can surface (see identify_notable_ffuf_
    # findings below).
    local mc_choice
    mc_choice="$(prompt_menu "Match Status Codes (-mc)" \
        "Recommended: 200,204,301,302,307,401,403" \
        "Success only: 200,204" \
        "Everything except 404: all except 404" \
        "Custom — I will enter status codes")"

    case "$mc_choice" in
        "Recommended"*) FFUF_FLAGS+=("-mc" "200,204,301,302,307,401,403") ;;
        "Success only"*) FFUF_FLAGS+=("-mc" "200,204") ;;
        "Everything except 404"*) FFUF_FLAGS+=("-mc" "all"); FFUF_FLAGS+=("-fc" "404") ;;
        "Custom"*)
            local custom_mc
            custom_mc="$(prompt_text "Status codes, comma-separated" "200,204,301,302,307,401,403" '^[0-9,]+$')"
            FFUF_FLAGS+=("-mc" "$custom_mc")
            ;;
    esac

    # ── 4. Auto-calibration (-ac) — strongly recommended ──────────────────────
    local ac_choice
    ac_choice="$(prompt_menu "Auto-Calibration (-ac)  [STRONGLY RECOMMENDED]" \
        "Yes — auto-detect and filter soft-404/false-positive responses" \
        "No  — disable (use only if a target behaves oddly with calibration)")"

    [[ "$ac_choice" == Yes* ]] && FFUF_FLAGS+=("-ac")

    # ── 5. Threads (-t) ───────────────────────────────────────────────────────
    local threads_choice
    threads_choice="$(prompt_menu "Threads (-t)" \
        "40  (default — balanced)" \
        "10  (polite — low load on target)" \
        "100 (aggressive — fast, noisy)" \
        "Custom — I will enter a value")"

    case "$threads_choice" in
        "40 "*)  FFUF_FLAGS+=("-t" "40")  ;;
        "10 "*)  FFUF_FLAGS+=("-t" "10")  ;;
        "100"*)  FFUF_FLAGS+=("-t" "100") ;;
        "Custom"*)
            local custom_threads
            custom_threads="$(prompt_text "Thread count" "40" '^[0-9]+$')"
            FFUF_FLAGS+=("-t" "$custom_threads")
            ;;
    esac

    # ── 6. Rate limit (-rate, requests/sec — 0 = unlimited) ───────────────────
    local rate_choice
    rate_choice="$(prompt_menu "Rate Limit (-rate, req/sec)" \
        "Unlimited (default — bounded only by -t threads)" \
        "50  (polite)" \
        "Custom — I will enter a value")"

    case "$rate_choice" in
        "50 "*) FFUF_FLAGS+=("-rate" "50") ;;
        "Custom"*)
            local custom_rate
            custom_rate="$(prompt_text "Requests per second" "0" '^[0-9]+$')"
            [[ "$custom_rate" != "0" ]] && FFUF_FLAGS+=("-rate" "$custom_rate")
            ;;
    esac

    # ── 7. Recursion ──────────────────────────────────────────────────────────
    # Off by default: recursion can blow up scan scope enormously (every hit
    # directory gets re-fuzzed with the full wordlist), which is often not
    # what's wanted on a first pass.
    local recursion_choice
    recursion_choice="$(prompt_menu "Recursion (-recursion) — fuzz discovered directories too" \
        "No  — single-level scan (default, predictable runtime)" \
        "Yes — recurse into discovered directories (depth 1)" \
        "Yes — recurse with custom depth")"

    case "$recursion_choice" in
        "Yes — recurse into"*)
            FFUF_FLAGS+=("-recursion" "-recursion-depth" "1")
            ;;
        "Yes — recurse with custom"*)
            local custom_depth
            custom_depth="$(prompt_text "Recursion depth" "2" '^[0-9]+$')"
            FFUF_FLAGS+=("-recursion" "-recursion-depth" "$custom_depth")
            ;;
    esac

    # ── 8. Extra flags (power-user escape hatch) ──────────────────────────────
    echo -e "\n${BOLD}  Additional ffuf flags${RESET} (leave blank to skip):" >&2
    echo -e "  Examples:  -fs 1234   -H 'Cookie: session=xyz'   -X POST -d 'user=FUZZ'" >&2
    printf "  Extra flags: " >&2
    local extra_flags_raw
    read -r extra_flags_raw

    if [[ -n "$extra_flags_raw" ]]; then
        local saved_ifs="$IFS"
        IFS=' ' read -ra extra_array <<< "$extra_flags_raw"
        IFS="$saved_ifs"
        FFUF_FLAGS+=("${extra_array[@]}")
    fi

    # ── Always-on flags (not user-configurable — see rationale above) ────────
    FFUF_FLAGS+=("-ic" "-se" "-of" "json")

    # ── Configuration summary ─────────────────────────────────────────────────
    FFUF_CMD_PREVIEW="ffuf -u <target>/FUZZ -w ${FFUF_WORDLIST}:FUZZ $(printf '%s ' "${FFUF_FLAGS[@]}")-o <out>.json"

    echo -e "\n${BOLD}${CYAN}── ffuf configuration summary ──────────────────────────${RESET}"
    echo "  Wordlist: $FFUF_WORDLIST ($wc_lines lines)"
    local pending=""
    local flag
    for flag in "${FFUF_FLAGS[@]}"; do
        if [[ "$flag" == -* ]]; then
            [[ -n "$pending" ]] && echo "  $pending"
            pending="$flag"
        else
            echo "  $pending $flag"
            pending=""
        fi
    done
    [[ -n "$pending" ]] && echo "  $pending"

    echo -e "\n${BOLD}  Full command (per endpoint):${RESET}"
    echo -e "  ${CYAN}${FFUF_CMD_PREVIEW}${RESET}\n"

    local confirm
    confirm="$(prompt_menu "Proceed with this ffuf configuration?" \
        "Yes — use this configuration" \
        "No  — reconfigure from the start")"

    if [[ "$confirm" == No* ]]; then
        log_info "Re-running ffuf configuration..."
        configure_ffuf_scan
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

    local optional_tools=("xmllint" "jq")

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
# LIVE NIKTO FINDING MONITOR
# ─────────────────────────────────────────────────────────────────────────────
# Nikto prints each finding to the console the moment it's discovered as a
# line starting with "+ " — same lines parse_nikto_findings() later extracts
# from the saved report. Mirroring that live, filtered down to just the
# finding text, gives the same "watch it happen, bail out if you've seen
# enough" experience the ffuf live monitor provides.
# ─────────────────────────────────────────────────────────────────────────────
_NIKTO_NOTABLE_KEYWORDS='admin|login|backup|\.sql|\.git|\.env|config|phpinfo|shell|inject|disclos|wp-|exec|password|secret'

_nikto_live_monitor() {
    local match_count=0
    local notable_count=0
    local line

    while IFS= read -r line; do
        [[ "$line" == +\ * ]] || continue
        [[ "$line" == *"Target IP:"* || "$line" == *"Target Hostname:"* || \
           "$line" == *"Target Port:"* || "$line" == *"Start Time:"* || \
           "$line" == *"End Time:"* || "$line" == *"requests:"*"item(s) reported"* ]] && continue

        (( match_count++ )) || true
        local finding="${line#+ }"

        if echo "$finding" | grep -qiE "$_NIKTO_NOTABLE_KEYWORDS"; then
            (( notable_count++ )) || true
            echo -e "    ${RED}${BOLD}⚠  NOTABLE${RESET}  [${match_count}] ${finding}" >&2
        else
            echo -e "    ${GREEN}[${match_count}]${RESET} ${finding}" >&2
        fi
    done

    echo -e "  ${CYAN}── ${match_count} finding(s) so far, ${notable_count} notable ──${RESET}" >&2
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
#
# CTRL+C SAFETY: same pattern as run_ffuf_scan — a scoped INT trap catches
# the signal instead of letting it kill the whole script, logs what
# happened, stops scanning any remaining endpoints, and falls through to
# parse_nikto_findings() as usual (which recovers whatever was captured —
# see its header comment).
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
    local NIKTO_INTERRUPTED=0

    log_info "Live findings will print below as they're found. Press ${BOLD}Ctrl+C${RESET} anytime to stop early — partial results are preserved."

    trap 'NIKTO_INTERRUPTED=1' INT

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
        if ! { nikto -h "$host" -p "$port" "${target_flags[@]}" \
                -Format "$NIKTO_FORMAT" -o "$out_file" \
                2>&1 | tee "$log_file" | _nikto_live_monitor; }; then
            if (( NIKTO_INTERRUPTED )); then
                log_warn "  nikto interrupted by user (Ctrl+C) — partial results for ${endpoint} preserved in $out_file / $log_file."
            else
                log_warn "  nikto run against ${endpoint} reported a non-zero exit — see $log_file"
                (( scan_failures++ )) || true
            fi
        fi

        if (( NIKTO_INTERRUPTED )); then
            touch "${nikto_dir}/.interrupted"
            log_warn "Stopping nikto stage early — skipping any remaining endpoints."
            break
        fi

    done < <(grep -v '^#' "$web_file")

    trap - INT

    log_info "nikto stage complete: ${BOLD}${endpoint_count}${RESET} endpoint(s) attempted, ${scan_failures} failure(s)."
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

    if [[ -f "${OUTPUT_DIR}/nikto/.interrupted" ]]; then
        log_warn "Note: nikto stage was interrupted early (Ctrl+C) — findings above reflect partial endpoint coverage."
    fi

    log_info "Parsed ${BOLD}${finding_count}${RESET} finding(s) → $out_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN NUCLEI SCAN  (Step 3)
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# LIVE NUCLEI MATCH MONITOR
# ─────────────────────────────────────────────────────────────────────────────
# nuclei's default (non -silent) console output prints each match as a line
# in the form "[template-id] [protocol] [severity] matched-url". This reads
# that stream and prints a compact counter, highlighting high/critical hits.
# ─────────────────────────────────────────────────────────────────────────────
_nuclei_live_monitor() {
    local match_count=0
    local notable_count=0
    local line

    while IFS= read -r line; do
        [[ "$line" =~ ^\[.+\]\ \[.+\]\ \[.+\] ]] || continue

        (( match_count++ )) || true
        local severity
        severity="$(echo "$line" | grep -oP '(?<=\[)[a-z]+(?=\])' | sed -n '3p')"

        if [[ "$severity" == "critical" || "$severity" == "high" ]]; then
            (( notable_count++ )) || true
            echo -e "    ${RED}${BOLD}⚠  ${severity^^}${RESET}  [${match_count}] ${line}" >&2
        else
            echo -e "    ${GREEN}[${match_count}]${RESET} ${line}" >&2
        fi
    done

    echo -e "  ${CYAN}── ${match_count} match(es) so far, ${notable_count} high/critical ──${RESET}" >&2
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN NUCLEI SCAN  (Step 3)
# ─────────────────────────────────────────────────────────────────────────────
# Unlike nikto, nuclei is invoked ONCE against a target list file (-l), not
# once per endpoint — it has its own internal worker pool (-c) and rate
# limiter (-rate-limit), so looping per-host here would just fight nuclei's
# own concurrency model and slow things down for no benefit.
#
# Input : ${OUTPUT_DIR}/web_services.txt (same endpoint list nikto consumes)
# Output: ${OUTPUT_DIR}/nuclei/targets.txt   — the -l input file we build
#         ${OUTPUT_DIR}/nuclei/nuclei_raw.jsonl — one JSON finding per line
#         ${OUTPUT_DIR}/nuclei/nuclei_raw.log    — live run log (tee'd)
#
# CTRL+C SAFETY: unlike ffuf/nikto there's no per-endpoint loop to break out
# of — nuclei handles the whole target list in one process — so a scoped
# INT trap here just needs to catch the signal, stop the script dying via
# set -e, and log what happened. -jsonl writes one complete JSON object per
# line as each match is found, so any results already written to the file
# before the interrupt are already complete, valid, and safely parseable —
# only a match caught mid-write (rare — writes are per-line) is at risk, and
# parse_nuclei_findings() below is hardened against exactly that.
# ─────────────────────────────────────────────────────────────────────────────
run_nuclei_scan() {
    local web_file="${OUTPUT_DIR}/web_services.txt"
    local nuclei_dir="${OUTPUT_DIR}/nuclei"

    log_section "Running nuclei Scan"

    if (( ! PIPELINE_TOOLS[nuclei] )); then
        log_info "nuclei was not selected for this pipeline — skipping."
        return 0
    fi

    if [[ ! -s "$web_file" ]] || ! grep -qv '^#' "$web_file"; then
        log_warn "No web services found in $web_file — nothing for nuclei to scan."
        return 0
    fi

    mkdir -p "$nuclei_dir"

    local targets_file="${nuclei_dir}/targets.txt"
    local out_file="${nuclei_dir}/nuclei_raw.jsonl"
    local log_file="${nuclei_dir}/nuclei_raw.log"
    local NUCLEI_INTERRUPTED=0

    # Build the -l target list directly from web_services.txt, stripping the
    # "# ..." comment/header lines identify_web_services() writes at the top.
    grep -v '^#' "$web_file" > "$targets_file"

    local target_count
    target_count="$(wc -l < "$targets_file" | tr -d ' ')"
    log_info "Target list (${BOLD}${target_count}${RESET} endpoint(s)) → $targets_file"
    log_info "Command: nuclei -l $targets_file ${NUCLEI_FLAGS[*]} -o $out_file"
    log_info "Live matches will print below as they're found. Press ${BOLD}Ctrl+C${RESET} anytime to stop early — partial results are preserved."

    trap 'NUCLEI_INTERRUPTED=1' INT

    # || true: nuclei exits non-zero on some non-fatal conditions (e.g. partial
    # template failures); we don't want that to abort the whole pipeline the
    # way a genuine setup error would. Failure is logged, not silently eaten.
    if ! { nuclei -l "$targets_file" "${NUCLEI_FLAGS[@]}" -o "$out_file" \
            2>&1 | tee "$log_file" | _nuclei_live_monitor; }; then
        if (( NUCLEI_INTERRUPTED )); then
            touch "${nuclei_dir}/.interrupted"
            log_warn "nuclei interrupted by user (Ctrl+C) — partial results preserved in $out_file / $log_file."
        else
            log_warn "nuclei exited with a non-zero status — check $log_file"
        fi
    fi

    trap - INT

    if [[ -s "$out_file" ]]; then
        local finding_lines
        finding_lines="$(wc -l < "$out_file" | tr -d ' ')"
        log_info "nuclei scan complete: ${BOLD}${finding_lines}${RESET} finding line(s) → $out_file"
    else
        log_info "nuclei scan complete: 0 findings (target matched no installed templates)."
        log_info "  This is a normal outcome, not a failure — check $log_file for run stats"
        log_info "  (templates loaded/executed) to confirm the scan actually ran."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PARSE NUCLEI FINDINGS  (Step 3)
# ─────────────────────────────────────────────────────────────────────────────
# -jsonl output is one JSON object per line, e.g.:
#   {"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},
#    "host":"https://192.168.1.10:8443","matched-at":"https://192.168.1.10:8443", ...}
#
# Parsed LINE-BY-LINE rather than as a whole-file jq stream — this is what
# makes it Ctrl+C-safe: if the scan was interrupted mid-write, only the
# single incomplete trailing line fails its "does this look like a complete
# JSON object" check and gets skipped; every earlier line, each one a
# complete finding already flushed to disk, parses normally. Prefers jq per
# line when available (proper JSON parsing); falls back to best-effort
# grep extraction otherwise.
# ─────────────────────────────────────────────────────────────────────────────
parse_nuclei_findings() {
    local raw_file="${OUTPUT_DIR}/nuclei/nuclei_raw.jsonl"
    local out_file="${OUTPUT_DIR}/nuclei_findings.txt"

    log_section "Parsing nuclei Findings"

    if (( ! PIPELINE_TOOLS[nuclei] )); then
        log_info "nuclei was not selected — nothing to parse."
        return 0
    fi

    if [[ ! -s "$raw_file" ]]; then
        log_warn "No nuclei output found (or file is empty) at $raw_file — skipping parse."
        return 0
    fi

    echo "severity|template-id|host|matched-at|name" > "$out_file"

    local finding_count=0
    local skipped_incomplete=0
    local jq_available=0
    command -v jq &>/dev/null && jq_available=1
    (( jq_available )) || log_warn "jq not found — using best-effort text extraction per line."

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # A complete JSON object line starts with { and ends with } — a line
        # cut short mid-write by Ctrl+C won't, and is skipped here rather
        # than fed to a parser that would error on it.
        if [[ "$line" != \{*\} ]]; then
            (( skipped_incomplete++ )) || true
            continue
        fi

        local severity template_id host matched_at name
        if (( jq_available )); then
            IFS=$'\t' read -r severity template_id host matched_at name < <(
                echo "$line" | jq -r '[.info.severity, ."template-id", .host, ."matched-at", .info.name] | @tsv' 2>/dev/null
            ) || true
        fi

        # jq unavailable, or it choked on this specific line for some other
        # reason (still worth a text-based attempt rather than losing the row)
        if [[ -z "$template_id" ]]; then
            severity="$(echo "$line" | grep -oP '"severity"\s*:\s*"\K[^"]+' | head -1)"
            template_id="$(echo "$line" | grep -oP '"template-id"\s*:\s*"\K[^"]+' | head -1)"
            host="$(echo "$line" | grep -oP '"host"\s*:\s*"\K[^"]+' | head -1)"
            matched_at="$(echo "$line" | grep -oP '"matched-at"\s*:\s*"\K[^"]+' | head -1)"
            name="$(echo "$line" | grep -oP '"name"\s*:\s*"\K[^"]+' | head -1)"
        fi

        [[ -z "$template_id" ]] && continue
        name="${name//|/;}"
        echo "${severity:-unknown}|${template_id}|${host}|${matched_at}|${name}" >> "$out_file"
        (( finding_count++ )) || true
    done < "$raw_file"

    if [[ -f "${OUTPUT_DIR}/nuclei/.interrupted" ]]; then
        log_warn "Note: nuclei stage was interrupted early (Ctrl+C) — findings above reflect partial template coverage."
    fi
    (( skipped_incomplete > 0 )) && log_info "Skipped ${skipped_incomplete} incomplete trailing line(s) (expected if the scan was interrupted mid-write)."

    log_info "Parsed ${BOLD}${finding_count}${RESET} finding(s) → $out_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# CURATED "HIGH-SIGNAL" PATH PATTERNS  (used by identify_notable_ffuf_findings)
# ─────────────────────────────────────────────────────────────────────────────
# Extended-regex fragments (grep -E) matched against the discovered path.
# These are paths where a hit is disproportionately significant regardless of
# how big the wordlist was — config/secret files, VCS metadata, admin panels,
# backups, and common info-disclosure endpoints.
# ─────────────────────────────────────────────────────────────────────────────
_FFUF_HIGH_SIGNAL_PATTERNS='\.env(\.|$)|\.git(/|$)|\.svn(/|$)|\.htpasswd|\.htaccess|wp-config|wp-admin|wp-login|phpinfo|server-status|server-info|robots\.txt|sitemap\.xml|\.well-known/security\.txt|admin|login|backup|\.sql$|\.zip$|\.tar\.gz$|\.bak$|\.old$|docker-compose|Dockerfile|\.DS_Store|id_rsa|swagger|api-docs|graphql|actuator|debug|console|\.idea|\.vscode|web\.config|configuration\.php|dump\.sql|database\.sql|crossdomain\.xml'

# ─────────────────────────────────────────────────────────────────────────────
# LIVE FFUF MATCH MONITOR
# ─────────────────────────────────────────────────────────────────────────────
# Reads ffuf's own stdout as it streams (one process stage in a pipe) and
# prints a compact, one-line-per-match indicator instead of ffuf's default
# boxed report — so a user watching a long scan can see what's being found
# in real time and make an informed call to Ctrl+C early, without having to
# parse ffuf's noisier native output.
#
# ffuf's default (non-silent) text output prints each match as a line
# containing "[Status: <code>, Size: <n>, Words: <n>, ...]" — every other
# line (progress bar redraws, banner, summary) is passed through untouched
# to the log file by `tee` upstream of this function but is simply not
# matched/counted here.
# ─────────────────────────────────────────────────────────────────────────────
_ffuf_live_monitor() {
    local match_count=0
    local notable_count=0
    local line

    while IFS= read -r line; do
        [[ "$line" == *"[Status:"* ]] || continue

        (( match_count++ )) || true

        local path status
        path="$(echo "$line" | awk '{print $1}')"
        status="$(echo "$line" | grep -oP '(?<=Status: )[0-9]+' || true)"

        if echo "$path" | grep -qiE "$_FFUF_HIGH_SIGNAL_PATTERNS"; then
            (( notable_count++ )) || true
            echo -e "    ${RED}${BOLD}⚠  NOTABLE${RESET}  [${match_count}] ${BOLD}${path}${RESET}  (status ${status:-?})" >&2
        else
            echo -e "    ${GREEN}[${match_count}]${RESET} ${path}  (status ${status:-?})" >&2
        fi
    done

    echo -e "  ${CYAN}── ${match_count} match(es) so far, ${notable_count} notable ──${RESET}" >&2
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN FFUF SCAN  (Step 4)
# ─────────────────────────────────────────────────────────────────────────────
# Runs once PER endpoint (ffuf's -u target/FUZZ model is inherently
# single-target, unlike nuclei's batch -l mode).
#
# Output per endpoint: ffuf/<host>_<port>.json  (ffuf's native -of json report)
#                       ffuf/<host>_<port>.log   (live run log, tee'd)
#
# CTRL+C SAFETY: a dedicated INT trap is installed for the duration of this
# function only. On SIGINT it does NOT let the script die mid-write — it
# sets a flag, lets the current ffuf process (which also receives the
# signal and exits on its own) unwind normally, logs what happened, skips
# any remaining endpoints, and falls through to parse_ffuf_results() as
# usual. parse_ffuf_results() is itself hardened (see its header comment)
# to recover whatever was captured even if ffuf's JSON file was left
# incomplete by the interruption — no results are lost, only the endpoints
# that hadn't started yet are skipped.
# ─────────────────────────────────────────────────────────────────────────────
run_ffuf_scan() {
    local web_file="${OUTPUT_DIR}/web_services.txt"
    local ffuf_dir="${OUTPUT_DIR}/ffuf"

    log_section "Running ffuf Scan"

    if (( ! PIPELINE_TOOLS[ffuf] )); then
        log_info "ffuf was not selected for this pipeline — skipping."
        return 0
    fi

    if [[ ! -s "$web_file" ]] || ! grep -qv '^#' "$web_file"; then
        log_warn "No web services found in $web_file — nothing for ffuf to scan."
        return 0
    fi

    mkdir -p "$ffuf_dir"

    local endpoint_count=0
    local scan_failures=0
    local FFUF_INTERRUPTED=0

    log_info "Live matches will print below as they're found. Press ${BOLD}Ctrl+C${RESET} anytime to stop early — partial results are preserved."

    trap 'FFUF_INTERRUPTED=1' INT

    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue

        local host port
        host="$(echo "$endpoint" | grep -oP '(?<=://)[^:]+')"
        port="$(echo "$endpoint" | grep -oP ':\K[0-9]+$')"

        if [[ -z "$host" || -z "$port" ]]; then
            log_warn "  Could not parse endpoint '$endpoint' — skipping."
            continue
        fi

        (( endpoint_count++ )) || true

        local out_file="${ffuf_dir}/${host}_${port}.json"
        local log_file="${ffuf_dir}/${host}_${port}.log"
        local target_url="${endpoint}/FUZZ"

        log_info "  🔎  Fuzzing ${BOLD}${target_url}${RESET} → $out_file"

        # || true: one endpoint erroring out (dead host, TLS handshake
        # failure, etc.) must not abort the whole ffuf stage. tee writes the
        # complete raw stream to $log_file (used as a parsing fallback);
        # _ffuf_live_monitor consumes the same stream to print live matches.
        if ! { ffuf -u "$target_url" -w "${FFUF_WORDLIST}:FUZZ" "${FFUF_FLAGS[@]}" \
                -o "$out_file" \
                2>&1 | tee "$log_file" | _ffuf_live_monitor; }; then
            if (( FFUF_INTERRUPTED )); then
                log_warn "  ffuf interrupted by user (Ctrl+C) — partial results for ${endpoint} preserved in $out_file / $log_file."
            else
                log_warn "  ffuf run against ${endpoint} reported a non-zero exit — see $log_file"
                (( scan_failures++ )) || true
            fi
        fi

        if (( FFUF_INTERRUPTED )); then
            touch "${ffuf_dir}/.interrupted"
            log_warn "Stopping ffuf stage early — skipping any remaining endpoints."
            break
        fi

    done < <(grep -v '^#' "$web_file")

    trap - INT

    log_info "ffuf stage complete: ${BOLD}${endpoint_count}${RESET} endpoint(s) attempted, ${scan_failures} failure(s)."
    log_info "Raw reports → $ffuf_dir/"
}

# ─────────────────────────────────────────────────────────────────────────────
# PARSE FFUF RESULTS  (Step 4)
# ─────────────────────────────────────────────────────────────────────────────
# ffuf's -of json report is a single JSON object: {"results": [ {...}, ... ]}.
# Each result object has (in this fixed key order): input, position, status,
# length, words, lines, content-type, redirectlocation, url, host, resultfile.
#
# Prefers jq (order-independent, handles edge cases in URLs/paths correctly)
# — but ONLY when the file is verified valid JSON first. A scan interrupted
# mid-write (Ctrl+C) can leave a truncated file; jq would error on that and
# silently return zero rows even though dozens of matches were captured.
# That failure mode is exactly what we need to avoid per the "don't damage
# findings on Ctrl+C" requirement, so invalid JSON routes to two fallback
# layers instead:
#   1. Positional grep+paste over the same file, truncated to the shortest
#      field list so a partially-written trailing object is dropped cleanly
#      rather than producing a misaligned row.
#   2. If that still yields nothing (interrupted before any field completed),
#      recover matches from ffuf's plain-text .log file instead — each match
#      there is a single self-contained line, immune to JSON structure.
# ─────────────────────────────────────────────────────────────────────────────
parse_ffuf_results() {
    local ffuf_dir="${OUTPUT_DIR}/ffuf"
    local out_file="${OUTPUT_DIR}/ffuf_findings.txt"

    log_section "Parsing ffuf Results"

    if (( ! PIPELINE_TOOLS[ffuf] )); then
        log_info "ffuf was not selected — nothing to parse."
        return 0
    fi

    if [[ ! -d "$ffuf_dir" ]] || [[ -z "$(ls -A "$ffuf_dir" 2>/dev/null)" ]]; then
        log_warn "No ffuf output directory/files found — skipping parse."
        return 0
    fi

    echo "host|port|path|status|length|words|url" > "$out_file"

    local finding_count=0
    local report_file
    local jq_available=0
    command -v jq &>/dev/null && jq_available=1

    for report_file in "$ffuf_dir"/*.json; do
        [[ -f "$report_file" ]] || continue

        local base host port log_file
        base="$(basename "$report_file" .json)"
        host="${base%_*}"
        port="${base##*_}"
        log_file="${ffuf_dir}/${base}.log"

        local file_finding_count=0

        # Only trust jq's parse if the file is verified valid JSON first —
        # an interrupted (Ctrl+C) run can leave a truncated file that jq
        # would error on and silently return nothing for.
        local json_valid=0
        if (( jq_available )) && jq empty "$report_file" &>/dev/null; then
            json_valid=1
        fi

        if (( json_valid )); then
            while IFS=$'\t' read -r status length words url; do
                [[ -z "$url" ]] && continue
                local path="${url#*://*/}"
                echo "${host}|${port}|${path}|${status}|${length}|${words}|${url}" >> "$out_file"
                (( finding_count++ )) || true
                (( file_finding_count++ )) || true
            done < <(jq -r '.results[]? | [.status, .length, .words, .url] | @tsv' "$report_file" 2>/dev/null || true)
        else
            if (( jq_available )) && [[ -s "$report_file" ]]; then
                log_warn "  ${base}.json failed JSON validation (scan was likely interrupted) — using resilient fallback parser."
            elif (( ! jq_available )); then
                log_warn "  jq not found — using positional grep+paste fallback for ${base}."
            fi

            # FALLBACK LAYER 1 — positional grep+paste, truncated to the
            # shortest field list so a partially-written trailing object
            # (missing its last key or two) is dropped cleanly instead of
            # producing a misaligned row.
            local status_list length_list words_list url_list
            status_list="$(grep -oP '"status":\s*\K[0-9]+' "$report_file" 2>/dev/null || true)"
            length_list="$(grep -oP '"length":\s*\K[0-9]+' "$report_file" 2>/dev/null || true)"
            words_list="$(grep -oP '"words":\s*\K[0-9]+' "$report_file" 2>/dev/null || true)"
            url_list="$(grep -oP '"url":\s*"\K[^"]+' "$report_file" 2>/dev/null || true)"

            local n_status n_length n_words n_url min_n
            n_status="$([[ -n "$status_list" ]] && wc -l <<< "$status_list" || echo 0)"
            n_length="$([[ -n "$length_list" ]] && wc -l <<< "$length_list" || echo 0)"
            n_words="$([[ -n "$words_list" ]] && wc -l <<< "$words_list" || echo 0)"
            n_url="$([[ -n "$url_list" ]] && wc -l <<< "$url_list" || echo 0)"
            min_n=$(( n_status < n_length ? n_status : n_length ))
            min_n=$(( min_n < n_words ? min_n : n_words ))
            min_n=$(( min_n < n_url ? min_n : n_url ))

            if (( min_n > 0 )); then
                while IFS='|' read -r status length words url; do
                    [[ -z "$url" ]] && continue
                    local path="${url#*://*/}"
                    echo "${host}|${port}|${path}|${status}|${length}|${words}|${url}" >> "$out_file"
                    (( finding_count++ )) || true
                    (( file_finding_count++ )) || true
                done < <(paste -d'|' <(head -n "$min_n" <<< "$status_list") \
                                      <(head -n "$min_n" <<< "$length_list") \
                                      <(head -n "$min_n" <<< "$words_list") \
                                      <(head -n "$min_n" <<< "$url_list"))
            fi

            # FALLBACK LAYER 2 — last resort. If the JSON gave us nothing
            # usable at all (interrupted before even one field completed),
            # recover matches straight from ffuf's plain-text .log file —
            # each match there is one self-contained line, independent of
            # JSON structure entirely: "path   [Status: 200, Size: 45, ...]"
            if (( file_finding_count == 0 )) && [[ -f "$log_file" ]]; then
                log_warn "  No usable data in ${base}.json — recovering matches from ${base}.log instead."
                while IFS= read -r line; do
                    [[ "$line" == *"[Status:"* ]] || continue
                    local lpath lstatus llength lwords
                    lpath="$(echo "$line" | awk '{print $1}')"
                    lstatus="$(echo "$line" | grep -oP '(?<=Status: )[0-9]+' || true)"
                    llength="$(echo "$line" | grep -oP '(?<=Size: )[0-9]+' || true)"
                    lwords="$(echo "$line" | grep -oP '(?<=Words: )[0-9]+' || true)"
                    [[ -z "$lpath" || -z "$lstatus" ]] && continue
                    echo "${host}|${port}|${lpath}|${lstatus}|${llength:-0}|${lwords:-0}|${host}:${port}/${lpath}" >> "$out_file"
                    (( finding_count++ )) || true
                    (( file_finding_count++ )) || true
                done < "$log_file"
            fi
        fi
    done

    if [[ -f "${ffuf_dir}/.interrupted" ]]; then
        log_warn "Note: ffuf stage was interrupted early (Ctrl+C) — results above reflect partial wordlist coverage, not a completed scan."
    fi

    log_info "Parsed ${BOLD}${finding_count}${RESET} result(s) → $out_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# IDENTIFY NOTABLE FFUF FINDINGS  (Step 4)
# ─────────────────────────────────────────────────────────────────────────────
# ffuf can easily produce hundreds of hits on a large wordlist. This function
# surfaces the small subset that's actually worth a human looking at first:
#   - path matches a known-sensitive pattern (config/secret/VCS/admin/backup)
#   - AND status is 200 (exists and readable), 401/403 (exists but gated —
#     itself informative), or a redirect (301/302/307, often config/admin
#     panels bouncing to a login page)
# Sorted so 200s (highest priority — directly accessible) appear first.
# ─────────────────────────────────────────────────────────────────────────────
identify_notable_ffuf_findings() {
    local findings_file="${OUTPUT_DIR}/ffuf_findings.txt"
    local out_file="${OUTPUT_DIR}/ffuf_notable.txt"

    log_section "Identifying Notable ffuf Findings"

    if (( ! PIPELINE_TOOLS[ffuf] )); then
        log_info "ffuf was not selected — nothing to flag."
        return 0
    fi

    if [[ ! -s "$findings_file" ]]; then
        log_warn "No parsed ffuf findings at $findings_file — skipping."
        return 0
    fi

    echo "priority|host|port|path|status|length|url" > "$out_file"

    local notable_count=0
    local tmp_unsorted
    tmp_unsorted="$(mktemp)"

    while IFS='|' read -r host port path status length words url; do
        [[ "$host" == "host" ]] && continue  # skip header row

        # High-signal path match — case-insensitive
        echo "$path" | grep -qiE "$_FFUF_HIGH_SIGNAL_PATTERNS" || continue

        local priority
        case "$status" in
            200)          priority=1 ;;   # directly accessible — most critical
            401|403)      priority=2 ;;   # exists, access-controlled — still worth a look
            301|302|307)  priority=3 ;;   # redirect — often an admin/login bounce
            *)            priority=4 ;;
        esac

        echo "${priority}|${host}|${port}|${path}|${status}|${length}|${url}" >> "$tmp_unsorted"
        (( notable_count++ )) || true
    done < "$findings_file"

    # Sort numerically by priority (200s first), stable order otherwise
    sort -t'|' -k1,1n "$tmp_unsorted" >> "$out_file"
    rm -f "$tmp_unsorted"

    if (( notable_count == 0 )); then
        log_info "No high-signal paths matched. See ${OUTPUT_DIR}/ffuf_findings.txt for the full result set."
    else
        log_info "Flagged ${BOLD}${notable_count}${RESET} notable finding(s) → $out_file"
        log_warn "Review these first — they include config/secret/admin/backup-style paths."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE UNIFIED CROSS-TOOL REPORT
# ─────────────────────────────────────────────────────────────────────────────
# The per-tool findings files (nikto_findings.txt, nuclei_findings.txt,
# ffuf_notable.txt) are each keyed differently and read separately. This
# pulls all three into one host-keyed file, ${OUTPUT_DIR}/unified_findings.txt
# (host|port|tool|severity_or_status|detail), so "everything found on this
# one host, from every tool" is a single grep away instead of three.
# Silently produces an empty-but-headered file if no tools ran / found
# anything — downstream consumers (generate_summary) handle that cleanly.
# ─────────────────────────────────────────────────────────────────────────────
generate_unified_report() {
    local out_file="${OUTPUT_DIR}/unified_findings.txt"

    log_section "Generating Unified Cross-Tool Report"

    echo "host|port|tool|severity_or_status|detail" > "$out_file"
    local total=0

    if [[ -s "${OUTPUT_DIR}/nikto_findings.txt" ]]; then
        while IFS='|' read -r host port finding; do
            [[ "$host" == "host" ]] && continue
            echo "${host}|${port}|nikto|-|${finding}" >> "$out_file"
            (( total++ )) || true
        done < "${OUTPUT_DIR}/nikto_findings.txt"
    fi

    if [[ -s "${OUTPUT_DIR}/nuclei_findings.txt" ]]; then
        while IFS='|' read -r severity template_id host matched_at name; do
            [[ "$severity" == "severity" ]] && continue
            local port hostonly
            # nuclei's "host" field is a full scheme://host:port URL — pull
            # the bare host and port back out so this rolls up under the
            # same host key nikto/ffuf use.
            hostonly="$(echo "$host" | grep -oP '(?<=://)[^:/]+' || echo "$host")"
            port="$(echo "$host" | grep -oP ':\K[0-9]+' | head -1)"
            [[ -z "$port" ]] && port="?"
            echo "${hostonly}|${port}|nuclei|${severity}|${template_id}: ${name}" >> "$out_file"
            (( total++ )) || true
        done < "${OUTPUT_DIR}/nuclei_findings.txt"
    fi

    if [[ -s "${OUTPUT_DIR}/ffuf_notable.txt" ]]; then
        while IFS='|' read -r priority host port path status length url; do
            [[ "$priority" == "priority" ]] && continue
            echo "${host}|${port}|ffuf|${status}|${path}" >> "$out_file"
            (( total++ )) || true
        done < "${OUTPUT_DIR}/ffuf_notable.txt"
    fi

    log_info "Unified report: ${BOLD}${total}${RESET} cross-tool finding(s) → $out_file"
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

        if [[ -s "${OUTPUT_DIR}/unified_findings.txt" ]] && \
           (( $(tail -n +2 "${OUTPUT_DIR}/unified_findings.txt" | wc -l) > 0 )); then
            echo "── CONSOLIDATED FINDINGS BY HOST (all tools) ──────────"
            local uhosts
            uhosts="$(tail -n +2 "${OUTPUT_DIR}/unified_findings.txt" | cut -d'|' -f1 | sort -u)"
            while IFS= read -r h; do
                [[ -z "$h" ]] && continue
                echo "  ${BOLD}${h}${RESET}"
                grep "^${h}|" "${OUTPUT_DIR}/unified_findings.txt" | \
                while IFS='|' read -r fhost fport ftool fsev fdetail; do
                    printf "    [%-6s] port %-5s %-8s %s\n" "$ftool" "$fport" "$fsev" "$fdetail"
                done
            done <<< "$uhosts"
            echo ""
        fi

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

        if (( PIPELINE_TOOLS[nuclei] )); then
            echo ""
            echo "── NUCLEI FINDINGS ─────────────────────────────────────"
            if [[ -s "${OUTPUT_DIR}/nuclei_findings.txt" ]]; then
                local nuclei_finding_total
                nuclei_finding_total="$(tail -n +2 "${OUTPUT_DIR}/nuclei_findings.txt" | wc -l | tr -d ' ')"
                echo "  Total findings: ${nuclei_finding_total}"
                echo ""
                printf "%-10s %-25s %-30s %s\n" "SEVERITY" "TEMPLATE-ID" "MATCHED-AT" "NAME"
                printf "%-10s %-25s %-30s %s\n" "─────────" "────────────────────────" "─────────────────────────────" "───────────────────────"
                tail -n +2 "${OUTPUT_DIR}/nuclei_findings.txt" | \
                while IFS='|' read -r severity template_id host matched_at name; do
                    printf "%-10s %-25s %-30s %s\n" "$severity" "$template_id" "$matched_at" "$name"
                done
            else
                echo "  (no parsed findings — check ${OUTPUT_DIR}/nuclei/nuclei_raw.jsonl for raw output)"
            fi
        fi

        if (( PIPELINE_TOOLS[ffuf] )); then
            echo ""
            if [[ -f "${OUTPUT_DIR}/ffuf/.interrupted" ]]; then
                echo "  ⚠ ffuf scan was interrupted early (Ctrl+C) — coverage below is partial."
            fi
            echo "── FFUF: NOTABLE / HIGH-SIGNAL FINDINGS ───────────────"
            if [[ -s "${OUTPUT_DIR}/ffuf_notable.txt" ]]; then
                printf "%-6s %-18s %-6s %-8s %s\n" "STATUS" "HOST" "PORT" "LENGTH" "PATH"
                printf "%-6s %-18s %-6s %-8s %s\n" "──────" "──────────────────" "─────" "───────" "──────────────────────────"
                tail -n +2 "${OUTPUT_DIR}/ffuf_notable.txt" | \
                while IFS='|' read -r priority host port path status length url; do
                    printf "%-6s %-18s %-6s %-8s %s\n" "$status" "$host" "$port" "$length" "$path"
                done
            else
                echo "  (none flagged — see ${OUTPUT_DIR}/ffuf_findings.txt for the full result set)"
            fi

            echo ""
            echo "── FFUF: ALL RESULTS (summary) ─────────────────────────"
            if [[ -s "${OUTPUT_DIR}/ffuf_findings.txt" ]]; then
                local ffuf_total
                ffuf_total="$(tail -n +2 "${OUTPUT_DIR}/ffuf_findings.txt" | wc -l | tr -d ' ')"
                echo "  Total results: ${ffuf_total}  (full detail in ffuf_findings.txt)"
            else
                echo "  (no results — check ${OUTPUT_DIR}/ffuf/ for raw JSON output)"
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
        if (( PIPELINE_TOOLS[nuclei] )); then
            echo "  [✔] nuclei  — vuln scan + parse   COMPLETE"
        else
            echo "  [-] nuclei  — skipped (not selected)"
        fi
        if (( PIPELINE_TOOLS[ffuf] )); then
            echo "  [✔] ffuf    — fuzz + parse + triage COMPLETE"
        else
            echo "  [-] ffuf    — skipped (not selected)"
        fi
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
    echo -e "  Security Pipeline — nmap + nikto + nuclei + ffuf v${SCRIPT_VERSION}${RESET}"
    echo ""

    [[ "${1:-}" =~ ^(-h|--help)$ ]] && usage

    if [[ $# -lt 1 ]]; then
        log_error "Missing required argument: <target>"
        usage
    fi

    local target="$1"
    local output_base="${2:-./scan_results}"
    local pipeline_start_time
    pipeline_start_time="$(date +%s)"

    # ── Interactive configuration (runs before any scanning) ─────────────────
    select_pipeline_tools       # 1. Ask which tools to chain
    configure_nmap_scan         # 2. Ask how to run nmap
    if (( PIPELINE_TOOLS[nikto] )); then
        configure_nikto_scan    # 2b. Ask how to run nikto (only if selected)
    fi
    if (( PIPELINE_TOOLS[nuclei] )); then
        configure_nuclei_scan   # 2c. Ask how to run nuclei (only if selected)
    fi
    if (( PIPELINE_TOOLS[ffuf] )); then
        configure_ffuf_scan     # 2d. Ask how to run ffuf (only if selected)
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
    run_nuclei_scan             # Step 3: skips internally if not selected / no web services
    parse_nuclei_findings
    run_ffuf_scan               # Step 4: skips internally if not selected / no web services
    parse_ffuf_results
    identify_notable_ffuf_findings
    generate_unified_report
    generate_summary "$target"

    # ── Housekeeping ──────────────────────────────────────────────────────────
    cleanup_temp_files
    archive_results

    local pipeline_end_time elapsed
    pipeline_end_time="$(date +%s)"
    elapsed=$(( pipeline_end_time - pipeline_start_time ))

    log_section "Pipeline Complete"
    log_info "All files are in: ${BOLD}${OUTPUT_DIR}${RESET}"
    log_info "Total runtime: ${BOLD}$(( elapsed / 60 ))m $(( elapsed % 60 ))s${RESET}"
    local ran_stages="nmap"
    (( PIPELINE_TOOLS[nikto] ))  && ran_stages+=", nikto"
    (( PIPELINE_TOOLS[nuclei] )) && ran_stages+=", nuclei"
    (( PIPELINE_TOOLS[ffuf] ))   && ran_stages+=", ffuf"
    log_info "Stages run: ${BOLD}${ran_stages}${RESET}"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP TEMP FILES
# ─────────────────────────────────────────────────────────────────────────────
# Removes the auto-generated fallback wordlist (mktemp'd under /tmp) when one
# was created — never touches a user-supplied or auto-detected system
# wordlist, since FFUF_WORDLIST_IS_TEMP is only ever set to 1 by the fallback
# path in configure_ffuf_scan().
# ─────────────────────────────────────────────────────────────────────────────
cleanup_temp_files() {
    if (( FFUF_WORDLIST_IS_TEMP )) && [[ -f "$FFUF_WORDLIST" ]]; then
        rm -f "$FFUF_WORDLIST"
        log_info "Cleaned up temporary fallback wordlist: $FFUF_WORDLIST"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ARCHIVE RESULTS
# ─────────────────────────────────────────────────────────────────────────────
# Bundles the entire output directory into a single .tar.gz alongside it —
# convenient for handing off a complete report (raw scans + parsed findings
# + summary) as one file. Never overwrites/removes the unarchived directory;
# purely additive. A failure here is a warning, not a pipeline failure — the
# results are already safely on disk either way.
# ─────────────────────────────────────────────────────────────────────────────
archive_results() {
    local archive_path="${OUTPUT_DIR}.tar.gz"

    log_section "Archiving Results"

    if tar -czf "$archive_path" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null; then
        local archive_size
        archive_size="$(du -h "$archive_path" 2>/dev/null | cut -f1)"
        log_info "Full results archived → ${BOLD}${archive_path}${RESET} (${archive_size:-unknown size})"
    else
        log_warn "Archiving failed — results remain fully available, unarchived, at $OUTPUT_DIR"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry point guard — allows sourcing for unit testing
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
