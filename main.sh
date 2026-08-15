        echo ""
        echo "── PIPELINE STATUS ─────────────────────────────────────"
        echo "  [✔] nmap    — scan + parse        COMPLETE"
        # Print each tool's status based on what the user selected
        for _tool in nikto nuclei ffuf; do
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

    # ── Interactive configuration (runs before any scanning) ─────────────────
    select_pipeline_tools       # 1. Ask which tools to chain
    configure_nmap_scan         # 2. Ask how to run nmap

    # ── Validation & setup ───────────────────────────────────────────────────
    check_dependencies          # 3. Verify nmap + selected tools are installed
    validate_target "$target"   # 4. Sanitise the target string
    setup_output_dir "$target" "$output_base"  # 5. Create timestamped output dir

    # ── Scanning & parsing ───────────────────────────────────────────────────
    run_nmap_scan "$target"     # 6. Execute nmap with user-chosen flags
    parse_open_ports            # 7. gnmap → open_ports.txt
    identify_web_services       # 8. Flag HTTP/HTTPS → web_services.txt
    generate_summary "$target"  # 9. Human-readable report

    log_section "nmap Stage Complete"
    log_info "All files are in: ${BOLD}${OUTPUT_DIR}${RESET}"

    # Remind user what runs next based on their pipeline selection
    local next_steps=()
    (( PIPELINE_TOOLS[nikto]  )) && next_steps+=("nikto")
    (( PIPELINE_TOOLS[nuclei] )) && next_steps+=("nuclei")
    (( PIPELINE_TOOLS[ffuf]   )) && next_steps+=("ffuf")

    if (( ${#next_steps[@]} > 0 )); then
        log_info "Next stages queued: ${BOLD}${next_steps[*]}${RESET}"
        log_info "Confirm to proceed to Step 2 — Nikto Integration."
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
