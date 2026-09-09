#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 07-report.sh
# DESCRIPTION  : Phase 7 - aggregate results into a run inventory and summary.
#                Builds a machine-readable JSON index of the engagement's
#                artifacts and a human summary, and (when present) drives the
#                repo's analysis_and_output.sh over any per-domain M365 JSON.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_report
###############################################################################
function run_phase_report() {
    local d="${RECON_OUTDIR}"
    local summary="${d}/recon-summary.txt"
    local index="${d}/recon-summary.json"

    LOG info "aggregating results into ${summary}"

    {
        printf 'External Recon Summary\n'
        printf 'Engagement : %s\n' "${RECON_ENGAGEMENT_DIR}"
        printf 'Generated  : %s\n\n' "$(date '+%F %T')"
        printf '%-22s %s\n' "Subdomains:" "$(count_lines "${d}/subdomains.txt")"
        printf '%-22s %s\n' "Resolved IPs (recon):" "$(count_lines "${d}/resolved-ips.txt")"
        printf '%-22s %s\n' "Domain candidates:" "$(count_lines "${d}/domains-candidates.txt")"
        printf '%-22s %s\n' "Live hosts:" "$(count_lines "${d}/04-portscan/live-hosts.txt")"
        printf '%-22s %s\n' "Web services:" "$(count_lines "${d}/04-portscan/web-services.txt")"
        printf '%-22s %s\n' "Live URLs:" "$(count_lines "${d}/urls.txt")"
        printf '%-22s %s\n' "Nuclei findings:" "$(count_lines "${d}/06-vuln/nuclei.out")"
    } > "${summary}"

    # Minimal JSON inventory (jq if available for clean encoding).
    if have_cmd jq; then
        jq -n \
            --arg engagement "${RECON_ENGAGEMENT_DIR}" \
            --arg generated "$(date '+%F %T')" \
            --argjson subdomains "$(count_lines "${d}/subdomains.txt")" \
            --argjson resolved_ips "$(count_lines "${d}/resolved-ips.txt")" \
            --argjson candidates "$(count_lines "${d}/domains-candidates.txt")" \
            --argjson live_hosts "$(count_lines "${d}/04-portscan/live-hosts.txt")" \
            --argjson web_services "$(count_lines "${d}/04-portscan/web-services.txt")" \
            --argjson live_urls "$(count_lines "${d}/urls.txt")" \
            --argjson nuclei "$(count_lines "${d}/06-vuln/nuclei.out")" \
            '{engagement:$engagement, generated:$generated, counts:{
                subdomains:$subdomains, resolved_ips:$resolved_ips,
                domain_candidates:$candidates, live_hosts:$live_hosts,
                web_services:$web_services, live_urls:$live_urls,
                nuclei_findings:$nuclei}}' > "${index}" 2> /dev/null || true
    fi

    # Optional: drive the repo's analysis module over per-domain M365 JSON.
    local analysis="${RECON_MODULE_DIR}/analysis_and_output.sh"
    if [[ -f "${analysis}" ]] && have_cmd jq; then
        # shellcheck source=/dev/null
        source "${analysis}" 2> /dev/null || true
        if declare -F print_summary > /dev/null 2>&1; then
            local jf
            for jf in "${d}"/02-dns-email/*.json "${d}"/03-cloud/*.json; do
                [[ -f "${jf}" ]] || continue
                LOG info "analysis: $(basename "${jf}")"
                print_summary "$(cat "${jf}")" >> "${summary}" 2> /dev/null || true
            done
        fi
    fi

    LOG pass "report written: ${summary}"
    return 0
}
