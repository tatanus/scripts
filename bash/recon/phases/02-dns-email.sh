#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 02-dns-email.sh
# DESCRIPTION  : Phase 2 - DNS and email-security intelligence. Wraps the
#                repo's m365_recon_NG.sh (which drives dns_email_recon.sh and
#                smtp_recon.sh) to collect A/MX/TXT/SPF/DMARC/DKIM/MTA-STS/
#                TLS-RPT/BIMI, SRV records, SMTP banners and direct-send
#                posture for each root domain. Opt-in.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_dns_email
###############################################################################
function run_phase_dns_email() {
    local m365="${RECON_MODULE_DIR}/m365_recon_NG.sh"
    if [[ ! -f "${m365}" ]]; then
        LOG warn "m365_recon_NG.sh not found - skipping DNS/email intelligence"
        RECON_STAGE_NOTE="skipped (module missing)"
        return 0
    fi
    if [[ -z "${DOMAINS_FILE:-}" ]] || [[ ! -s "${DOMAINS_FILE}" ]]; then
        LOG warn "no domains file - nothing for DNS/email intelligence to do"
        RECON_STAGE_NOTE="skipped (no domains)"
        return 0
    fi

    local d="${RECON_OUTDIR}/02-dns-email"
    mkdir -p "${d}"

    local domain
    while IFS= read -r domain; do
        [[ -n "${domain}" ]] || continue
        LOG info "DNS/email intelligence for ${domain}"
        run bash "${m365}" -d "${domain}" \
            --dns --srv --smtp --direct-send --osint \
            --json-out "${d}/${domain}.json" > "${d}/${domain}.log" 2>&1 ||
            LOG warn "m365 (dns/email) returned non-zero for ${domain}"
    done < "${DOMAINS_FILE}"

    LOG pass "DNS/email intelligence written to ${d}"
    return 0
}
