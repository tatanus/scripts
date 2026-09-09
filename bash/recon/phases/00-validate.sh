#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 00-validate.sh
# DESCRIPTION  : Phase 0 - validate the engagement environment and inputs,
#                build the RECON directory layout, expand the target scope,
#                and preflight the tools the selected phases will need.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_validate
# Purpose : Validate env vars, create output tree, expand targets.txt.
# Returns : 0 on success; RECON_ERR_INPUT on unrecoverable input problems.
###############################################################################
function run_phase_validate() {
    LOG info "validating environment and inputs"

    if [[ -z "${RECON_ENGAGEMENT_DIR:-}" ]]; then
        LOG error "RECON_ENGAGEMENT_DIR is not set"
        return "${RECON_ERR_INPUT}"
    fi

    need_file "${TARGETS_FILE}" || return "${RECON_ERR_INPUT}"

    local dir
    for dir in "${RECON_OUTDIR}" "${RECON_OUTDIR}/discovery" \
        "${RECON_ENGAGEMENT_DIR}/OUTPUT/TEE" "${RECON_ENGAGEMENT_DIR}/LOGS" \
        "${RECON_STATE_DIR}"; do
        [[ -d "${dir}" ]] || mkdir -p "${dir}" || {
            LOG error "failed to create ${dir}"
            return "${RECON_ERR_INPUT}"
        }
    done

    # Expand the scan scope once; downstream phases reuse the flat IP list.
    local expanded="${RECON_OUTDIR}/targets-expanded.txt"
    local hosts="${RECON_OUTDIR}/targets-hostnames.txt"
    local stats
    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]]; then
        stats="$(scope_expand "${TARGETS_FILE}" "${RECON_MAX_HOSTS:-8192}" \
            "${expanded}" "${hosts}" 2> /dev/null)" || {
            LOG error "failed to expand ${TARGETS_FILE}"
            return "${RECON_ERR_INPUT}"
        }
        # scope_expand prints "<ips> <hosts> <over-cap> <unparsed>". Re-admit
        # space to IFS (the suite runs under IFS=$'\n\t') so the counts split.
        local IFS=$' \t\n'
        # shellcheck disable=SC2086
        set -- ${stats}
        LOG pass "expanded scope: ${1:-0} IP(s), ${2:-0} hostname(s)"
        [[ "${3:-0}" -gt 0 ]] && LOG warn "hit --max-hosts cap (${RECON_MAX_HOSTS}); ${3} address(es) dropped"
        [[ "${4:-0}" -gt 0 ]] && LOG warn "${4} unparsed scope line(s) - review ${TARGETS_FILE}"
        export RECON_EXPANDED_TARGETS="${expanded}"
    fi

    # Domains file is optional: without it, phase 01 runs IP->domain discovery.
    if [[ -n "${DOMAINS_FILE:-}" ]] && [[ -s "${DOMAINS_FILE}" ]]; then
        LOG info "domains file: $(count_lines "${DOMAINS_FILE}") root domain(s)"
    else
        LOG info "no domains file - phase 01 will derive candidates from the IP scope"
    fi

    LOG info "scope model: domains->enumeration only, targets->scanning only (kept separate)"
    return 0
}
