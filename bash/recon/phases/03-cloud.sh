#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 03-cloud.sh
# DESCRIPTION  : Phase 3 - Microsoft 365 / Entra ID / Azure surface discovery.
#                Wraps m365_recon_NG.sh (Entra posture, SharePoint/Teams/B2C/
#                SAML, Azure services, SaaS/IdP fingerprints). When a Graph
#                bearer token is supplied it also runs the authenticated
#                Microsoft Graph collectors (msgraph_recon.sh). Opt-in.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_cloud
###############################################################################
function run_phase_cloud() {
    local m365="${RECON_MODULE_DIR}/m365_recon_NG.sh"
    if [[ ! -f "${m365}" ]]; then
        LOG warn "m365_recon_NG.sh not found - skipping cloud/M365 discovery"
        RECON_STAGE_NOTE="skipped (module missing)"
        return 0
    fi
    if [[ -z "${DOMAINS_FILE:-}" ]] || [[ ! -s "${DOMAINS_FILE}" ]]; then
        LOG warn "no domains file - nothing for cloud/M365 discovery to do"
        RECON_STAGE_NOTE="skipped (no domains)"
        return 0
    fi

    local d="${RECON_OUTDIR}/03-cloud"
    mkdir -p "${d}"

    local domain args
    while IFS= read -r domain; do
        [[ -n "${domain}" ]] || continue
        LOG info "cloud/M365/Entra discovery for ${domain}"
        args=(-d "${domain}" --entra --sharepoint --teams --b2c --saml
            --azure-services --saas --cloud "${RECON_CLOUD_INSTANCE:-na}")
        # Authenticated Microsoft Graph collectors when a token is provided.
        if [[ -n "${RECON_MSGRAPH_TOKEN:-}" ]]; then
            LOG info "Graph token supplied - enabling authenticated collectors"
            args+=(--with-token "${RECON_MSGRAPH_TOKEN}" --graph-apps --mdi)
        fi
        run bash "${m365}" "${args[@]}" \
            --json-out "${d}/${domain}.json" > "${d}/${domain}.log" 2>&1 ||
            LOG warn "m365 (cloud) returned non-zero for ${domain}"
    done < "${DOMAINS_FILE}"

    LOG pass "cloud/M365/Entra results written to ${d}"
    return 0
}
