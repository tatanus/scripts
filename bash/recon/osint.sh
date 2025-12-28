#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : osint.sh
# DESCRIPTION  : Optional OSINT lookups (safe).
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-21
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-21 | Adam Compton | Initial creation
# =============================================================================

# Module dependencies (adjust as needed)
script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source "${script_dir}/common_utils.sh"
source "${script_dir}/dns_utils.sh"  2>/dev/null || true
source "${script_dir}/smtp_utils.sh" 2>/dev/null || true
source "${script_dir}/web_utils.sh"  2>/dev/null || true
source "${script_dir}/cloud_surface_utils.sh" 2>/dev/null || true
source "${script_dir}/json_utils.sh" 2>/dev/null || true

#==============================================================================
# OSINT (optional, safe)
#==============================================================================

###############################################################################
# do_osint_crtsh
# Query crt.sh for known certificates (public info).
# Arguments:
#   $1 - domain
# Output:
#   JSON object { crtsh: { query_used:string, http_status:string } }
# Notes:
#   - We intentionally do not parse crt.sh output here to avoid HTML/JSON
#     variability and brittle parsers. Instead we:
#       * build the standard subdomain query: %.example.com  (encoded as %25.)
#       * perform a lightweight reachability check
#       * emit the exact query URL for offline/interactive use
###############################################################################
function do_osint_crtsh() {
    local domain="${1}"
    local ua="${CURL_UA:-Mozilla/5.0}"
    # Use %.domain to include subdomains; encode '%' as '%25'
    #local q="https://crt.sh/?q=%25.${domain}&output=json"
    local q="https://crt.sh/?Identity=${domain}&output=json"

    info "OSINT: prepared crt.sh query for ${domain}."

    local code="000"
    code="$(run_with_timeout 6s curl -fsS -o /dev/null -w '%{http_code}' -m 6 --retry 0 \
        -A "${ua}" "${q}" 2> /dev/null || true)"
    [[ -z "${code}" ]] && code="000"

    jq -n --arg q "${q}" --arg code "${code}" '{ crtsh: { query_used: $q, http_status: $code } }'
}

