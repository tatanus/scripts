#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : msgraph_recon.sh
# DESCRIPTION  : Microsoft Graph (authenticated) data collection helpers.
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
# Microsoft Graph (optional, authenticated)
#==============================================================================

###############################################################################
# _graph_get
#------------------------------------------------------------------------------
# PURPOSE:
#   Minimal helper to GET a Microsoft Graph URL with Bearer token auth and
#   JSON headers. Intended for use by collectors below.
#
# ARGUMENTS:
#   $1 - url    (full Graph endpoint)
#   $2 - token  (OAuth 2.0 access token with appropriate scopes)
#
# OUTPUT (stdout):
#   Raw response body (JSON) on success; empty string on error/timeout.
###############################################################################
function _graph_get() {
    local url="${1}"
    local token="${2}"

    run_with_timeout 15s curl -fsS -m 15 --retry 1 \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/json" \
        -H "ConsistencyLevel: eventual" \
        "${url}" 2> /dev/null || true
}

###############################################################################
# graph_get_paginated
#------------------------------------------------------------------------------
# PURPOSE:
#   Follow Microsoft Graph `@odata.nextLink` to accumulate items into a single
#   JSON array, up to an explicit limit (max_items). This avoids bringing the
#   universe when a tenant has thousands of apps/SPNs.
#
# ARGUMENTS:
#   $1 - url         (initial Graph collection URL, with any $select/$top)
#   $2 - token       (OAuth 2.0 access token)
#   $3 - max_items   (integer; stop after this many items)
#
# OUTPUT (stdout):
#   JSON array of items (possibly truncated to `max_items`).
###############################################################################
function graph_get_paginated() {
    local url="${1}"
    local token="${2}"
    local max_items="${3}"

    local items="[]"
    local next="${url}"
    local total=0

    while [[ -n "${next}" ]]; do
        local page
        page="$(_graph_get "${next}" "${token}")"
        if [[ -z "${page}" ]]; then
            break
        fi

        # Extract current page items and append.
        local page_items
        page_items="$(jq '.value // []' <<< "${page}" 2> /dev/null || echo '[]')"
        items="$(jq -s '.[0] + .[1]' <<< "${items}"$'\n'"${page_items}")"

        # Stop if we've reached the cap.
        total="$(jq 'length' <<< "${items}")"
        if [[ "${total}" -ge "${max_items}" ]]; then
            items="$(jq --argjson n "${max_items}" '.[0:$n]' <<< "${items}")"
            break
        fi

        # Follow next link if present.
        next="$(jq -r '."@odata.nextLink" // empty' <<< "${page}" 2> /dev/null || true)"
    done

    printf '%s\n' "${items}"
}

###############################################################################
# graph_collect_applications
#------------------------------------------------------------------------------
# PURPOSE:
#   Collect an unauthenticated **snapshot** of Azure AD **Applications** via
#   Microsoft Graph (requires a valid token). Intended for high-level inventory
#   (display name, appId, audience, created time).
#
# ARGUMENTS:
#   $1 - token       (OAuth 2.0 access token with Application.Read.All etc.)
#   $2 - max_items   (integer cap for pagination)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "graph": {
#       "applications": [ { "displayName":"...", "appId":"...", ... }, ... ],
#       "applications_total": <int>
#     }
#   }
###############################################################################
function graph_collect_applications() {
    local token="${1}"
    local max_items="${2}"

    info "Graph: collecting Applications snapshot (limit ${max_items}) ..."

    local url="https://graph.microsoft.com/v1.0/applications?\
\$select=displayName,appId,signInAudience,createdDateTime&\$top=999"

    local items
    items="$(graph_get_paginated "${url}" "${token}" "${max_items}")"

    jq -n \
        --argjson apps  "${items:-[]}" \
        --argjson total "$(jq 'length' <<< "${items}")" \
        '{ graph: { applications: $apps, applications_total: $total } }'
}

###############################################################################
# graph_collect_service_principals
#------------------------------------------------------------------------------
# PURPOSE:
#   Collect a snapshot of **Service Principals** (SPNs) via Microsoft Graph to
#   support inventory and downstream inferences (e.g., Defender for Identity).
#
# ARGUMENTS:
#   $1 - token       (OAuth 2.0 access token with ServicePrincipal.Read.All etc.)
#   $2 - max_items   (integer cap for pagination)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "graph": {
#       "service_principals":     [ { "displayName":"...", "appId":"...", ... }, ... ],
#       "service_principals_total": <int>
#     }
#   }
###############################################################################
function graph_collect_service_principals() {
    local token="${1}"
    local max_items="${2}"

    info "Graph: collecting Service Principals snapshot (limit ${max_items}) ..."

    local url="https://graph.microsoft.com/v1.0/servicePrincipals?\
\$select=displayName,appId,appOwnerOrganizationId,signInAudience&\$top=999"

    local items
    items="$(graph_get_paginated "${url}" "${token}" "${max_items}")"

    jq -n \
        --argjson sps   "${items:-[]}" \
        --argjson total "$(jq 'length' <<< "${items}")" \
        '{ graph: { service_principals: $sps, service_principals_total: $total } }'
}

###############################################################################
# graph_infer_mdi_from_service_principals
#------------------------------------------------------------------------------
# PURPOSE:
#   Infer **Microsoft Defender for Identity** (MDI) presence by scanning a
#   Service Principals list for historic/current product names.
#   This is heuristic and unauthenticated beyond the SPN listing.
#
# ARGUMENTS:
#   $1 - sps_json   (a merged JSON object that includes
#                    .graph.service_principals array)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "defender_for_identity": {
#       "present": true|false,
#       "matches": [ { "displayName":"...", "appId":"..." }, ... ],
#       "note": "inferred from service principals"
#     }
#   }
###############################################################################
function graph_infer_mdi_from_service_principals() {
    local sps_json="${1}"

    info "Graph: inferring Microsoft Defender for Identity presence from service principals ..."

    # Filter for common branding variants to reduce false negatives.
    local mdi_matches
    mdi_matches="$(
        jq '[ .graph.service_principals[]? 
                | select((.displayName // "") 
                    | test("(?i)(Defender\\s*for\\s*Identity|Azure\\s*Advanced\\s*Threat\\s*Protection)")) 
                | {displayName,appId} ]' \
            <<< "${sps_json}" 2> /dev/null || echo '[]'
    )"

    local present="false"
    if [[ "$(jq 'length' <<< "${mdi_matches}")" -gt 0 ]]; then
        present="true"
    fi

    jq -n \
        --argjson matches "${mdi_matches:-[]}" \
        --arg present "${present}" \
        '{ defender_for_identity: { present: ($present=="true"), matches: $matches, note:"inferred from service principals" } }'
}

