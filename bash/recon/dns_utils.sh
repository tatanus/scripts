#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : dns_utils.sh
# DESCRIPTION  : DNS utility function library
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-21
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-21 | Adam Compton | Initial creation
# =============================================================================

#----------------------------------------------------------------------------
# Guard to prevent multiple sourcing (portable; works on macOS Bash 3.2)
#----------------------------------------------------------------------------
if [[ -n "${DNS_UTILS_SH_LOADED:-}" ]]; then
    if ( return 0 2> /dev/null); then
        return 0
    else
        : # executed as a script; continue
    fi
else
    DNS_UTILS_SH_LOADED=1
fi

#----------------------------------------------------------------------------
# Required libs (adjust paths as needed)
#----------------------------------------------------------------------------
# shellcheck source=./common_utils.sh
. "./common_utils.sh"

###############################################################################
# dns_query_generic
# Query DNS using dig (preferred) then host fallback.
# Arguments:
#   $1 - record type (A, AAAA, MX, TXT, CNAME, SRV)
#   $2 - name (e.g., example.com or _dmarc.example.com)
#   $3 - dns_server (ip or resolvable name)
# Output:
#   JSON array of strings (answers similar to 'dig +short')
###############################################################################
function dns_query_generic() {
    local rtype="${1}"
    local name="${2}"
    local dns_server="${3}"

    local raw=""
    if have_cmd "dig"; then
        raw="$(run_with_timeout 7s dig +short "${name}" "${rtype}" @"${dns_server}" 2> /dev/null || true)"
    elif have_cmd "host"; then
        # Normalize 'host' output into dig-like +short lines.
        # shellcheck disable=SC2016
        raw="$(run_with_timeout 7s host -t "${rtype}" "${name}" "${dns_server}" 2> /dev/null | awk -v t="${rtype}" '
            BEGIN { IGNORECASE=1 }
            t ~ /^A$/      && /has address/           { print $NF }
            t ~ /^AAAA$/   && /has IPv6 address/      { print $NF }
            t ~ /^CNAME$/  && /(is an alias for|alias for)/ { print $NF }
            t ~ /^MX$/     && /handled by/ {
                # e.g., example.com mail is handled by 10 mx.example.com.
                pref=$(NF-1); host=$NF; sub(/\.$/,"",host); print pref" "host
            }
            t ~ /^TXT$/    && /descriptive text/ {
                # keep raw text content (quotes may be present)
                sub(/.*descriptive text is /,""); print
            }
            t ~ /^SRV$/    && /has SRV record/ {
                # e.g., _sip._tls.example.com has SRV record 100 1 443 sipdir.online.lync.com.
                n=NF; target=$NF; sub(/\.$/, "", target);
                port=$(NF-1); weight=$(NF-2); priority=$(NF-3);
                print priority" "weight" "port" "target
            }
        ' || true)"
    fi

    printf '%s\n' "${raw}" \
        | tr -d '\r' \
        | sed '/^$/d' \
        | jq -R -s 'split("\n") | map(select(length>0))'
}

function resolve_host() {
    # Returns 0 if name has any A/AAAA/CNAME, else 1. Quiet on failure.
    local h="$1"
    if command -v dig > /dev/null 2>&1; then
        dig +time=2 +tries=1 +short "$h" A AAAA CNAME 2> /dev/null | grep -q .
    else
        # host(1) fallback
        host "$h" 2> /dev/null | grep -qE 'has address|alias for|IPv6 address'
    fi
}
