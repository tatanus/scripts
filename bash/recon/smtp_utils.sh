#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : smtp_utils.sh
# DESCRIPTION  : SMTP probing utilities
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
if [[ -n "${SMTP_UTILS_SH_LOADED:-}" ]]; then
    if ( return 0 2> /dev/null ); then
        return 0
    else
        : # executed as a script; continue
    fi
else
    SMTP_UTILS_SH_LOADED=1
fi

#----------------------------------------------------------------------------
# Required libs (adjust paths as needed)
#----------------------------------------------------------------------------
# shellcheck source=./common_utils.sh
. "./common_utils.sh"

###############################################################################
# smtp_open_banner
# Attempt to open TCP 25 and read the banner (nc -> openssl -> /dev/tcp).
# Arguments:
#   $1 - host
#   $2 - seconds timeout
# Output:
#   JSON object { method:"...", ok:bool, banner:"...", starttls:bool }
###############################################################################
function smtp_open_banner() {
    local host="${1}"
    local port="${2:-25}"
    local timeout_s="${3:-6}"

    info "SMTP: opening to ${host}:${port} ..."
    # Prefer openssl s_client for TLS if port is 587/465, else plain nc
    local out tmp rc
    tmp="$(mktemp)"
    if [[ "${port}" -eq 465 ]]; then
        run_with_timeout "${timeout_s}s" openssl s_client -connect "${host}:${port}" < /dev/null > "${tmp}" 2> /dev/null
        rc=$?
    else
        # Plain TCP banner (no data sent)
        run_with_timeout "${timeout_s}s" bash -c "exec 3<>/dev/tcp/${host}/${port}; head -n 1 <&3; exec 3<&- 3>&-" > "${tmp}" 2> /dev/null
        rc=$?
    fi
    if ((rc != 0)); then
        warn "SMTP connection failed (rc=${rc})."
        jq -n --arg host "${host}" --argjson port "${port}" '{smtp:{host:$host, port:$port, banner:null, error:"connect_failed"}}'
        rm -f "${tmp}" 2> /dev/null || true
        return 0
    fi

    out="$(tr -d '\r' < "${tmp}" | head -n 1)"
    rm -f "${tmp}" 2> /dev/null || true

    jq -n --arg host "${host}" --argjson port "${port}" --arg banner "${out}" \
        '{smtp:{host:$host, port:$port, banner:$banner}}'
}

###############################################################################
# do_smtp_probe
# For each MX host, attempt banner + STARTTLS discovery.
# Arguments:
#   $1 - domain
#   $2 - dns_server
# Output:
#   JSON object { smtp: { results: [ { mx, probe{...} } ] } }
###############################################################################
function do_smtp_probe() {
    local mx_host="${1}"
    local port="${2:-25}"

    local banner_json
    banner_json="$(smtp_open_banner "${mx_host}" "${port}")"

    # Try STARTTLS advertisement with EHLO (best-effort)
    local ehlo supports_starttls="false" code="0"
    ehlo="$(run_with_timeout 7s bash -c "exec 3<>/dev/tcp/${mx_host}/${port}; echo -e 'EHLO example.com\r' >&3; sleep 1; cat <&3 | head -n 10; exec 3<&- 3>&-" 2> /dev/null || true)"
    if echo "${ehlo}" | grep -qi 'STARTTLS'; then
        supports_starttls="true"
    fi
    if echo "${ehlo}" | head -n1 | grep -Eq '^2[0-9]{2}'; then
        code="$(echo "${ehlo}" | head -n1 | awk '{print $1}')"
    fi

    jq -n --argjson banner "${banner_json}" --arg s "${supports_starttls}" --arg code "${code}" '
      { smtp_probe:
        { banner: $banner.smtp
        , ehlo_supports_starttls: ($s=="true")
        , first_status: ($code|tonumber? // 0)
        } }'
}
