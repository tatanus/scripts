#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : web_utils.sh
# DESCRIPTION  : Web/HTTP utility function library
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
if [[ -n "${WEB_UTILS_SH_LOADED:-}" ]]; then
    if ( return 0 2> /dev/null ); then
        return 0
    else
        : # executed as a script; continue
    fi
else
    WEB_UTILS_SH_LOADED=1
fi

#----------------------------------------------------------------------------
# Required libs (adjust paths as needed)
#----------------------------------------------------------------------------
# shellcheck source=./common_utils.sh
. "./common_utils.sh"

#==============================================================================
# HTTP Defaults
#==============================================================================
# Generic "realistic" browser User-Agent for all curl requests
readonly CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

# =============================================================================
# Core HTTP helpers (curl wrappers)
# =============================================================================

###############################################################################
# http_status_only
# Return only the HTTP status code for a URL (string, e.g., "200").
# Arguments:
#   $1 - url
###############################################################################
function http_status_only() {
    local url="${1}"
    local code=""
    code="$(run_with_timeout 9s curl -fsS -o /dev/null -m 9 -A "${CURL_UA}" -w '%{http_code}' "${url}" 2> /dev/null || true)"
    if [[ -z "${code}" ]]; then
        code="000"
    fi
    printf '%s\n' "${code}"
}

###############################################################################
# http_post_xml_status_and_body
# POST an XML file, print status (first line) then response body (stdout).
# Arguments:
#   $1 - url
#   $2 - body_file (path to XML)
###############################################################################
function http_post_xml_status_and_body() {
    local url="${1}" body_file="${2}"
    local tmp=""
    tmp="$(mktemp)"
    local code="000"
    code="$(run_with_timeout 12s curl -fsS -m 12 -A "${CURL_UA}" -H 'Content-Type: text/xml; charset=utf-8' \
        --data-binary @"${body_file}" -w '%{http_code}' -o "${tmp}" "${url}" 2> /dev/null || true)"
    printf '%s\n' "${code}"
    cat "${tmp}" 2> /dev/null || true
    rm -f "${tmp}" 2> /dev/null || true
}

function head_with_bearer() {
    # Prints "code|true|headers" when WWW-Authenticate: Bearer present, else "code|false|headers".
    local url="$1"
    # force headers fetch, silence stderr to avoid noisy DNS/SSL logs
    local hdr
    hdr="$(curl -sI -m 7 -A "${CURL_UA}" "$url" 2> /dev/null || true)"
    local code
    code="$(printf '%s\n' "$hdr" | awk 'NR==1{print $2}')"
    if printf '%s' "$hdr" | grep -qiE '^www-authenticate:\s*Bearer\b'; then
        printf '%s|true|%s\n' "${code:-0}" "$hdr"
    else
        printf '%s|false|%s\n' "${code:-0}" "$hdr"
    fi
}
