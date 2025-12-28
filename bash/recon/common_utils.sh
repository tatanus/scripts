#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : common_utils.sh
# DESCRIPTION  : Common utility function library
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
if [[ -n "${COMMON_UTILS_SH_LOADED:-}" ]]; then
    if ( return 0 2> /dev/null); then
        return 0
    else
        : # executed as a script; continue
    fi
else
    COMMON_UTILS_SH_LOADED=1
fi

#==============================================================================
# Color Setup
#==============================================================================
if [[ -t 1 && -n "$(command -v tput)" ]]; then
    blue=$(tput setaf 4)
    light_blue=$(tput setaf 6)
    light_green=$(tput setaf 2)
    light_red=$(tput setaf 1)
    yellow=$(tput setaf 3)
    orange=$(tput setaf 214 2> /dev/null || tput setaf 3)
    white=$(tput setaf 7)
    reset=$(tput sgr0)
else
    blue="\033[0;34m"
    light_blue="\033[1;36m"
    light_green="\033[0;32m"
    light_red="\033[0;31m"
    yellow="\033[0;33m"
    orange="\033[1;33m"
    white="\033[0;37m"
    reset="\033[0m"
fi

#==============================================================================
# Logging (lightweight; writes to stderr by default)
#==============================================================================
ENABLE_COLOR="${ENABLE_COLOR:-1}"

function log_msg() {
    local level="${1}"
    local message="${2}"
    local color prefix color_prefix color_reset
    case "${level}" in
        INFO)
            color="${blue}"
            prefix="[* INFO  ]"
            ;;
        WARN)
            color="${yellow}"
            prefix="[! WARN  ]"
            ;;
        ERROR | FAIL)
            color="${light_red}"
            prefix="[- ERROR ]"
            ;;
        PASS | SUCCESS)
            color="${light_green}"
            prefix="[+ PASS  ]"
            ;;
        DEBUG)
            color="${orange}"
            prefix="[# DEBUG ]"
            ;;
        *)
            color="${white}"
            prefix="[  LOG   ]"
            ;;
    esac
    if [[ "${ENABLE_COLOR}" -eq 1 ]]; then
        color_prefix="${color}"
        color_reset="${reset}"
    else
        color_prefix=""
        color_reset=""
    fi
    printf '%b%s%b %s\n' "${color_prefix}" "${prefix}" "${color_reset}" "${message}" >&2
}
function info()  { log_msg "INFO"  "${1}"; }
function warn()  { log_msg "WARN"  "${1}"; }
function error() { log_msg "ERROR" "${1}"; }
function fail()  { log_msg "FAIL"  "${1}"; }
function pass()  { log_msg "PASS"  "${1}"; }
function success()  { log_msg "SUCCESS"  "${1}"; }
function debug() { log_msg "DEBUG" "${1}"; }

#==============================================================================
# Helper Functions
#==============================================================================

###############################################################################
# have_cmd
# Check if a command exists.
# Arguments:
#   $1 - command name
# Returns:
#   0 if exists, 1 otherwise
###############################################################################
function have_cmd() {
    command -v "${1}" > /dev/null 2>&1
}

###############################################################################
# _fmt_bool_yn
#------------------------------------------------------------------------------
# PURPOSE: Format a string "true"/"false" (or 1/0) as "Yes"/"No".
###############################################################################
function _fmt_bool_yn() {
    local v="${1:-false}"
    if [[ "${v}" == "true" || "${v}" == "1" ]]; then
        printf '%s\n' "Yes"
    else
        printf '%s\n' "No"
    fi
}

###############################################################################
# _join_lines_or_na
#------------------------------------------------------------------------------
# PURPOSE: Read lines from stdin, join with comma+space, or print "N/A" if empty.
###############################################################################
function _join_lines_or_na() {
    local joined
    joined="$(paste -sd ', ' - 2> /dev/null || true)"
    if [[ -n "${joined}" ]]; then
        printf '%s\n' "${joined}"
    else
        printf '%s\n' "N/A"
    fi
}

###############################################################################
# validate_tools
# Ensure at least one tool per capability is available (with fallbacks).
# Arguments:
#   none (uses local lists)
###############################################################################
function validate_tools() {
    local -a need_any_dns=("dig" "host")
    local -a need_http=("curl")
    local -a need_json=("jq")
    local -a need_timeout=("timeout")
    local -a need_smtp_any=("nc" "openssl") # /dev/tcp used as last resort

    local ok=1

    # DNS
    local dns_ok=1 http_ok=1 json_ok=1 tmo_ok=1 smtp_ok=1
    for c in "${need_any_dns[@]}"; do have_cmd "${c}" && dns_ok=0; done
    have_cmd "curl" && http_ok=0
    have_cmd "jq" && json_ok=0
    have_cmd "timeout" && tmo_ok=0
    for c in "${need_smtp_any[@]}"; do have_cmd "${c}" && smtp_ok=0; done

    if ((dns_ok != 0)); then
        error "Missing DNS client (need one of: dig, host)."
        ok=0
    fi
    if ((http_ok != 0)); then
        error "Missing HTTP client: curl."
        ok=0
    fi
    if ((json_ok != 0)); then
        error "Missing JSON processor: jq."
        ok=0
    fi
    if ((tmo_ok != 0)); then
        error "Missing timeout(1) command."
        ok=0
    fi
    if ((smtp_ok != 0)); then
        warn "Neither 'nc' nor 'openssl' found. SMTP banner tests will fall back to /dev/tcp (best-effort)."
    fi

    ((ok == 1))   || die 1 "Required tools missing."
}

###############################################################################
# run_with_timeout
# Run a command with timeout; returns 124 on timeout.
# Arguments:
#   $1 - seconds
#   $@ - command
###############################################################################
function run_with_timeout() {
    local seconds="${1}"
    shift
    timeout --preserve-status --signal=TERM "${seconds}" "$@"
}
