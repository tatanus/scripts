#!/usr/bin/env bash
###############################################################################
# NAME         : core.sh  (m365 library)
# DESCRIPTION  : Foundation layer for the canonical M365 / Entra / Azure OSINT
#                library. Hard-depends on common_core (Bash 4+): it sources
#                common_core's util.sh and then provides the small helpers the
#                M365 modules need that common_core does not ship (JSON
#                composition, HTTP/SMTP probes, cloud-endpoint maps) plus thin
#                delegating shims that route the suite's legacy helper names
#                (have_cmd, run_with_timeout, dns_query_generic, resolve_host)
#                onto common_core primitives (cmd::exists, platform::timeout,
#                dns::). This replaces the old common_utils.sh + dns_utils.sh +
#                json/web/smtp/cloud util files, so there is one source of
#                truth backed by common_core.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-17
###############################################################################

set -uo pipefail
IFS=$'\n\t'

#===============================================================================
# Library Guard
#===============================================================================
if [[ -n "${M365_CORE_SH_LOADED:-}" ]]; then
    if (return 0 2> /dev/null); then
        return 0
    fi
else
    M365_CORE_SH_LOADED=1
fi

#===============================================================================
# common_core (hard dependency)
#-------------------------------------------------------------------------------
# The whole suite now relies on common_core for logging (info/warn/error/pass/
# debug/fail), command detection (cmd::exists), DNS (dns::), and the
# cross-platform timeout (platform::timeout). Source it once here.
#===============================================================================
if ! declare -F cmd::exists > /dev/null 2>&1; then
    _cc="${COMMON_CORE_LIB:-${HOME}/.config/bash/lib/common_core}/util.sh"
    if [[ -r "${_cc}" ]]; then
        # shellcheck source=/dev/null
        source "${_cc}"
    fi
    unset _cc
fi
if ! declare -F cmd::exists > /dev/null 2>&1; then
    printf '[ERROR] m365 core.sh: common_core not found (set COMMON_CORE_LIB or install it at ~/.config/bash/lib/common_core)\n' >&2
    if (return 0 2> /dev/null); then return 1; else exit 1; fi
fi

#===============================================================================
# Defaults
#===============================================================================
: "${DNS_DEFAULT_SERVER:=1.1.1.1}"
# Realistic browser User-Agent shared by all curl requests.
readonly CURL_UA="${CURL_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36}"

#===============================================================================
# Compatibility shims onto common_core
#===============================================================================

# have_cmd <name> : legacy alias for cmd::exists (57 call sites suite-wide).
function have_cmd() { cmd::exists "${1}"; }

# success <msg> : the suite uses success(); common_core exposes pass().
if ! declare -F success > /dev/null 2>&1; then
    function success() { pass "${1}"; }
fi

# die <code> <msg...> : abort with an error message (was undefined suite-wide).
function die() {
    local code="${1:-1}"
    shift || true
    error "$*"
    exit "${code}"
}

###############################################################################
# run_with_timeout <seconds> <cmd...>
#------------------------------------------------------------------------------
# Quiet cross-platform timeout wrapper. Prefers common_core's platform::timeout
# (handles gtimeout/timeout portability); falls back to timeout(1). Unlike
# cmd::timeout it emits no pass/fail log line and preserves the child's exit
# status (124 on timeout), which several callers inspect.
###############################################################################
function run_with_timeout() {
    local seconds="${1}"
    shift || true
    if declare -F platform::timeout > /dev/null 2>&1; then
        platform::timeout "${seconds}" "$@"
    elif cmd::exists timeout; then
        timeout --preserve-status --signal=TERM "${seconds}" "$@"
    else
        "$@"
    fi
}

#===============================================================================
# Tool validation (recon-specific capability check)
#===============================================================================
function validate_tools() {
    local ok=1
    if ! have_cmd dig && ! have_cmd host; then
        error "Missing DNS client (need one of: dig, host)."
        ok=0
    fi
    if ! have_cmd curl; then
        error "Missing HTTP client: curl."
        ok=0
    fi
    if ! have_cmd jq; then
        error "Missing JSON processor: jq."
        ok=0
    fi
    if ! have_cmd timeout && ! declare -F platform::timeout > /dev/null 2>&1; then
        warn "No timeout(1) and no platform::timeout; long-running probes may hang."
    fi
    if ! have_cmd nc && ! have_cmd openssl; then
        warn "Neither 'nc' nor 'openssl' found. SMTP banner tests fall back to /dev/tcp (best-effort)."
    fi
    ((ok == 1)) || die 1 "Required tools missing."
}

#===============================================================================
# Small formatting helpers
#===============================================================================

# _fmt_bool_yn <true|false|1|0> -> "Yes"/"No"
function _fmt_bool_yn() {
    local v="${1:-false}"
    if [[ "${v}" == "true" || "${v}" == "1" ]]; then
        printf '%s\n' "Yes"
    else
        printf '%s\n' "No"
    fi
}

# _join_lines_or_na : join stdin lines with ", " or print "N/A" if empty.
function _join_lines_or_na() {
    local joined
    joined="$(paste -sd ', ' - 2> /dev/null || true)"
    if [[ -n "${joined}" ]]; then
        printf '%s\n' "${joined}"
    else
        printf '%s\n' "N/A"
    fi
}

#===============================================================================
# DNS helpers (adapters over common_core dns::)
#===============================================================================

###############################################################################
# dns_query_generic <TYPE> <name> [dns_server]
#------------------------------------------------------------------------------
# JSON-array DNS lookup used across the suite. Delegates the actual query to
# common_core's dns::query (dig +short) and wraps the plain output as a JSON
# array of strings, preserving the historic contract.
###############################################################################
function dns_query_generic() {
    local rtype="${1}" name="${2}" dns_server="${3:-${DNS_DEFAULT_SERVER}}"
    dns::query "${rtype}" "${name}" "${dns_server}" 2> /dev/null |
        tr -d '\r' | sed '/^$/d' |
        jq -R -s 'split("\n") | map(select(length>0))'
}

###############################################################################
# resolve_host <name> : 0 if the name has any A/AAAA/CNAME, else 1 (quiet).
###############################################################################
function resolve_host() {
    local h="${1}"
    {
        dns::a "${h}"
        dns::aaaa "${h}"
        dns::cname "${h}"
    } 2> /dev/null | grep -q .
}

#===============================================================================
# JSON composition helpers
#===============================================================================

# json_kv : placeholder kept for API parity (callers use jq -n directly).
function json_kv() { :; }

###############################################################################
# json_merge : shallow-merge JSON objects (later wins) with deep-merge of the
# azure_services sub-structure so per-module fragments do not clobber each
# other. Reads objects from args, else from stdin.
###############################################################################
function json_merge() {
    # shellcheck disable=SC2016  # jq program: single-quotes are intentional
    local prog='
      reduce .[] as $i (
        {};
        . * $i
        | .azure_services =
            ( (.azure_services // {}) + ($i.azure_services // {}) )
        | .azure_services.hints =
            ((.azure_services.hints // []) + ($i.azure_services.hints // []))
        | .azure_services.storage_accounts =
            ((.azure_services.storage_accounts // []) + ($i.azure_services.storage_accounts // []))
        | .azure_services.power_apps =
            ((.azure_services.power_apps // []) + ($i.azure_services.power_apps // []))
        | .azure_services.cdn_endpoints =
            ((.azure_services.cdn_endpoints // []) + ($i.azure_services.cdn_endpoints // []))
        | .azure_services.app_services =
            ((.azure_services.app_services // {}) + ($i.azure_services.app_services // {}))
      )'
    if (("$#" > 0)); then
        jq -s "${prog}" <<< "$(printf '%s\n' "$@")"
    else
        jq -s "${prog}"
    fi
}

# json_output : merge all collected JSON fragments into one final object.
function json_output() { json_merge "$@"; }

#===============================================================================
# HTTP helpers (curl wrappers)
#===============================================================================

# http_status_only <url> : print only the HTTP status code (e.g. "200"/"000").
function http_status_only() {
    local url="${1}"
    local code=""
    code="$(run_with_timeout 9s curl -fsS -o /dev/null -m 9 -A "${CURL_UA}" -w '%{http_code}' "${url}" 2> /dev/null || true)"
    [[ -z "${code}" ]] && code="000"
    printf '%s\n' "${code}"
}

# http_post_xml_status_and_body <url> <body_file> : status (line1) then body.
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

# head_with_bearer <url> : "code|true|headers" if WWW-Authenticate: Bearer, else false.
function head_with_bearer() {
    local url="${1}"
    local hdr
    hdr="$(curl -sI -m 7 -A "${CURL_UA}" "${url}" 2> /dev/null || true)"
    local code
    code="$(printf '%s\n' "${hdr}" | awk 'NR==1{print $2}')"
    if printf '%s' "${hdr}" | grep -qiE '^www-authenticate:\s*Bearer\b'; then
        printf '%s|true|%s\n' "${code:-0}" "${hdr}"
    else
        printf '%s|false|%s\n' "${code:-0}" "${hdr}"
    fi
}

#===============================================================================
# SMTP helpers (baseline; smtp_recon.sh may override with richer versions)
#===============================================================================

# smtp_open_banner <host> [port] [timeout_s] : JSON { smtp:{...} }
function smtp_open_banner() {
    local host="${1}"
    local port="${2:-25}"
    local timeout_s="${3:-6}"

    info "SMTP: opening to ${host}:${port} ..."
    local out tmp rc
    tmp="$(mktemp)"
    if [[ "${port}" -eq 465 ]]; then
        run_with_timeout "${timeout_s}s" openssl s_client -connect "${host}:${port}" < /dev/null > "${tmp}" 2> /dev/null
        rc=$?
    else
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

# do_smtp_probe <mx_host> [port] : JSON { smtp_probe:{...} }
function do_smtp_probe() {
    local mx_host="${1}"
    local port="${2:-25}"

    local banner_json
    banner_json="$(smtp_open_banner "${mx_host}" "${port}")"

    local ehlo supports_starttls="false" code="0"
    ehlo="$(run_with_timeout 7s bash -c "exec 3<>/dev/tcp/${mx_host}/${port}; printf '%b\n' 'EHLO example.com\r' >&3; sleep 1; cat <&3 | head -n 10; exec 3<&- 3>&-" 2> /dev/null || true)"
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

#===============================================================================
# Cloud endpoint helpers
#===============================================================================

# _azure_hint_from_cname <target> : cdn|storage|app_service|unknown
function _azure_hint_from_cname() {
    local target="${1}"
    if grep -Eq 'azure(edge|fd)\.net$' <<< "${target}"; then
        printf '%s\n' "cdn"
        return 0
    fi
    if grep -Eq 'blob\.core\.windows\.net$' <<< "${target}"; then
        printf '%s\n' "storage"
        return 0
    fi
    if grep -Eq 'azurewebsites\.net$' <<< "${target}"; then
        printf '%s\n' "app_service"
        return 0
    fi
    printf '%s\n' "unknown"
}

# _domain_prefix <domain> : leftmost label.
function _domain_prefix() {
    local domain="${1}"
    printf '%s\n' "${domain%%.*}"
}

# get_cloud_endpoints <na|gov|china> : "login|outlook|autodiscover|eop_suffix"
function get_cloud_endpoints() {
    local cloud="${1}"
    local login_host="" outlook_host="" autod_global="" eop_suffix=""
    case "${cloud}" in
        gov | GOV | Gov)
            login_host="login.microsoftonline.us"
            outlook_host="outlook.office365.us"
            autod_global="autodiscover-s.office365.us"
            eop_suffix=".mail.protection.office365.us"
            ;;
        china | cn | CN | China)
            login_host="login.partner.microsoftonline.cn"
            outlook_host="partner.outlook.cn"
            autod_global="autodiscover.partner.outlook.cn"
            eop_suffix=".mail.protection.partner.outlook.cn"
            ;;
        *)
            # Default to NA.
            login_host="login.microsoftonline.com"
            outlook_host="outlook.office365.com"
            autod_global="autodiscover-s.outlook.com"
            eop_suffix=".mail.protection.outlook.com"
            ;;
    esac
    printf '%s|%s|%s|%s\n' "${login_host}" "${outlook_host}" "${autod_global}" "${eop_suffix}"
}
