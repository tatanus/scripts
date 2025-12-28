#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : smtp_recon.sh
# DESCRIPTION  : SMTP banner/probing and direct-send evaluation.
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-21
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-21 | Adam Compton | Initial creation
# =============================================================================

# Module dependencies (adjust as needed)
script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
source "${script_dir}/common_utils.sh"
source "${script_dir}/dns_utils.sh"             2> /dev/null || true
source "${script_dir}/smtp_utils.sh"            2> /dev/null || true
source "${script_dir}/web_utils.sh"             2> /dev/null || true
source "${script_dir}/cloud_surface_utils.sh"   2> /dev/null || true
source "${script_dir}/json_utils.sh"            2> /dev/null || true

#==============================================================================
# SMTP Probing
#==============================================================================

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
    local seconds="${2}"
    local domain="${3:-example.com}"

    local method="" ok="false" banner="" starttls="false"

    if have_cmd "nc"; then
        method="nc"
        # Try plain (banner), then probe STARTTLS by issuing EHLO
        banner="$(run_with_timeout "${seconds}s" bash -c "printf '' | nc -w ${seconds} ${host} 25 2>/dev/null | head -n 1" || true)"
        if [[ -n "${banner}" ]]; then
            ok="true"
            # STARTTLS probe
            if run_with_timeout "${seconds}s" bash -c "printf 'EHLO ${domain}\r\n' | nc -w ${seconds} ${host} 25 2>/dev/null | grep -qi 'STARTTLS'" > /dev/null 2>&1; then
                starttls="true"
            fi
        fi
    fi

    if [[ "${ok}" != "true" ]] && have_cmd "openssl"; then
        method="openssl"
        # Use s_client with -starttls smtp to fetch capabilities, suppress cert verification
        local full
        full="$(run_with_timeout "${seconds}s" bash -c "printf 'QUIT\r\n' | openssl s_client -starttls smtp -crlf -ign_eof -connect ${host}:25 2>/dev/null" || true)"
        # Banner often present in the session transcript
        banner="$(printf '%s\n' "${full}" | grep -E '^[0-9]{3}[- ]' | head -n 1 || true)"
        if [[ -n "${full}" ]]; then
            ok="true"
            if grep -qi 'STARTTLS' <<< "${full}"; then
                starttls="true"
            fi
        fi
    fi

    if [[ "${ok}" != "true" ]]; then
        method="/dev/tcp"
        # Best-effort: bash TCP redirection (no STARTTLS capability parsing)
        # shellcheck disable=SC2129
        {
            exec 3<> "/dev/tcp/${host}/25" || true
            # read banner
            if read -r -t "${seconds}" banner_line <&3; then
                banner="${banner_line}"
                ok="true"
            fi
            # try EHLO to maybe see STARTTLS
            printf 'EHLO %s\r\n' "${domain}" >&3 || true
            if read -r -t "${seconds}" banner_line <&3; then
                if grep -qi 'STARTTLS' <<< "${banner_line}"; then
                    starttls="true"
                fi
            fi
            printf 'QUIT\r\n' >&3 || true
            exec 3>&-
        } 2> /dev/null || true
    fi

    jq -n \
        --arg method "${method}" \
        --arg banner "${banner}" \
        --arg ok "${ok}" \
        --arg starttls "${starttls}" \
        '{ method:$method, ok: ($ok=="true"), banner:$banner, starttls: ($starttls=="true") }'
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
    local domain="${1}"
    local dns_server="${2}"

    info "SMTP: probing MX hosts for ${domain} ..."
    local mx_rr
    mx_rr="$(dns_query_generic "MX" "${domain}" "${dns_server}")"

    # Parse into host list (handle "pref host")
    local mx_hosts
    mx_hosts="$(printf '%s\n' "${mx_rr}" | jq '[ .[] | capture("(?<pref>^[0-9]+)\\s+(?<host>.+)$")? // {host:.} | .host | rtrimstr(".") ]')"

    local results="[]"
    local host count
    count="$(jq 'length' <<< "${mx_hosts}")"
    if [[ "${count}" -gt 0 ]]; then
        for host in $(jq -r '.[]' <<< "${mx_hosts}"); do
            debug "SMTP: checking ${host} ..."
            local probe
            probe="$(smtp_open_banner "${host}" "7" "${domain}")"
            results="$(jq -n --arg host "${host}" --argjson p "${probe}" --argjson cur "${results}" \
                '$cur + [ { mx:$host, probe:$p } ]')"
        done
    fi

    jq -n --argjson results "${results}" '{ smtp: { results: $results } }'
}

#==============================================================================
# Direct-send probing (improved)
#==============================================================================

###############################################################################
# _rcpt_code_from_transcript
# Extract the numeric reply code corresponding to the RCPT TO command.
# Requires insertion of markers #--AFTER_MAIL-- and #--AFTER_RCPT-- in the stream.
# stdin : full transcript
# stdout: numeric code or empty
###############################################################################
_rcpt_code_from_transcript() {
    awk '
    /#--AFTER_RCPT--/ { seen_rcpt=1; next }
    /^[0-9][0-9][0-9][ -]/ && seen_rcpt && rcpt=="" { rcpt=$1 }
    END { if (rcpt!="") print rcpt }
  '
}

###############################################################################
# _supports_starttls_nc
# Quick capability sniff with EHLO over plaintext using nc.
# Returns 0 if STARTTLS advertised, 1 otherwise.
###############################################################################
function _supports_starttls_nc() {
    local domain="${1}"
    local mx_host="${2}"
    local seconds="${3:-7}"
    local caps
    caps="$(run_with_timeout "${seconds}s" bash -c "
        { printf 'EHLO ${domain}\r\nQUIT\r\n'; } | nc -w ${seconds} ${mx_host} 25 2>/dev/null
    " || true)"
    if grep -qi 'STARTTLS' <<< "${caps}"; then return 0; fi
    return 1
}

###############################################################################
# do_direct_send_probe
# Attempt a minimal SMTP dialog (no DATA) to see RCPT policy.
# Prefers STARTTLS if advertised; otherwise plaintext. HELO fallback if EHLO
# not recognized (rare).
# Arguments:
#   $1 - domain
#   $2 - mx_host
#   $3 - seconds timeout
# Output:
#   JSON { mx, method, tls:bool, smtp_codes:{ehlo?,helo?,mail?,rcpt?}, accepted:bool, reason, transcript }
###############################################################################
function do_direct_send_probe() {
    local domain="${1}"
    local mx_host="${2}"
    local seconds="${3:-7}"

    local method="plaintext" tls="false" transcript="" rcpt_code="" reason="" accepted="false"
    local supports_starttls=1

    if have_cmd "nc"; then
        if _supports_starttls_nc "${domain}" "${mx_host}" "${seconds}"; then supports_starttls=0; fi
    fi

    if [[ ${supports_starttls} -eq 0 ]] && have_cmd "openssl"; then
        method="starttls"
        tls="true"

        # STARTTLS path (one-shot post-TLS dialog; s_client negotiates TLS on connect)
        transcript="$(run_with_timeout "${seconds}s" bash -c "
          {
            printf 'EHLO %s\r\n' \"${domain}\"
            printf 'MAIL FROM:<doesnotexistuser@%s>\r\n#--AFTER_MAIL--\r\n' \"${domain}\"
            printf 'RCPT TO:<postmaster@%s>\r\n#--AFTER_RCPT--\r\n' \"${domain}\"
            printf 'QUIT\r\n'
          } | openssl s_client -starttls smtp -crlf -quiet -ign_eof -connect ${mx_host}:25 2>/dev/null
        " || true)"
    else
        if have_cmd "nc"; then
            transcript="$(run_with_timeout "${seconds}s" bash -c "
              {
                exec 3<>/dev/tcp/${mx_host}/25
                end_banner=0
                deadline=$((SECONDS + ${seconds}))
                while IFS= read -r -t 1 ln <&3; do
                  echo \"\${ln}\"
                  if [[ \"\${ln}\" =~ ^220[[:space:]] ]]; then end_banner=1; break; fi
                  [[ \${SECONDS} -ge \${deadline} ]] && break
                done
                [[ \${end_banner} -eq 1 ]] || sleep 1
                printf 'EHLO %s\r\n' \"${domain}\" >&3
                printf 'MAIL FROM:<doesnotexistuser@%s>\r\n#--AFTER_MAIL--\r\n' \"${domain}\" >&3
                printf 'RCPT TO:<postmaster@%s>\r\n#--AFTER_RCPT--\r\n' \"${domain}\" >&3
                printf 'QUIT\r\n' >&3
                while IFS= read -r -t 1 ln <&3; do echo \"\${ln}\"; done
                exec 3>&-
              } 2>/dev/null
            " || true)"
            # EHLO unrecognized? retry with HELO
            if grep -Eq '^5(00|02)[ -].*EHLO' <<< "${transcript}"; then
                transcript="$(run_with_timeout "${seconds}s" bash -c "
                    {
                        printf 'HELO ${domain}\r\n'
                        printf 'MAIL FROM:<doesnotexistuser@${domain}>\r\n#--AFTER_MAIL--\r\n'
                        printf 'RCPT TO:<postmaster@${domain}>\r\n#--AFTER_RCPT--\r\n'
                        printf 'QUIT\r\n'
                    } | nc -w ${seconds} ${mx_host} 25 2>/dev/null
                " || true)"
            fi
        else
            # /dev/tcp fallback
            {
                exec 3<> "/dev/tcp/${mx_host}/25" || true
                printf 'EHLO %s\r\n' "${domain}" >&3 || true
                printf 'MAIL FROM:<doesnotexistuser@%s>\r\n#--AFTER_MAIL--\r\n' "${domain}" >&3 || true
                printf 'RCPT TO:<postmaster@%s>\r\n#--AFTER_RCPT--\r\n' "${domain}" >&3 || true
                printf 'QUIT\r\n' >&3 || true
                local ln out=""
                while read -r -t "${seconds}" ln <&3; do out+="${ln}\n"; done
                transcript="${out}"
                exec 3>&-
            } 2> /dev/null || true
        fi
    fi

    rcpt_code="$(printf '%s\n' "${transcript}" | _rcpt_code_from_transcript || true)"
    case "${rcpt_code}" in
        250 | 251)
                 accepted="true"
                                   reason="rcpt_accepted"
                                                          ;;
        450 | 451 | 452 | 421)     reason="temp_fail" ;;   # greylist/deferral
        "")                        reason="no_rcpt_response" ;;
        *)                         reason="rcpt_rejected_${rcpt_code}" ;;
    esac

    local is_eop="false"
    # If the current host equals the computed EOP host for this domain/cloud,
    # mark it as such for downstream reporting.
    if [[ -n "${SMTP_CLOUD:-}" ]]; then
        [[ "${mx_host}" == "$(_eop_host_for_domain "${domain}" "${SMTP_CLOUD}")" ]] && is_eop="true"
    else
        [[ "${mx_host}" == "$(_eop_host_for_domain "${domain}")" ]] && is_eop="true"
    fi

    jq -n \
        --arg mx "${mx_host}" \
        --arg method "${method}" \
        --arg tls "${tls}" \
        --arg rcpt "${rcpt_code}" \
        --arg accepted "${accepted}" \
        --arg reason "${reason}" \
        --arg transcript "${transcript}" \
        --arg is_eop "${is_eop}" \
        '{
         mx:$mx, is_eop:($is_eop=="true"),
         method:$method, tls:($tls=="true"),
         smtp_codes:{ rcpt:$rcpt },
         accepted:($accepted=="true"), reason:$reason, transcript:$transcript
       }'
}

###############################################################################
# _eop_host_for_domain
# Use cloud_surface_utils.get_cloud_endpoints to get the correct EOP suffix
# for the specified cloud ("na", "gov", "de", "china", etc.), then synthesize
# the canonical EOP host for the domain.
# Args:
#   $1 - domain (e.g., example.com)
#   $2 - cloud  (optional; default "na")
# Out:
#   prints FQDN, e.g., "example-com.mail.protection.outlook.com"
###############################################################################
_eop_host_for_domain() {
    local domain="${1}"
    local cloud="${2:-na}"
    [[ -z "${domain}" ]] && return 1

    # get_cloud_endpoints prints: login|outlook|autodiscover|eop_suffix
    local endpoints eop_suffix
    endpoints="$(get_cloud_endpoints "${cloud}")" || return 1
    eop_suffix="$(cut -d'|' -f4 <<< "${endpoints}")"

    # eop_suffix includes a leading dot (e.g., ".mail.protection.outlook.com")
    # Domain must have dots replaced with hyphens
    printf '%s%s\n' "${domain//./-}" "${eop_suffix}"
}

###############################################################################
# detect_direct_send_for_domain
# Iterate MX hosts (lowest preference first), probe each, and short-circuit on
# the first acceptance. Produces a unified, report-friendly JSON.
# Arguments:
#   $1 - domain
#   $2 - dns_server (optional)
#   $3 - timeout seconds (optional, default 7)
# Output:
#   {
#     ok: true,
#     domain: "...",
#     mx: ["mx1.example","mx2.example"],
#     probes: [ {.. per-MX object from do_direct_send_probe ..}, ... ],
#     direct_send: { possible:bool, reason:"...", note? }
#   }
###############################################################################
function detect_direct_send_for_domain() {
    local domain="${1}"
    local mx_host="${2:-}"
    local timeout="${3:-7}"

    local probes="[]" verdict="false" reason="rcpt_rejected_all"
    debug "SMTP: direct-send RCPT test on ${mx_host} ..."
    local p
    p="$(do_direct_send_probe "${domain}" "${mx_host}" "${timeout}")"
    probes="$(jq -n --argjson cur "${probes}" --argjson add "${p}" '$cur + [ $add ]')"
    if jq -e '.accepted == true' <<< "${p}" > /dev/null; then
        verdict="true"
        reason="rcpt_accepted"
    fi

    local note=""
    if [[ "${verdict}" == "true" ]]; then
        note="Server accepted RCPT TO postmaster@${domain} without authentication."
    fi

    jq -n \
        --arg domain "${domain}" \
        --arg mx "${mx_host}" \
        --argjson probes "${probes}" \
        --arg verdict "${verdict}" \
        --arg reason "${reason}" \
        --arg note "${note}" \
        '{
         ok: true,
         domain: $domain,
         mx: $mx,
         probes: $probes,
         direct_send: (
           { possible: ($verdict=="true"), reason: $reason }
           + ( if ($note|length) > 0 then {note:$note} else {} end )
         )
       }'
}
