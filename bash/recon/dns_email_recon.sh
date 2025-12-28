#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : dns_email_recon.sh
# DESCRIPTION  : DNS and Email intelligence checks.
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
source "${script_dir}/dns_utils.sh"  2> /dev/null || true
source "${script_dir}/smtp_utils.sh" 2> /dev/null || true
source "${script_dir}/web_utils.sh"  2> /dev/null || true
source "${script_dir}/cloud_surface_utils.sh" 2> /dev/null || true
source "${script_dir}/json_utils.sh" 2> /dev/null || true

#==============================================================================
# DNS / Email Intelligence
#==============================================================================
# --------------------------- SPF ANALYSIS -------------------------------------
# Returns:
# { spf: {
#     present:bool, records:[...], primary:string, multiple:bool,
#     terminal_all:"-all"|"~all"| "?all"|"none",
#     plus_all:bool, redirect:string, est_dns_lookups:int
#   }}
analyze_spf_json() {
    local domain="$1" dns_server="$2"
    local txt_rr spf_arr spf_count primary

    txt_rr="$(dns_query_generic "TXT" "${domain}" "${dns_server}")"
    # Normalize: strip outer quotes/whitespace, select v=spf1
    spf_arr="$(
        printf '%s\n' "${txt_rr}" \
            | jq '[ .[] | gsub("^(\"|\\s+)|(\"$)"; "") | select(test("(?i)(^|\\s)v=spf1\\b")) ]'
    )"

    spf_count="$(jq 'length' <<< "${spf_arr}")"
    if [[ "${spf_count}" -eq 0 ]]; then
        fail "SPF: No SPF record found for ${domain}"
        jq -n '{ spf:{ present:false, records:[], primary:"", multiple:false, terminal_all:"none", plus_all:false, redirect:"", est_dns_lookups:0 } }'
        return
    fi

    if [[ "${spf_count}" -gt 1 ]]; then
        fail "SPF: Multiple SPF records (${spf_count}) — RFC requires one."
    else
        pass "SPF: Single record present"
    fi

    primary="$(jq -r '.[0]' <<< "${spf_arr}")"
    # terminal all
    local terminal="none"
    if grep -Eq '(^|[[:space:]])-all($|[[:space:]])' <<< "${primary}"; then
                                                                         terminal="-all"
    elif grep -Eq '(^|[[:space:]])~all($|[[:space:]])' <<< "${primary}"; then
                                                                           terminal="~all"
    elif grep -Eq '(^|[[:space:]])\?all($|[[:space:]])' <<< "${primary}"; then
                                                                            terminal="?all"
    else terminal="none"; fi

    case "${terminal}" in
        -all) pass "SPF: Ends with -all (strict)" ;;
        ~all) warn "SPF: Ends with ~all (softfail) — ok for transition, tighten later" ;;
        ?all) warn "SPF: Ends with ?all (neutral) — generally not recommended" ;;
        none) fail "SPF: Missing terminal ~all/-all" ;;
    esac

    # +all detection
    local plus_all=false
    if grep -Eq '(^|[[:space:]])\+all($|[[:space:]])' <<< "${primary}"; then
        plus_all=true
        fail "SPF: +all present — critical misconfiguration"
    fi

    # redirect=
    local redirect=""
    redirect="$(tr ' ' '\n' <<< "${primary}" | awk -F= '/^redirect=/ {print $2; exit}')"
    [[ -n "${redirect}" ]] && info "SPF: redirect=${redirect}"

    # Rough DNS lookup estimator: include: a mx ptr exists: redirect=
    # (SPF limit is 10; this is heuristic)
    local est_lookups=0
    for mech in 'include:' 'a' 'mx' 'ptr' 'exists:' 'redirect='; do
        c="$(tr ' ' '\n' <<< "${primary}" | grep -Ei "^${mech}" | wc -l | tr -d ' ')"
        est_lookups=$((est_lookups + c))
    done
    if ((est_lookups > 10)); then
        fail "SPF: Estimated DNS lookups ${est_lookups} > 10 (RFC limit)"
    elif ((est_lookups == 10)); then
        warn "SPF: Estimated DNS lookups at limit (10)"
    else
        pass "SPF: Estimated DNS lookups ${est_lookups} (<=10)"
    fi

    jq -n \
        --argjson present true \
        --argjson multiple "$([[ "${spf_count}" -gt 1 ]] && echo true || echo false)" \
        --arg primary "${primary}" \
        --argjson records "${spf_arr}" \
        --arg terminal_all "${terminal}" \
        --argjson plus_all "${plus_all}" \
        --arg redirect "${redirect}" \
        --argjson est "${est_lookups}" \
        '{ spf:{present:$present, records:$records, primary:$primary, multiple:$multiple,
            terminal_all:$terminal_all, plus_all:$plus_all, redirect:$redirect,
            est_dns_lookups:$est} }'
}

# --------------------------- DMARC ANALYSIS -----------------------------------
# { dmarc: { present, record, v_ok, p, sp, adkim, aspf, rua, ruf, pct, issues:[...] } }
analyze_dmarc_json() {
    local domain="$1" dns_server="$2"
    local name="_dmarc.${domain}"
    local recs rec

    recs="$(dns_query_generic "TXT" "${name}" "${dns_server}")"
    rec="$(printf '%s\n' "${recs}" | jq -r 'map(gsub("^(\"|\\s+)|(\"$)"; "")) | map(select(test("(?i)^v=DMARC1"))) | .[0] // ""')"

    if [[ -z "${rec}" ]]; then
        fail "DMARC: No record at ${name}"
        jq -n '{ dmarc:{present:false, record:"", v_ok:false, p:"", sp:"", adkim:"", aspf:"", rua:"", ruf:"", pct:100, issues:["absent"]} }'
        return
    fi

    pass "DMARC: Record present"
    local v_ok=false
                    grep -qi '^v=DMARC1' <<< "${rec}" && v_ok=true

    # Extract tags
    local p sp adkim aspf rua ruf pct
    p="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])p=/){sub(/.*p=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    sp="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])sp=/){sub(/.*sp=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    adkim="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])adkim=/){sub(/.*adkim=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    aspf="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])aspf=/){sub(/.*aspf=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    rua="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])rua=/){sub(/.*rua=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | sed 's/[[:space:]]//g')"
    ruf="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])ruf=/){sub(/.*ruf=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | sed 's/[[:space:]]//g')"
    pct="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])pct=/){sub(/.*pct=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    [[ -z "${pct}" ]] && pct="100"

    # Issues
    local -a issues=()
    $v_ok || issues+=("bad_version")
    case "${p,,}" in
        reject) pass "DMARC: p=reject" ;;
        quarantine) warn "DMARC: p=quarantine — consider reject when ready" ;;
        none | "")
             issues+=("p_none")
                                 fail "DMARC: p=none"
                                                     ;;
        *)
            issues+=("p_unknown")
                              warn "DMARC: p=${p}"
                                                  ;;
    esac
    [[ -z "${rua}" ]] && {
                         issues+=("missing_rua")
                                                  warn "DMARC: missing rua="
    }
    [[ -n "${ruf}" ]] && info "DMARC: ruf=${ruf}"
    case "${adkim,,}" in s) pass "DMARC: adkim=strict" ;; "" | r) issues+=("adkim_relaxed_or_missing") ;; esac
    case "${aspf,,}" in s) pass "DMARC: aspf=strict" ;; "" | r) issues+=("aspf_relaxed_or_missing") ;; esac
    if [[ -n "${sp}" ]]; then
        case "${sp,,}" in
            reject) : ;;
            quarantine) issues+=("sp_quarantine") ;;
            none) issues+=("sp_none") ;;
        esac
    fi
    if ! [[ "${pct}" =~ ^[0-9]+$ ]]; then
        issues+=("pct_non_numeric")
                                 warn "DMARC: pct non-numeric"
    elif ((pct < 100)); then
        issues+=("pct_less_than_100")
                                   warn "DMARC: pct=${pct}"
    else
        pass "DMARC: pct=100"
    fi

    jq -n \
        --argjson present true --arg record "${rec}" --argjson v_ok "${v_ok}" \
        --arg p "${p}" --arg sp "${sp}" --arg adkim "${adkim}" --arg aspf "${aspf}" \
        --arg rua "${rua}" --arg ruf "${ruf}" --argjson pct "$(printf %s "${pct}")" \
        --argjson issues "$(printf '%s\n' "${issues[@]:-}" | jq -R . | jq -s .)" \
        '{ dmarc:{present:$present, record:$record, v_ok:$v_ok, p:$p, sp:$sp, adkim:$adkim, aspf:$aspf, rua:$rua, ruf:$ruf, pct:$pct, issues:$issues} }'
}

# --------------------------- MX / NULL-MX -------------------------------------
# { mx: { present, records:[...], null_mx:bool, bad_targets:[...] } }
analyze_mx_json() {
    local domain="$1" dns_server="$2"
    local mx_rr
    mx_rr="$(dns_query_generic "MX" "${domain}" "${dns_server}")"
    local count
               count="$(jq 'length' <<< "${mx_rr}")"

    if [[ "${count}" -eq 0 ]]; then
        warn "MX: No MX records"
        jq -n '{ mx:{present:false, records:[], null_mx:false, bad_targets:[]} }'
        return
    fi
    pass "MX: Records present"

    # Detect null MX: "0 ."
    local null_mx=false
    if jq -e 'map(test("^0\\s+\\.$")) | any' <<< "${mx_rr}" > /dev/null; then
        null_mx=true
        info "MX: Null MX detected (no inbound mail)"
    fi

    # Flag targets that are CNAMEs/IP literals (by pattern; deep check would need extra queries)
    # We’ll parse host field: strip pref then target
    local bad="$(printf '%s\n' "${mx_rr}" | jq '
    [ .[]
      | (if test("^[0-9]+\\s+") then capture("(?<pref>^[0-9]+)\\s+(?<host>.+)$").host else . end)
      | rtrimstr(".")
      | select(test("^[0-9.]+$") or test(":"))  # IP literal (v4/v6) as weak proxy
    ]')"

    jq -n \
        --argjson mx "${mx_rr}" \
        --argjson null "${null_mx}" \
        --argjson bad "${bad}" \
        '{ mx:{present:true, records:$mx, null_mx:$null, bad_targets:$bad} }'
}

# --------------------------- MTA-STS ------------------------------------------
# { mta_sts:{ present, record } }
analyze_mta_sts_json() {
    local domain="$1" dns_server="$2"
    local name="_mta-sts.${domain}"
    local rr rec
    rr="$(dns_query_generic "TXT" "${name}" "${dns_server}")"
    rec="$(printf '%s\n' "${rr}" | jq -r 'map(gsub("^(\"|\\s+)|(\"$)"; "")) | .[0] // ""')"
    if [[ -z "${rec}" ]]; then
        warn "MTA-STS: No TXT at ${name}"
        jq -n '{ mta_sts:{present:false, record:""} }'
        return
    fi
    if grep -qi '^v=STSv1' <<< "${rec}"; then pass "MTA-STS: v=STSv1 present"; else warn "MTA-STS: missing v=STSv1"; fi
    jq -n --arg rec "${rec}" '{ mta_sts:{present:true, record:$rec} }'
}

# --------------------------- TLS-RPT ------------------------------------------
# { tls_rpt:{ present, record, rua } }
analyze_tls_rpt_json() {
    local domain="$1" dns_server="$2"
    local name="_smtp._tls.${domain}"
    local rr rec rua
    rr="$(dns_query_generic "TXT" "${name}" "${dns_server}")"
    rec="$(printf '%s\n' "${rr}" | jq -r 'map(gsub("^(\"|\\s+)|(\"$)"; "")) | .[0] // ""')"
    if [[ -z "${rec}" ]]; then
        warn "TLS-RPT: No TXT at ${name}"
        jq -n '{ tls_rpt:{present:false, record:"", rua:""} }'
        return
    fi
    grep -qi '^v=TLSRPTv1' <<< "${rec}" || warn "TLS-RPT: missing v=TLSRPTv1"
    rua="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])rua=/){sub(/.*rua=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    [[ -z "${rua}" ]] && warn "TLS-RPT: missing rua="
    jq -n --arg rec "${rec}" --arg rua "${rua}" '{ tls_rpt:{present:true, record:$rec, rua:$rua} }'
}

# --------------------------- BIMI ---------------------------------------------
# { bimi:{ present, record, l, a } }
analyze_bimi_json() {
    local domain="$1" dns_server="$2"
    local name="default._bimi.${domain}"
    local rr rec l a
    rr="$(dns_query_generic "TXT" "${name}" "${dns_server}")"
    rec="$(printf '%s\n' "${rr}" | jq -r 'map(gsub("^(\"|\\s+)|(\"$)"; "")) | .[0] // ""')"
    if [[ -z "${rec}" ]]; then
        info "BIMI: No record"
        jq -n '{ bimi:{present:false, record:"", l:"", a:""} }'
        return
    fi
    grep -qi '^v=BIMI1' <<< "${rec}" || warn "BIMI: missing v=BIMI1"
    l="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])l=/){sub(/.*l=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    a="$(awk -F';' '{for(i=1;i<=NF;i++){if($i~/(^|[[:space:]])a=/){sub(/.*a=/,"",$i);print $i}}}' <<< "${rec}" | head -n1 | tr -d '[:space:]')"
    [[ -z "${l}" ]] && warn "BIMI: missing l= (logo)"
    jq -n --arg rec "${rec}" --arg l "${l}" --arg a "${a}" '{ bimi:{present:true, record:$rec, l:$l, a:$a} }'
}

# --------------------------- DKIM ---------------------------------------------
# Tries a curated selector set + optional file.
# { dkim:{ any_found, selectors:[{selector,record,key_len,issues:[...]}] } }
analyze_dkim_json() {
    local domain="$1" dns_server="$2" selectors_file="$3"
    local -a default=(default selector selector1 selector2 s1 s2 google google1 google2 mail m1 smtp dkim k1 mandrill sendgrid postmark sparkpost amazonses amazonses1 amazonses2 mailchimp zoho office365 o365 pm krs s1024 s2048)
    local -a extra=()
    [[ -r "${selectors_file}" && -n "${selectors_file}" ]] && mapfile -t extra < <(sed -e 's/[[:space:]]//g' -e '/^$/d' -e '/^#/d' "${selectors_file}")
    local -a all=("${default[@]}" "${extra[@]}")
    local found=0
    local tmp
             tmp="$(mktemp)"

    for sel in "${all[@]}"; do
        local name="${sel}._domainkey.${domain}"
        local rr rec
        rr="$(dns_query_generic "TXT" "${name}" "${dns_server}")"
        rec="$(printf '%s\n' "${rr}" | jq -r 'map(gsub("^(\"|\\s+)|(\"$)"; "")) | .[0] // ""')"
        if [[ -n "${rec}" ]]; then
            found=1
            local issues=()
            grep -qi '^v=DKIM1' <<< "${rec}" || issues+=("missing_v")
            if grep -qi 'p=' <<< "${rec}"; then
                local pval
                    pval="$(tr ';' '\n' <<< "${rec}" | awk '/^[Pp]=/ {sub(/^[Pp]=/,""); gsub(/[[:space:]]/,""); print; exit}')"
                local len=${#pval}
                ((len > 0 && len < 100)) && issues+=("p_too_short_heuristic")
                jq -n --arg sel "${sel}" --arg rec "${rec}" --argjson key_len "${len}" \
                    --argjson issues "$(printf '%s\n' "${issues[@]:-}" | jq -R . | jq -s .)" \
                    '{selector:$sel, record:$rec, key_len:$key_len, issues:$issues}' >> "${tmp}"
            else
                issues+=("missing_p")
                jq -n --arg sel "${sel}" --arg rec "${rec}" --argjson key_len 0 \
                    --argjson issues "$(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .)" \
                    '{selector:$sel, record:$rec, key_len:$key_len, issues:$issues}' >> "${tmp}"
            fi
        fi
    done

    if [[ "${found}" -eq 0 ]]; then
        warn "DKIM: No selectors from probe list found"
        jq -n '{ dkim:{ any_found:false, selectors:[] } }'
    else
        jq -s '{ dkim:{ any_found:true, selectors:. } }' "${tmp}"
    fi
    rm -f "${tmp}"
}

# --------------------------- ORCHESTRATOR -------------------------------------
# Merges all JSON blocks:
# { mailsec:{ domain, server, ...<sub-objects from above>... } }
do_mailsec_analysis() {
    local domain="$1" dns_server="$2" selectors_file="$3"
    jq -s --arg domain "${domain}" --arg server "${dns_server}" '
    reduce .[] as $i ({}; . * $i) | { mailsec: ({domain:$domain, server:$server} + .) }'
}

###############################################################################
# do_dns_suite
# Run DNS suite: A/AAAA/MX/TXT/SPF/DMARC and basic parsing.
# Arguments:
#   $1 - domain
#   $2 - dns_server
# Output:
#   JSON object { dns: { ... } }
###############################################################################
function do_dns_suite() {
    local domain="${1}"
    local dns_server="${2}"

    info "DNS: querying records for ${domain} via ${dns_server} ..."
    local a_rr aaaa_rr mx_rr txt_rr dmarc_rr spf_arr

    a_rr="$(dns_query_generic "A" "${domain}" "${dns_server}")"
    aaaa_rr="$(dns_query_generic "AAAA" "${domain}" "${dns_server}")"
    mx_rr="$(dns_query_generic "MX" "${domain}" "${dns_server}")"
    txt_rr="$(dns_query_generic "TXT" "${domain}" "${dns_server}")"
    dmarc_rr="$(dns_query_generic "TXT" "_dmarc.${domain}" "${dns_server}")"

    # FIX: Strip surrounding quotes before testing for v=spf1
    # Also tolerate leading whitespace.
    spf_arr="$(
        printf '%s\n' "${txt_rr}" \
            | jq '[ .[] | gsub("^(\"|\\s+)|(\"$)"; "") | select(test("(?i)(^|\\s)v=spf1\\b")) ]'
    )"

    jq -n --arg server "${dns_server}" --arg domain "${domain}" \
        --argjson a "${a_rr:-[]}" --argjson aaaa "${aaaa_rr:-[]}" \
        --argjson mx "${mx_rr:-[]}" --argjson txt "${txt_rr:-[]}" \
        --argjson dmarc "${dmarc_rr:-[]}" --argjson spf "${spf_arr:-[]}" \
        '{ dns: { domain:$domain, server:$server, a:$a, aaaa:$aaaa, mx:$mx, txt:$txt, dmarc:$dmarc, spf:$spf } }'
}

###############################################################################
# do_dns_srv_suite
#==================
# Purpose:
#   Query key Microsoft/Teams-related SRV records for a target domain using the
#   caller-provided DNS server, and return results as a structured JSON object.
#
# Records queried:
#   - _sip._tls.<domain>               : SIP over TLS (Teams/Skype for Business)
#   - _sipfederationtls._tcp.<domain>  : SIP federation over TLS
#   - _autodiscover._tcp.<domain>      : Exchange Autodiscover SRV
#
# Behavior:
#   - Uses the generic DNS helper 'dns_query_generic' for portability and
#     built-in fallback (dig -> host).
#   - Always emits valid JSON; if a lookup fails, the corresponding array
#     is empty.
#
# Globals:
#   (none)
#
# Arguments:
#   $1 - domain (e.g., "contoso.com")
#   $2 - dns_server (e.g., "1.1.1.1")
#
# Output (stdout):
#   {
#     "srv": {
#       "sip_tls":            [ "... SRV answers ..." ],
#       "sipfederation_tls":  [ "... SRV answers ..." ],
#       "autodiscover_tcp":   [ "... SRV answers ..." ]
#     }
#   }
#
# Returns:
#   0 - always (errors are handled by emitting empty arrays)
###############################################################################
function do_dns_srv_suite() {
    local domain="${1}"
    local dns_server="${2}"

    info "DNS SRV: _sip._tls, _sipfederationtls._tcp, _autodiscover._tcp for ${domain} via ${dns_server} ..."

    # Perform each SRV query with the same helper for consistent formatting.
    local sip srv_name sipfed adis
    srv_name="_sip._tls.${domain}"
    sip="$(dns_query_generic "SRV" "${srv_name}" "${dns_server}")"

    srv_name="_sipfederationtls._tcp.${domain}"
    sipfed="$(dns_query_generic "SRV" "${srv_name}" "${dns_server}")"

    srv_name="_autodiscover._tcp.${domain}"
    adis="$(dns_query_generic "SRV" "${srv_name}" "${dns_server}")"

    # Compose a namespaced JSON object; tolerate empty variables by defaulting
    # to '[]' so downstream jq does not break.
    jq -n \
        --argjson sip   "${sip:-[]}" \
        --argjson sipfd "${sipfed:-[]}" \
        --argjson ad    "${adis:-[]}" \
        '{ srv: { sip_tls:$sip, sipfederation_tls:$sipfd, autodiscover_tcp:$ad } }'
}

###############################################################################
# do_eop_eval
# Infer EOP usage and basic hints from MX records.
# Arguments:
#   $1 - domain
#   $2 - dns_server
#   $3 - eop_suffix (e.g., .mail.protection.outlook.com)
# Output:
#   JSON object { eop: { using_eop:bool, mx_hosts:[...], matches:[...] } }
###############################################################################
function do_eop_eval() {
    local domain="${1}"
    local dns_server="${2}"
    local eop_suffix="${3}"
    local mx_rr matches using_eop="false"

    mx_rr="$(dns_query_generic "MX" "${domain}" "${dns_server}")"

    # Extract host, trim trailing dot, then endswith() the suffix.
    matches="$(
        printf '%s\n' "${mx_rr}" \
            | jq --arg suf "${eop_suffix}" '
            [ .[]
              | (if test("^[0-9]+\\s+") then capture("(?<pref>^[0-9]+)\\s+(?<host>.+)$").host else . end)
              | rtrimstr(".")
              | select(endswith($suf))
            ]'
    )"

    if [[ "$(jq 'length' <<< "${matches}")" -gt 0 ]]; then
        using_eop="true"
        pass "EOP: MX indicates ${eop_suffix}."
    else
        warn "EOP: MX does not clearly indicate ${eop_suffix}."
    fi

    jq -n \
        --argjson mx "${mx_rr:-[]}" \
        --argjson matches "${matches:-[]}" \
        --arg using_eop "${using_eop}" \
        '{ eop: { using_eop: ($using_eop=="true"), mx_hosts:$mx, eop_matches:$matches } }'
}

###############################################################################
# do_realm_discovery
# Use getuserrealm.srf to determine Managed vs Federated & related hints.
# Arguments:
#   $1 - login_host (e.g., login.microsoftonline.com)
#   $2 - domain (UPN suffix)
# Output:
#   JSON object { realm: {...} }
###############################################################################
function do_realm_discovery() {
    local login_host="${1}"
    local domain="${2}"
    local upn="postmaster@${domain}"
    info "Entra: realm discovery for ${domain} via ${login_host} ..."
    local url="https://${login_host}/getuserrealm.srf?login=${upn}&json=1"
    local body rc
    body="$(run_with_timeout 9s curl -fsS -m 9 --retry 1 -A "${CURL_UA}" "${url}" 2> /dev/null)"
    rc=$?
    if ((rc != 0)); then
        warn "Realm discovery request failed (rc=${rc})."
        echo '{}' | jq -n --arg err "request_failed" '{ realm:{ error:$err } }'
        return 0
    fi

    # Ensure valid JSON
    jq -n --argjson j "${body}" '{ realm: $j }'
}

###############################################################################
# do_oidc_wellknown
# Query OIDC well-known for tenant/issuer hints.
# Arguments:
#   $1 - login_host
#   $2 - domain
# Output:
#   JSON object { oidc: {...} }
###############################################################################
function do_oidc_wellknown() {
    local login_host="${1}"
    local domain="${2}"

    local url_v2="https://${login_host}/${domain}/v2.0/.well-known/openid-configuration"
    info "Entra: OIDC well-known for ${domain} ..."
    local body_v2 rc
    body_v2="$(run_with_timeout 10s curl -fsS -m 10 --retry 1 -A "${CURL_UA}" "${url_v2}" 2> /dev/null)"
    rc=$?
    if ((rc != 0)); then
        warn "OIDC v2.0 discovery failed (rc=${rc}). Trying v1.0 ..."
        local url_v1="https://${login_host}/${domain}/.well-known/openid-configuration"
        body_v2="$(run_with_timeout 9s curl -fsS -m 9 --retry 1 -A "${CURL_UA}" "${url_v1}" 2> /dev/null || true)"
    fi

    if [[ -z "${body_v2}" ]]; then
        echo '{}' | jq -n --arg err "not_found" '{ oidc:{ error:$err } }'
        return 0
    fi

    # Extract known fields, tolerate extras
    local issuer auth token devicecode tenant_id
    issuer="$(jq -r '.issuer // empty' <<< "${body_v2}" 2> /dev/null || true)"
    auth="$(jq -r '.authorization_endpoint // empty' <<< "${body_v2}" 2> /dev/null || true)"
    token="$(jq -r '.token_endpoint // empty' <<< "${body_v2}" 2> /dev/null || true)"
    devicecode="$(jq -r '.device_authorization_endpoint // empty' <<< "${body_v2}" 2> /dev/null || true)"
    tenant_id="$(printf '%s\n' "${issuer}" | grep -Eo '[0-9a-fA-F-]{36}' | head -n1 || true)"

    jq -n \
        --argjson obj "${body_v2}" \
        --arg issuer "${issuer}" \
        --arg authorization_endpoint "${auth}" \
        --arg token_endpoint "${token}" \
        --arg device_authorization_endpoint "${devicecode}" \
        --arg tenant_id "${tenant_id}" \
        '{ oidc: ($obj + { tenant_id:$tenant_id, authorization_endpoint:$authorization_endpoint, token_endpoint:$token_endpoint, device_authorization_endpoint:$device_authorization_endpoint, issuer:$issuer }) }'
}

###############################################################################
# autodiscover_probe
# Probe Autodiscover endpoints (domain and global host) for reachability.
# Arguments:
#   $1 - domain
#   $2 - autodiscover_global (e.g., autodiscover-s.outlook.com)
# Output:
#   JSON object { autodiscover: { ... } }
###############################################################################
function autodiscover_probe() {
    local domain="${1}"
    local autodiscover_global="${2}"

    info "Autodiscover: probing endpoints for ${domain} ..."
    local url1="https://autodiscover.${domain}/autodiscover/autodiscover.xml"
    local url2="https://${autodiscover_global}/autodiscover/autodiscover.xml"
    local s1 s2

    s1="$(run_with_timeout 7s curl -s -o /dev/null -w '%{http_code}' -m 7 --retry 0 -A "${CURL_UA}" "${url1}" || true)"
    s2="$(run_with_timeout 7s curl -s -o /dev/null -w '%{http_code}' -m 7 --retry 0 -A "${CURL_UA}" "${url2}" || true)"

    jq -n --arg u1 "${url1}" --arg u2 "${url2}" --arg s1 "${s1}" --arg s2 "${s2}" \
        '{ autodiscover: { endpoints: [ {url:$u1,status:($s1|tonumber? // 0)}, {url:$u2,status:($s2|tonumber? // 0)} ] } }'
}
