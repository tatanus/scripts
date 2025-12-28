#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : analysis_and_output.sh
# DESCRIPTION  : Analysis and JSON/report orchestration.
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
# Analysis / Summary
#==============================================================================

###############################################################################
# analyze_results
#------------------------------------------------------------------------------
# PURPOSE:
#   Review the merged JSON from all collectors and produce derived findings
#   with a coarse risk score. Findings are human-readable strings; the risk
#   score is a simple sum of weighted conditions.
#
# ARGUMENTS:
#   $1 - merged (the final merged JSON string from json_merge)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "analysis": {
#       "findings":  [ "string", "string", ... ],
#       "risk_score": <int>
#     }
#   }
#
# NOTES:
#   - This is intentionally heuristic and conservative.
#   - No authentication is used anywhere here.
###############################################################################
function analyze_results() {
    local merged="${1}"

    # Local accumulator for messages and risk.
    local -a findings=()
    local risk=0

    # Small helper to push a finding and add a weight to risk.
    # Usage: add_finding "message" 3
    local _msg="" _wt=0
    function add_finding() {
        _msg="${1}"
                     _wt="${2}"
        findings+=("${1}")
        # Only add numeric weights >= 0
        if [[ "${_wt}" =~ ^[0-9]+$ ]]; then
            risk=$((risk + _wt))
        fi
    }

    # -----------------------------
    # SPF policy evaluation
    # -----------------------------
    local spf_count="0" spf_join=""
    spf_count="$(jq -r '.dns.spf | length // 0' <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${spf_count}" -eq 0 ]]; then
        add_finding "SPF record not found." 3
    else
        spf_join="$(jq -r '.dns.spf | join(" ")' <<< "${merged}" 2> /dev/null || true)"
        if grep -qE '\+all' <<< "${spf_join}"; then
            add_finding "SPF contains +all (allows any sender)." 5
        elif grep -qE '~all' <<< "${spf_join}"; then
            add_finding "SPF ends with ~all (soft fail). Consider -all for stricter policy." 1
        elif grep -qE '-all' <<< "${spf_join}"; then
            add_finding "SPF ends with -all (good)." 0
        fi
    fi

    # -----------------------------
    # DMARC policy evaluation
    # -----------------------------
    local dmarc_count="0" dmarc_join=""
    dmarc_count="$(jq -r '.dns.dmarc | length // 0' <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${dmarc_count}" -eq 0 ]]; then
        add_finding "DMARC record not found." 3
    else
        dmarc_join="$(jq -r '.dns.dmarc | join(" ")' <<< "${merged}" 2> /dev/null || true)"
        if grep -qi 'p=none' <<< "${dmarc_join}"; then
            add_finding "DMARC policy is p=none (monitoring only). Consider p=quarantine or p=reject." 2
        elif grep -qi 'p=quarantine' <<< "${dmarc_join}"; then
            add_finding "DMARC policy is p=quarantine (better)." 1
        elif grep -qi 'p=reject' <<< "${dmarc_join}"; then
            add_finding "DMARC policy is p=reject (good)." 0
        fi
    fi

    # -----------------------------
    # EOP / MX provider hint
    # -----------------------------
    local using_eop="false"
    using_eop="$(jq -r '.eop.using_eop // false' <<< "${merged}" 2> /dev/null || printf 'false')"
    if [[ "${using_eop}" != "true" ]]; then
        add_finding "MX does not indicate Exchange Online Protection for this cloud." 1
    else
        add_finding "MX indicates Exchange Online Protection is in use." 0
    fi

    # -----------------------------
    # SMTP STARTTLS support
    # -----------------------------
    local no_tls_count="0"
    no_tls_count="$(jq '[ .smtp.results[]? | select(.probe.ok==true and (.probe.starttls|not)) ] | length' \
        <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${no_tls_count}" -gt 0 ]]; then
        add_finding "One or more MX hosts do not advertise STARTTLS." 4
    fi

    # -----------------------------
    # Direct send acceptance
    # -----------------------------
    local accepted_count="0"
    accepted_count="$(jq '[ .direct_send.results[]? | select(.accepted==true) ] | length' \
        <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${accepted_count}" -gt 0 ]]; then
        add_finding "At least one MX accepted RCPT for postmaster@domain without authentication (direct-send may be possible)." 1
    fi

    # -----------------------------
    # Autodiscover health
    # -----------------------------
    local ad_404="0"
    ad_404="$(jq '[ .autodiscover.endpoints[]? | select(.status==404) ] | length' \
        <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${ad_404}" -gt 0 ]]; then
        add_finding "Autodiscover endpoint returned 404 on at least one URL (check DNS/web routing)." 1
    fi

    # -----------------------------
    # OIDC tenant ID presence
    # -----------------------------
    local tid=""
    tid="$(jq -r '.oidc.tenant_id // empty' <<< "${merged}" 2> /dev/null || true)"
    if [[ -n "${tid}" ]]; then
        add_finding "Tenant ID discovered: ${tid}." 0
    else
        add_finding "Tenant ID could not be discovered from OIDC metadata." 1
    fi

    # -----------------------------
    # Legacy auth signal (EWS)
    # -----------------------------
    local has_basic="false"
    if jq -e '.legacy_auth.ews.www_auth? // "" | test("(?i)Basic")' > /dev/null 2>&1 <<< "${merged}"; then
        has_basic="true"
    fi
    if [[ "${has_basic}" == "true" ]]; then
        add_finding "EWS advertises Basic auth (legacy). Confirm if disabled at tenant level." 3
    fi

    # -----------------------------
    # SIP SRV presence (Teams/Skype federation hint)
    # -----------------------------
    local sip_present="false"
    sip_present="$(jq -r '((.srv.sip_tls|length // 0) > 0) or ((.srv.sipfederation_tls|length // 0) > 0)' \
        <<< "${merged}" 2> /dev/null || printf 'false')"
    if [[ "${sip_present}" == "true" ]]; then
        add_finding "SIP SRV records present (Teams/Skype federation likely configured)." 0
    fi

    # -----------------------------
    # B2C presence
    # -----------------------------
    local b2c_host_status="0"
    b2c_host_status="$(jq -r '.b2c.host_status // 0' <<< "${merged}" 2> /dev/null || printf '0')"
    if [[ "${b2c_host_status}" -ge 200 ]]; then
        add_finding "B2C host resolves/responds; review policy endpoints for exposure." 0
    fi

    # -----------------------------
    # Graph snapshots summary (if present)
    # -----------------------------
    if jq -e '.graph.applications_total? // empty' > /dev/null 2>&1 <<< "${merged}"; then
        add_finding "Graph: Applications snapshot collected." 0
    fi
    if jq -e '.defender_for_identity.present? // empty' > /dev/null 2>&1 <<< "${merged}"; then
        if [[ "$(jq -r '.defender_for_identity.present' <<< "${merged}")" == "true" ]]; then
            add_finding "Microsoft Defender for Identity service principal(s) detected." 0
        else
            add_finding "No Defender for Identity service principal detected (heuristic)." 0
        fi
    fi

    # Build the final analysis JSON.
    local findings_json=""
    findings_json="$(printf '%s\n' "${findings[@]:-}" | jq -R -s 'split("\n") | map(select(length>0))')"

    jq -n \
        --argjson f "${findings_json:-[]}" \
        --argjson r "${risk}" \
        '{ analysis: { findings: $f, risk_score: ($r|tonumber) } }'
}

    function add_finding() {
        _msg="${1}"
                     _wt="${2}"
        findings+=("${1}")
        # Only add numeric weights >= 0
        if [[ "${_wt}" =~ ^[0-9]+$ ]]; then
            risk=$((risk + _wt))
    fi
}

###############################################################################
# print_summary
# Human-friendly summary based on the final merged JSON.
# Arguments:
#   $1 - merged JSON string
###############################################################################
function print_summary() {
    local merged="${1}"

    info "================ Final Summary ================"

    # Overall risk
    local risk
    risk="$(jq -r '.analysis.risk_score // 0' <<< "${merged}")"
    if [[ "${risk}" -ge 7 ]]; then
        fail "Overall risk score: ${risk}"
    elif [[ "${risk}" -ge 3 ]]; then
        warn "Overall risk score: ${risk}"
    else
        pass "Overall risk score: ${risk}"
    fi

    # Tenant identity quick facts
    local ns_type brand domain_name tid
    ns_type="$(jq -r '.tenant_branding.name_space_type // .aad_connect.name_space_type // empty' <<< "${merged}")"
    brand="$(jq -r '.tenant_branding.federation_brand_name // empty' <<< "${merged}")"
    domain_name="$(jq -r '.tenant_branding.domain_name // empty' <<< "${merged}")"
    tid="$(jq -r '.oidc.tenant_id // empty' <<< "${merged}")"
    if [[ -n "${domain_name}${tid}${ns_type}${brand}" ]]; then
        info "Tenant: ${domain_name:-unknown} | Mode: ${ns_type:-unknown} | Brand: ${brand:-n/a} | GUID: ${tid:-n/a}"
    fi

    # Direct-send possible?
    local ds_accept="false"
    ds_accept="$(jq -r '([ .direct_send.results[]? | select(.accepted==true) ] | length) > 0' <<< "${merged}" 2> /dev/null || echo false)"
    if [[ "${ds_accept}" == "true" ]]; then
        warn "Direct Send: POSSIBLE (at least one MX accepted RCPT TO for postmaster without auth)."
    else
        pass "Direct Send: not indicated (no MX accepted unauthenticated RCPT TO)."
    fi

    # EOP summary + MX list
    local using_eop mx_list
    using_eop="$(jq -r '.eop.using_eop // false' <<< "${merged}")"
    mx_list="$(jq -r '.dns.mx[]? // empty' <<< "${merged}" | paste -sd ', ' -)"
    if [[ "${using_eop}" == "true" ]]; then
        pass "EOP: yes (${mx_list:-no MX listed})"
    else
        warn "EOP: no (${mx_list:-no MX listed})"
    fi

    # SPF / DMARC snippets
    local spf_join dmarc_join
    spf_join="$(jq -r '(.dns.spf // []) | join(" | ")' <<< "${merged}" 2> /dev/null || true)"
    dmarc_join="$(jq -r '(.dns.dmarc // []) | join(" | ")' <<< "${merged}" 2> /dev/null || true)"
    if [[ -n "${spf_join}" ]]; then info "SPF: ${spf_join}"; else warn "SPF: not found"; fi
    if [[ -n "${dmarc_join}" ]]; then info "DMARC: ${dmarc_join}"; else warn "DMARC: not found"; fi

    # Key findings from analysis
    while IFS= read -r f; do
        if grep -qi 'good' <<< "${f}"; then
            pass "${f}"
        elif grep -Eqi '(^|[^a-z])(not|fail|no |\\+all|404|none\))' <<< "${f}"; then
            warn "${f}"
        else
            info "${f}"
        fi
    done < <(jq -r '.analysis.findings[]? // empty' <<< "${merged}")

    # Communication Services
    info "[+] Communication Services:"
    # Teams
    jq -r '
      def yn($b): if ($b|tostring)=="true" then "Yes" else "No" end;
      ( .teams.present
        // ((.teams.portal_status // 0) == 200)
        // false ) as $teams
      | "              - Microsoft Teams: " + yn($teams)
        + (if .teams.portal_url? then " | " + .teams.portal_url
           elif $teams == true then " | https://teams.microsoft.com"
           else "" end)
    ' <<< "${merged}"
    # Skype for Business
    jq -r '
      def yn($b): if ($b|tostring)=="true" then "Yes" else "No" end;
      (  ((.dns.srv."_sip._tls" // .dns.srv.sip_tls // [] ) | length) > 0
       or ((.dns.srv."_sipfederationtls._tcp" // .dns.srv.sipfederationtls_tcp // [] ) | length) > 0
      ) as $sfb
      | "              - Skype for Business: " + yn($sfb)
        + (if $sfb == true then " | sipdir.online.lync.com / sipfed.online.lync.com" else "" end)
    ' <<< "${merged}"

    # If SIP SRV targets are present, include them explicitly (service hostnames)
    jq -r '
      ((.srv.sip_tls // .dns.srv."_sip._tls" // []) + (.srv.sipfederation_tls // .dns.srv."_sipfederationtls._tcp" // []))
      | unique
      | if (length>0) then
          ( .[] | "              - SIP Target: " + ( . | sub("^\\s*([0-9]+\\s+[0-9]+\\s+[0-9]+\\s+)?";"") | rtrimstr(".") ) )
        else empty end
    ' <<< "${merged}"

    # Entra / Identity Posture (Unauth)
    info "[+] Entra / Identity Posture:"
    jq -r '
      "              - DomainType: " + ((.aad_connect.domain_type // "Unknown"))
    ' <<< "${merged}"
    jq -r '
      "              - Conditional Access signals: "
      + (if (.conditional_access.present // false) then "present" else "not indicated" end)
    ' <<< "${merged}"
    jq -r '
      "              - Legacy Auth signals: "
      + (if (.legacy_auth.present // false) then "present" else "not indicated" end)
    ' <<< "${merged}"

    # Provisioning Endpoints (Unauth) — include URL
    info "[+] Provisioning Endpoints:"
    jq -r '
      (.tenant_config.provisioning // {}) as $p
      | if ($p|type)!="object" or ($p|length)==0
        then "              - None"
        else
          $p | to_entries[]
            | "              - " + .key + ": " + (.value.status // "unknown")
              + " (HTTP " + (.value.http // "000") + ")"
              + (if (.value.url // "") != "" then " | " + .value.url else "" end)
        end
    ' <<< "${merged}"

    # Microsoft Defender for Identity (Unauth) — include host/URL if present
    info "[+] Microsoft Defender for Identity:"
    jq -r '
      if (.mdi_instance.detected // false) then
        ( "              - Presence: Yes"
          + ( if (.mdi_instance.host // .mdi_instance.url // "") != "" then
                " | " +
                ( if (.mdi_instance.url // "") != "" then (.mdi_instance.url)
                  elif (.mdi_instance.host // "") != "" then ("https://" + .mdi_instance.host)
                  else "" end )
              else "" end ) )
      else
        "              - Presence: No"
      end
    ' <<< "${merged}"

    # Azure Services (Passive CNAME Hints) — includes host and CNAME targets
    info "[+] Azure Services (Passive CNAME Hints):"
    jq -r '
      (.azure_services.hints // []) as $h |
      if ($h|length) == 0 then
        "              - None"
      else
        $h[]
        | "              - " + (.host // "?")
          + ": "
          + ( ((.cname // []) | map(tostring) | join(", ")) // "n/a" )
          + (if (.status // "") != "" then " [" + .status + "]" else "" end)
      end
    ' <<< "${merged}"

    # Azure Services (Deep Sweep)
    info "[+] Azure Services (Deep Sweep):"
    jq -r '
      (.azure_services_deep.hits // []) as $hits
      | if ($hits|length)==0
        then "              - N/A"
        else  "              - " + (( $hits|length )|tostring) + " hits"
        end
    ' <<< "${merged}"

    # Azure App Services — filter & show only 2xx/3xx codes, name|url|HTTP <code>
    info "[+] Azure App Services:"
    jq -r '
      def http_ok($c): ($c|tostring|test("^(2|3)[0-9][0-9]$"));
      def show($n;$u;$s): "              - " + ($n // ($u // "?")) + " | " + ($u // "?") + " | HTTP " + ($s|tostring);

      (.azure_services.app_services // null) as $as |
      if $as == null then
        "              - None"
      elif ($as|type) == "object" then
        [ $as
          | to_entries[]
          | select(.key|test("^https?://"))                # keep only URL-like keys
          | ( .value as $v
              | (if ($v|type)=="object" then $v else {} end) ) as $v
          | select( $v.status? and http_ok($v.status) )
          | show( $v.name; $v.url // .key; $v.status )
        ]
        | if length==0 then "              - None" else .[] end
      elif ($as|type) == "array" then
        [ $as[]
          | select(.url? and .status?)
          | select(http_ok(.status))
          | show(.name; .url; .status)
        ]
        | if length==0 then "              - None" else .[] end
      else
        "              - None"
      end
    ' <<< "${merged}"

    # Azure Storage Accounts — include URL
    info "[+] Azure Storage Accounts:"
    jq -r '
      (.azure_services.storage_accounts // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[]
          | "              - " + (.url // "?") + " (" + (.status // "unknown") + ")"
        end
    ' <<< "${merged}"

    # Power Apps Portals — include URL
    info "[+] Power Apps Portals:"
    jq -r '
      (.azure_services.power_apps // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[] | "              - " + .
        end
    ' <<< "${merged}"

    # Azure CDN Endpoints — include host
    info "[+] Azure CDN Endpoints:"
    jq -r '
      (.azure_services.cdn_endpoints // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[] | "              - " + .
        end
    ' <<< "${merged}"

    # Azure AD Applications — include unauth endpoints + Admin Consent URL
    info "[+] Azure AD Applications (if collected):"
    jq -r '
      if (.graph.applications|type=="array") and ((.graph.applications|length) > 0)
        then "              - " + ((.graph.applications|length)|tostring) + " application(s)"
      elif (.aad_applications.endpoints|type=="object")
        then "              - Unauth endpoint hints present (issuer/authorization/token)"
      else
        "              - N/A"
      end
    ' <<< "${merged}"
    # List unauth endpoints explicitly when present
    jq -r '
      (.aad_applications.endpoints // {}) as $e
      | if ($e|type)=="object" and ($e|length)>0 then
          [ ["Issuer",               ($e.issuer // "")],
            ["Authorization",        ($e.authorization_endpoint // "")],
            ["Token",                ($e.token_endpoint // "")],
            ["Device Authorization", ($e.device_authorization_endpoint // "")] ]
          | map(select(.[1] != ""))
          | .[] | "              - " + .[0] + ": " + .[1]
        else empty end
    ' <<< "${merged}"
    jq -r '
      (.oidc.tenant_id // "") as $tid
      | if ($tid|length) > 0
          then "              - Admin Consent URL: https://login.microsoftonline.com/" + $tid + "/adminconsent"
          else empty
        end
    ' <<< "${merged}"

    info "=============================================="
}

###############################################################################
# print_long_report
#------------------------------------------------------------------------------
# PURPOSE:
#   Pretty-print a long-form report (msftrecon-style) that ALSO embeds the
#   alerts/inferences/issues from the compact summary (.analysis.findings).
#
# ARGUMENTS:
#   $1 - merged JSON string (from json_merge after analysis)
#
# OUTPUT:
#   Human-readable report to stdout.
###############################################################################
function print_long_report() {
    local merged="${1}"

    info "================ Detailed Report ================"

    # ---------- Overall Risk ----------
    local risk
    risk="$(jq -r '.analysis.risk_score // 0' <<< "${merged}")"
    if [[ "${risk}" -ge 7 ]]; then
        fail "Overall risk score: ${risk}"
    elif [[ "${risk}" -ge 3 ]]; then
        warn "Overall risk score: ${risk}"
    else
        pass "Overall risk score: ${risk}"
    fi

    # ---------- Tenant / Identity Basics ----------
    local tid ns_type brand domain_name region cloud_instance
    tid="$(jq -r '.oidc.tenant_id // empty' <<< "${merged}")"
    ns_type="$(jq -r '.aad_connect.domain_type // .tenant_branding.name_space_type // empty' <<< "${merged}")"
    brand="$(jq -r '.tenant_branding.federation_brand_name // empty' <<< "${merged}")"
    domain_name="$(jq -r '.tenant_branding.domain_name // empty' <<< "${merged}")"
    region="$(jq -r '.oidc.tenant_region_scope // empty' <<< "${merged}")"
    cloud_instance="$(jq -r '.tenant_branding.cloud_instance // .oidc.cloud_instance_name // empty' <<< "${merged}")"

    echo
    echo "Tenant: ${domain_name:-Unknown}"
    echo "Tenant ID: ${tid:-Unknown}"
    echo "Identity Mode: ${ns_type:-Unknown}"
    echo "Brand: ${brand:-Unknown}"
    echo "Region: ${region:-Unknown}"
    echo "Cloud Instance: ${cloud_instance:-Unknown}"

    # ---------- AAD Connect / Identity (unauth posture) ----------
    echo
    info "[+] AAD Connect / Identity:"
    jq -r '
      { name_space_type:(.aad_connect.name_space_type // "Unknown"),
        domain_type:(.aad_connect.domain_type // "Unknown"),
        federation_brand_name:(.aad_connect.federation_brand_name // "Unknown"),
        cloud_instance:(.aad_connect.cloud_instance // "Unknown"),
        auth_url:(.aad_connect.auth_url // null),
        federation_version:(.aad_connect.federation_version // null),
        hybrid_config:(.aad_connect.hybrid_config // null) } as $x
      | "              - NameSpaceType: " + $x.name_space_type
      + "\n - DomainType: " + $x.domain_type
      + "\n - FederationBrand: " + $x.federation_brand_name
      + "\n - CloudInstance: " + $x.cloud_instance
      + (if $x.auth_url then "\n - AuthURL: " + $x.auth_url else "" end)
      + (if $x.federation_version then "\n - FederationVersion: " + $x.federation_version else "" end)
      + (if $x.hybrid_config then "\n - Hybrid: " + $x.hybrid_config else "" end)
    ' <<< "${merged}"

    # ---------- Communication Services ----------
    echo
    echo "[+] Communication Services:"
    jq -r '
      def yn($b): if ($b|tostring)=="true" then "Yes" else "No" end;
      ( .teams.present
        // ((.teams.portal_status // 0) == 200)
        // false ) as $teams
      | "              - Microsoft Teams: " + yn($teams)
        + (if .teams.portal_url? then " | " + .teams.portal_url
           elif $teams == true then " | https://teams.microsoft.com"
           else "" end)
    ' <<< "${merged}"
    jq -r '
      def yn($b): if ($b|tostring)=="true" then "Yes" else "No" end;
      (  ((.dns.srv."_sip._tls" // .dns.srv.sip_tls // [] ) | length) > 0
       or ((.dns.srv."_sipfederationtls._tcp" // .dns.srv.sipfederationtls_tcp // [] ) | length) > 0
      ) as $sfb
      | "              - Skype for Business: " + yn($sfb)
        + (if $sfb == true then " | sipdir.online.lync.com / sipfed.online.lync.com" else "" end)
    ' <<< "${merged}"

    # ---------- Email Posture ----------
    echo
    info "[+] Email Posture:"
    local using_eop ds_accept spf_join dmarc_join
    using_eop="$(jq -r '.eop.using_eop // false' <<< "${merged}")"
    ds_accept="$(jq -r '([ .direct_send.results[]? | select(.accepted==true) ] | length) > 0' <<< "${merged}" 2> /dev/null || echo false)"
    spf_join="$(jq -r '(.dns.spf // []) | join(" | ")' <<< "${merged}" 2> /dev/null || true)"
    dmarc_join="$(jq -r '(.dns.dmarc // []) | join(" | ")' <<< "${merged}" 2> /dev/null || true)"

    echo "Exchange Online Protection (MX suffix): $([[ "${using_eop}" == "true" ]] && echo yes || echo no)"
    echo "Direct Send Possible (unauth RCPT TO accepted): $([[ "${ds_accept}" == "true" ]] && echo yes || echo no)"

    echo "MX Records:"
    if jq -e '.dns.mx? | length>0' > /dev/null 2>&1 <<< "${merged}"; then
        jq -r '.dns.mx[]? // empty' <<< "${merged}" | sed 's/^/ - /'
    else
        echo "              - N/A"
    fi

    echo "TXT (SPF/DMARC):"
    if [[ -n "${spf_join}" ]]; then echo "              - SPF: ${spf_join}"; else echo "              - SPF: not found"; fi
    if [[ -n "${dmarc_join}" ]]; then echo "              - DMARC: ${dmarc_join}"; else echo "              - DMARC: not found"; fi

    # ---------- Conditional Access / Legacy Auth ----------
    echo
    info "[+] Entra Signals:"
    jq -r '
      "              - Conditional Access signals: "
      + (if (.conditional_access.present // false) then "present" else "not indicated" end)
    ' <<< "${merged}"
    jq -r '
      "              - Legacy Auth signals: "
      + (if (.legacy_auth.present // false) then "present" else "not indicated" end)
    ' <<< "${merged}"

    # ---------- Provisioning Endpoints (detail) ----------
    echo
    info "[+] Provisioning Endpoints (detail):"
    jq -r '
      (.tenant_config.provisioning // {}) as $p
      | if ($p|type)!="object" or ($p|length)==0
        then "              - None"
        else
          $p | to_entries[]
            | "              - " + .key + ": " + (.value.status // "unknown")
              + " | HTTP " + (.value.http // "000")
              + (if (.value.url // "") != "" then " | " + .value.url else "" end)
        end
    ' <<< "${merged}"

    # ---------- Microsoft Defender for Identity (unauth) ----------
    echo
    info "[+] Microsoft Defender for Identity:"
    jq -r '
      if (.mdi_instance.detected // false)
        then "              - Presence: Yes"
        else "              - Presence: No"
      end
    ' <<< "${merged}"

    # ---------- Azure Services (Passive CNAME Hints) ----------
    echo
    info "[+] Azure Services (Passive CNAME Hints):"
    jq -r '
      (.azure_services.hints // []) as $h |
      if ($h|length) == 0 then
        "              - None"
      else
        $h[]
        | "              - " + (.host // "?")
          + ": "
          + ( ((.cname // []) | map(tostring) | join(", ")) // "n/a" )
          + (if (.status // "") != "" then " [" + .status + "]" else "" end)
      end
    ' <<< "${merged}"

    # ---------- Azure Services (Deep Sweep) ----------
    echo
    info "[+] Azure Services (Deep Sweep):"
    jq -r '
      (.azure_services_deep.hits // []) as $hits
      | if ($hits|length)==0
        then "              - N/A"
        else  "              - " + (( $hits|length )|tostring) + " hits"
        end
    ' <<< "${merged}"

    # ---------- Azure explicit surfaces ----------
    echo
    info "[+] Azure App Services:"
    jq -r '
      def http_ok($c): ($c|tostring|test("^(2|3)[0-9][0-9]$"));
      def show($n;$u;$s): "              - " + ($n // ($u // "?")) + " | " + ($u // "?") + " | HTTP " + ($s|tostring);

      (.azure_services.app_services // null) as $as |
      if $as == null then
        "              - None"
      elif ($as|type) == "object" then
        [ $as
          | to_entries[]
          | select(.key|test("^https?://"))                # keep only URL-like keys
          | ( .value as $v
              | (if ($v|type)=="object" then $v else {} end) ) as $v
          | select( $v.status? and http_ok($v.status) )
          | show( $v.name; $v.url // .key; $v.status )
        ]
        | if length==0 then "              - None" else .[] end
      elif ($as|type) == "array" then
        [ $as[]
          | select(.url? and .status?)
          | select(http_ok(.status))
          | show(.name; .url; .status)
        ]
        | if length==0 then "              - None" else .[] end
      else
        "              - None"
      end
    ' <<< "${merged}"

    echo
    info "[+] Azure Storage Accounts:"
    jq -r '
      (.azure_services.storage_accounts // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[]
          | "              - " + (.url // "?") + " (" + (.status // "unknown") + ")"
        end
    ' <<< "${merged}"

    echo
    info "[+] Power Apps Portals:"
    jq -r '
      (.azure_services.power_apps // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[] | "              - " + .
        end
    ' <<< "${merged}"

    echo
    info "[+] Azure CDN Endpoints:"
    jq -r '
      (.azure_services.cdn_endpoints // []) as $a
      | if ($a|length)==0 then
          "              - None"
        else
          $a[] | "              - " + .
        end
    ' <<< "${merged}"

    # ---------- Azure AD Applications ----------
    echo
    info "[+] Azure AD Applications:"
    jq -r '
      if (.graph.applications|type=="array") and ((.graph.applications|length) > 0)
        then "              - " + ((.graph.applications|length)|tostring) + " application(s) (Graph)"
      elif (.aad_applications.endpoints|type=="object")
        then "              - Unauth endpoint hints present (issuer/authorization/token)"
      else
        "              - N/A"
      end
    ' <<< "${merged}"
    jq -r '
      (.oidc.tenant_id // "") as $tid
      | if ($tid|length) > 0
          then " Admin Consent URL: https://login.microsoftonline.com/" + $tid + "/adminconsent"
          else empty
        end
    ' <<< "${merged}"

    # ---------- Findings (from analysis) ----------
    echo
    info "[+] Alerts / Inferences / Issues:"
    echo "Risk Score: ${risk}"
    if jq -e '.analysis.findings? | length>0' > /dev/null 2>&1 <<< "${merged}"; then
        while IFS= read -r f; do
            if grep -Eqi '(good|reject\b|EOP.*in use)' <<< "${f}"; then
                echo " [+] ${f}"
            elif grep -Eqi '(not|fail|no |\\+all|404|none\))' <<< "${f}"; then
                echo " [!] ${f}"
            else
                echo " [*] ${f}"
            fi
        done < <(jq -r '.analysis.findings[]? // empty' <<< "${merged}")
    else
        echo " [*] No findings recorded."
    fi

    info "==============================================="
}
