#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : services_recon.sh
# DESCRIPTION  : SharePoint/Teams/B2C/SAML discovery checks. SaaS & IdP fingerprinting via URL list providers.
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
# SharePoint / Teams / B2C / SAML
#==============================================================================

###############################################################################
# check_sharepoint
#==================
# Purpose:
#   Discover probable tenant prefixes and confirm SharePoint/OneDrive by probing
#   /_vti_bin/client.svc and verifying the WWW-Authenticate: Bearer realm header.
#
# Arguments:
#   $1 - domain (e.g., contoso.com)
#   $2 - optional: newline-separated file of candidate tenant prefixes
#
# Output:
#   {
#     "sharepoint": {
#       "tested_prefixes": ["contoso","contosoinc","contoso-com"],
#       "confirmed_prefix": "contoso",
#       "sharepoint": {"url":"https://contoso.sharepoint.com/_vti_bin/client.svc","status":401,"bearer_realm":true},
#       "onedrive":  {"url":"https://contoso-my.sharepoint.com/_vti_bin/client.svc","status":401,"bearer_realm":true}
#     }
#   }
###############################################################################
function check_sharepoint() {
    local domain="${1}"
    local prefix_file="${2:-}"

    info "SharePoint: discovering tenant prefix and verifying Bearer realm for ${domain} ..."

    # Build candidate prefixes: left label, dotted->dash, strip symbols, plus optional file.
    local base="${domain%%.*}"
    local naked="${domain//./}"
    local dash="${domain//./-}"
    local nohyphen="${naked//-/}"
    local -a cand=("${base}" "${dash}" "${naked}" "${nohyphen}")

    if [[ -n "${prefix_file}" && -r "${prefix_file}" ]]; then
        while IFS= read -r p; do
            [[ -z "$p" ]] && continue              # skip blank lines
            [[ "$p" =~ ^[[:space:]]*# ]] && continue  # skip comments
            cand+=("$p")
        done < "$prefix_file"
    fi

    # Dedup
    local -A seen=()
    local -a uniq=()
    for p in "${cand[@]}"; do
        [[ -z "${p}" ]] && continue
        if [[ -z "${seen[$p]+x}" ]]; then
            uniq+=("$p")
            seen[$p]=1
        fi
    done
    cand=("${uniq[@]}")

    local confirmed="" sp_code=0 sp_bearer=false od_code=0 od_bearer=false

    # Helper to HEAD and sniff Bearer realm
    head_with_bearer() {
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

    for t in "${cand[@]}"; do
        local sp_host="${t}.sharepoint.com"
        local od_host="${t}-my.sharepoint.com"

        # Only probe hosts that resolve
        if resolve_host "$sp_host"; then
            local r
            IFS='|' read -r sp_code sp_bearer _ < <(head_with_bearer "https://${sp_host}/_vti_bin/client.svc")
        fi
        if resolve_host "$od_host"; then
            local r2
            IFS='|' read -r od_code od_bearer _ < <(head_with_bearer "https://${od_host}/_vti_bin/client.svc")
        fi

        if [[ "$sp_bearer" == "true" || "$od_bearer" == "true" ]]; then
            confirmed="$t"
            break
        fi
    done

    jq -n \
        --argjson tested "$(printf '%s\n' "${cand[@]}" | jq -R . | jq -s .)" \
        --arg conf "$confirmed" \
        --arg spu "https://${confirmed:-${cand[0]}}.sharepoint.com/_vti_bin/client.svc" \
        --arg odu "https://${confirmed:-${cand[0]}}-my.sharepoint.com/_vti_bin/client.svc" \
        --arg spc "$sp_code" \
        --arg odc "$od_code" \
        --arg spb "$sp_bearer" \
        --arg odb "$od_bearer" \
        '{
         sharepoint: {
           tested_prefixes: $tested,
           confirmed_prefix: ( $conf | select(. != "") ),
           sharepoint: { url:$spu, status: ($spc|tonumber? // 0), bearer_realm: ($spb=="true") },
           onedrive:  { url:$odu, status: ($odc|tonumber? // 0), bearer_realm: ($odb=="true") }
         }
       }'
}

###############################################################################
# check_teams_presence
#======================
# Purpose:
#   Combine SRV counts with target validation for Microsoft endpoints.
#
# Arguments:
#   $1 - srv_json (expects .srv.sip_tls[], .srv.sipfederation_tls[],
#                  .cname.lyncdiscover, .cname.sip if available)
#
# Output:
#   {
#     "teams": {
#       "sip_srv_present": true,
#       "sipfed_srv_present": true,
#       "srv_targets_valid": true,
#       "lyncdiscover_valid": true,
#       "sip_cname_valid": true,
#       "portal_status": 200
#     }
#   }
###############################################################################
function check_teams_presence() {
    local srv_json="${1}"

    info "Teams: validating SRV targets and CNAMEs ..."

    local sip_n sipf_n
    sip_n="$(jq '(.srv.sip_tls|length) // 0' <<< "${srv_json}")"
    sipf_n="$(jq '(.srv.sipfederation_tls|length) // 0' <<< "${srv_json}")"

    # Extract targets, when present
    local srv_targets
    srv_targets="$(jq -r '[.srv.sip_tls[]?.target?, .srv.sipfederation_tls[]?.target?] | map(select(.!=null)) | unique[]?' <<< "${srv_json}" 2> /dev/null || true)"
    local srv_valid=false
    if grep -qiE '(^|\.)(sipdir\.online\.lync\.com)$' <<< "${srv_targets}"; then
        srv_valid=true
    fi

    local lync_cname sip_cname
    lync_cname="$(jq -r '.cname.lyncdiscover // empty' <<< "${srv_json}")"
    sip_cname="$(jq -r '.cname.sip // empty' <<< "${srv_json}")"

    local lync_valid=false sip_valid=false
    [[ -n "${lync_cname}" ]] && [[ "${lync_cname,,}" == *"webdir.online.lync.com."* || "${lync_cname,,}" == *"webdir.online.lync.com"* ]] && lync_valid=true
    [[ -n "${sip_cname}"  ]] && [[ "${sip_cname,,}" == *"sipdir.online.lync.com."* || "${sip_cname,,}" == *"sipdir.online.lync.com"*     ]] && sip_valid=true

    local portal="https://teams.microsoft.com"
    local code
    code="$(run_with_timeout 7s curl -s -o /dev/null -w '%{http_code}' -m 7 -A "${CURL_UA}" "${portal}" || true)"

    jq -n \
        --argjson sip "${sip_n}" --argjson sipf "${sipf_n}" \
        --argjson srvv "${srv_valid}" \
        --argjson lyncv "${lync_valid}" \
        --argjson sipcv "${sip_valid}" \
        --arg code "${code}" \
        '{ teams: {
           sip_srv_present:   ($sip>0),
           sipfed_srv_present:($sipf>0),
           srv_targets_valid: $srvv,
           lyncdiscover_valid:$lyncv,
           sip_cname_valid:   $sipcv,
           portal_status:     ($code|tonumber? // 0)
      }}'
}

###############################################################################
# check_b2c_configuration
#=========================
# Purpose:
#   Probe Azure AD B2C well-known endpoints using candidate tenant identifiers.
#   Supports /tfp/ and /te/ flavors and national clouds (Public/.us/.cn).
#
# Arguments:
#   $1 - domain
#   $2 - optional: newline-separated file of candidate tenant IDs or names
#        (e.g., "contoso", "contoso.onmicrosoft.com", tenant GUID)
#   $3 - optional: cloud hint ("public"|"us"|"cn"), defaults to detect from realm
#
# Output:
#   {
#     "b2c": {
#       "cloud": "public",
#       "tested_tenants": ["contoso","contoso.onmicrosoft.com"],
#       "discoveries": [
#         {"url":"https://contoso.b2clogin.com/contoso.onmicrosoft.com/tfp/B2C_1_signupsignin1/v2.0/.well-known/openid-configuration","status":200},
#         {"url":"https://contoso.b2clogin.com/te/contoso.onmicrosoft.com/B2C_1A_signup_signin/v2.0/.well-known/openid-configuration","status":404}
#       ]
#     }
#   }
###############################################################################
function check_b2c_configuration() {
    local domain="${1}"
    local tenant_file="${2:-}"
    local cloud="${3:-}"

    info "B2C: probing tenant discovery for ${domain} ..."

    # Build candidate tenant identifiers.
    local base="${domain%%.*}"
    local -a tenants=("${base}" "${base}.onmicrosoft.com")
    if [[ -r "${tenant_file}" ]]; then
        while IFS= read -r t; do
            [[ -n "${t}" ]] && tenants+=("${t}")
        done < <(grep -vE '^\s*(#|$)' "${tenant_file}")
    fi
    # Dedup
    local -A seen=()
                      local -a uniq=()
    for t in "${tenants[@]}"; do
        [[ -z "${t}" ]] && continue
        if [[ -z "${seen[$t]+x}" ]]; then
            uniq+=("$t")
            seen[$t]=1
        fi
    done
    tenants=("${uniq[@]}")

    # Cloud base hostname
    case "${cloud,,}" in
        us) local host_tmpl='%s.b2clogin.com' ;;   # AAD B2C in Azure Gov often still uses b2clogin.com, but realm detection is safer
        cn) local host_tmpl='%s.b2clogin.cn' ;;
        *)  local host_tmpl='%s.b2clogin.com' ;;  # public
    esac

    # Common policy names to try (best-effort)
    local -a policies=("B2C_1_signupsignin1" "B2C_1A_signup_signin")
    local -a patterns=(
        "%s/%s/tfp/%s/v2.0/.well-known/openid-configuration"
        "%s/te/%s/%s/v2.0/.well-known/openid-configuration"
    )

    local -a tested_urls=()

    for tenant in "${tenants[@]}"; do
        # host is built from the *tenant label without suffix* when provided in long form
        local label="${tenant%%.*}"  # "contoso" from "contoso.onmicrosoft.com"
        local host
        printf -v host "${host_tmpl}" "${label}"

        for pol in "${policies[@]}"; do
            for pat in "${patterns[@]}"; do
                local path
                printf -v path "${pat}" "https://${host}" "${tenant}" "${pol}"

                local code
                code="$(run_with_timeout 7s curl -s -o /dev/null -w '%{http_code}' -m 7 -A "${CURL_UA}" "${path}" || true)"

                tested_urls+=("$(jq -n --arg u "${path}" --argjson c "${code}" '{url:$u,status:$c}')")
            done
        done
    done

    # Stitch JSON array
    local joined
    joined="$(printf '%s\n' "${tested_urls[@]}" | jq -s '.')"

    jq -n \
        --arg cloud "${cloud:-public}" \
        --argjson tenants "$(printf '%s\n' "${tenants[@]}" | jq -R . | jq -s .)" \
        --argjson disc "${joined}" \
        '{ b2c: { cloud:$cloud, tested_tenants:$tenants, discoveries:$disc } }'
}

###############################################################################
# check_saml_endpoints
#======================
# Purpose:
#   If the realm data indicates federation, surface the IdP authorization URL
#   (commonly SAML/ADFS) as a discovery artifact for further analysis.
#
# Globals:
#   (none)
#
# Arguments:
#   $1 - realm_json (string containing JSON with .realm.AuthURL)
#
# Output (stdout):
#   {
#     "saml": { "federation_auth_url":"https://idp.contoso.com/adfs/ls/..." }
#   }
#   OR
#   { "saml": { "note":"no_federation_auth_url" } }
###############################################################################
function check_saml_endpoints() {
    local realm_json="${1}"

    local auth_url
    auth_url="$(jq -r '.realm.AuthURL // empty' <<< "${realm_json}")"

    if [[ -z "${auth_url}" ]]; then
        jq -n '{ saml: { note:"no_federation_auth_url" } }'
    else
        jq -n --arg u "${auth_url}" '{ saml: { federation_auth_url:$u } }'
    fi
}

#==============================================================================
# SaaS/IdP fingerprints (URL list providers)
#==============================================================================

###############################################################################
# do_saas_idp_probe_basic_list
#------------------------------------------------------------------------------
# PURPOSE:
#   Emit a small, **low-noise** list of SaaS/IdP vanity/portal URLs derived
#   from a base domain. These are commonly fruitful with minimal false positives.
#
# ARGUMENTS:
#   $1 - domain (e.g., example.com)
#
# OUTPUT (stdout):
#   Plain text lines (URLs), suitable for piping to curl loop.
###############################################################################
function do_saas_idp_probe_basic_list() {
    local domain="${1}"
    local prefix="${2}"

    cat << EOF
https://${domain}.okta.com
https://${domain}.okta-emea.com
https://${domain}.auth0.com
https://${domain}.onelogin.com
https://${domain}.pingidentity.com
https://${domain}.my.salesforce.com
https://${domain}.atlassian.net
https://${domain}.webex.com
https://${prefix}.okta.com
https://${prefix}.okta-emea.com
https://${prefix}.auth0.com
https://${prefix}.onelogin.com
https://${prefix}.pingidentity.com
https://${prefix}.my.salesforce.com
https://${prefix}.atlassian.net
https://${prefix}.webex.com
EOF
}

###############################################################################
# do_saas_idp_probe_extended_list
#------------------------------------------------------------------------------
# PURPOSE:
#   Emit a **broader** (still curated) list of common SaaS/IdP URLs for probing.
#   This widens coverage (Okta/Auth0/Ping/OneLogin, ADFS, MS/SaaS portals like
#   Salesforce, Atlassian, Workday, ServiceNow, Box, Dropbox, Slack, Zoom/Webex,
#   Zscaler, Duo, JumpCloud, GitHub/GitLab).
#
# ARGUMENTS:
#   $1 - domain (e.g., example.com)
#
# OUTPUT (stdout):
#   Plain text lines (URLs), suitable for piping to curl loop.
###############################################################################
function do_saas_idp_probe_extended_list() {
    local domain="${1}"
    local prefix="${2}"

    cat << EOF
https://${domain}.okta.com
https://${domain}.okta-emea.com
https://${domain}.auth0.com
https://${domain}.onelogin.com
https://${domain}.pingidentity.com
https://${domain}.pingone.com
https://${domain}.my.salesforce.com
https://${domain}.atlassian.net
https://${domain}.workday.com
https://${domain}.service-now.com
https://${domain}.zoom.us
https://${domain}.webex.com
https://${domain}.github.com
https://${domain}.gitlab.com
https://${domain}.box.com
https://${domain}.dropbox.com
https://${domain}.slack.com
https://${domain}.zscaler.net
https://${domain}.duosecurity.com
https://${domain}.jumpcloud.com
https://login.${domain}/adfs/ls
https://${prefix}.onmicrosoft.com
https://login.microsoftonline.com/${prefix}.onmicrosoft.com
https://${prefix}.b2clogin.com
https://${prefix}-my.sharepoint.com
https://${prefix}.sharepoint.com
https://teams.microsoft.com/l/domain/${domain}
https://mail.${domain}
https://outlook.${domain}
https://portal.${domain}
https://autodiscover.${domain}/autodiscover.xml
https://autodiscover.${domain}/autodiscover/autodiscover.xml
https://adfs.${domain}
https://adfs.${domain}/adfs/ls/idpinitiatedsignon.aspx
https://${prefix}.okta.com
https://${prefix}.kerberos.okta.com
https://${prefix}.oktapreview.com
https://${prefix}.awsapps.com
https://${prefix}.awsapps.com/start
https://${prefix}.onelogin.com
https://${prefix}.auth0.com
https://${prefix}.verify.ibm.com
https://${prefix}.pingidentity.com
https://${prefix}.duosecurity.com
https://${prefix}.slack.com
https://${prefix}.atlassian.net
https://${prefix}.service-now.com
https://${prefix}.my.salesforce.com
https://${prefix}.webex.com
https://${prefix}.zendesk.com
https://${prefix}.freshdesk.com
https://${prefix}.myshopify.com
https://${prefix}.dropbox.com
https://${prefix}.box.com
https://${prefix}.hubspot.com
https://${prefix}.githubenterprise.com
https://${prefix}.gitlab.com
https://${prefix}.herokuapp.com
https://${prefix}.netlify.app
https://${prefix}.vercel.app
https://${prefix}.zoom.us
https://${prefix}.gotomeeting.com
https://${prefix}.bluejeans.com
https://${prefix}.trello.com
https://${prefix}.asana.com
https://${prefix}.monday.com
https://${prefix}.basecamp.com
https://${prefix}.smartsheet.com
https://${prefix}.workday.com
https://${prefix}.oraclecloud.com
https://${prefix}.sapcloud.io
https://${prefix}.crowdstrike.com
https://${prefix}.xdr.us.paloaltonetworks.com
https://${prefix}.workspaceoneaccess.com
https://${prefix}.proofpoint.com
https://${prefix}.zscaler.net
https://${prefix}.cloudflareaccess.com
https://${prefix}.cloud.com
https://${prefix}.insight.rapid7.com
https://${prefix}.splunkcloud.com
https://${prefix}.snowflakecomputing.com
https://${prefix}.sentinelone.net
https://${prefix}.crm.dynamics.com
EOF
}

###############################################################################
# do_saas_idp_probe
#------------------------------------------------------------------------------
# PURPOSE:
#   Perform **lightweight reachability probes** (status codes) against a list of
#   SaaS/IdP vanity URLs. Supports a basic or extended built-in catalog and an
#   optional user-supplied list to append.
#
# ARGUMENTS:
#   $1 - domain        (e.g., example.com)
#   $2 - extended      (1 = use extended list; 0 = basic list)
#   $3 - extra_file    (optional path to readable file with additional URLs;
#                       comment/blank lines allowed)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "saas_idp": {
#       "probes": [ { "url":"...", "status":200 }, ... ]
#     }
#   }
#
# NOTES:
#   - Purely **best-effort**: a 200/302/etc. doesn’t prove tenancy, just
#     indicates a live host at that vanity pattern.
###############################################################################
function do_saas_idp_probe() {
    local domain="${1}"
    local extended="${2}"
    local extra_file="${3:-}"
    local tenant_prefix="${4:-}"

    info "Checking for SaaS/IdP vanity URLs for ${domain} ..."

    # Derive a sane default tenant prefix if not supplied.
    if [[ -z "${tenant_prefix}" ]]; then
        tenant_prefix="${domain%%.*}"
    fi

    local ua="${CURL_UA:-Mozilla/5.0}"
    info "SaaS/IdP: probing vanity/portal URLs for ${domain} (prefix=${tenant_prefix}; extended=${extended}) ..."

    local results="[]"
    local u="" code="0"

    # Build the URL list into a temp file.
    local urls_file
    urls_file="$(mktemp 2> /dev/null || printf '/tmp/saas_urls_%s' "$$")"

    # Generate candidate URLs using the appropriate catalog, passing BOTH args.
    if [[ "${extended}" -eq 1 ]]; then
        do_saas_idp_probe_extended_list "${domain}" "${tenant_prefix}" > "${urls_file}"
    else
        do_saas_idp_probe_basic_list "${domain}" "${tenant_prefix}" > "${urls_file}"
    fi

    # Append user-supplied extras if provided.
    if [[ -n "${extra_file}" && -r "${extra_file}" ]]; then
        # Filter out blanks/comments.
        grep -vE '^\s*(#|$)' "${extra_file}" >> "${urls_file}" 2> /dev/null || true
    fi

    # Dedup url list
    mapfile -t urls < <(awk '!seen[$0]++' "${urls_file}")

    # Temp file to collect one-JSON-per-line
    local outfile
                   outfile="$(mktemp)"
    : > "${outfile}"

    if command -v xargs > /dev/null 2>&1; then
        printf '%s\n' "${urls[@]}" \
                                   | xargs -P 8 -n 1 -I {} bash -c '
            u="$1"
            code=$(curl -s -o /dev/null -w "%{http_code}" -m 6 --retry 0 -A "${CURL_UA}" "$u" 2>/dev/null || true)
            # SINGLE-QUOTED jq program so $u/$c are jq vars, not shell
            jq -n --arg u "$u" --arg c "$code" '"'"'{url:$u, status:($c|tonumber? // 0)}'"'"'
        ' _ {} >> "${outfile}"
    else
        for u in "${urls[@]}"; do
            code="$(curl -s -o /dev/null -w '%{http_code}' -m 6 --retry 0 -A "${CURL_UA}" "$u" 2> /dev/null || true)"
            jq -n --arg u "$u" --arg c "$code" '{url:$u, status:($c|tonumber? // 0)}' >> "${outfile}"
        done
    fi

    # Aggregate
    local arr
               arr="$(jq -s '.' < "${outfile}")"
    rm -f "${outfile}" 2> /dev/null || true

    jq -n --argjson r "${arr}" '{ saas_idp: { probes: $r } }'
}
