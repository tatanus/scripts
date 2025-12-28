#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : entra_azure_recon.sh
# DESCRIPTION  : Entra ID unauthenticated discovery and tenant posture checks. Unauthenticated probing of Azure surfaces and services.
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

###############################################################################
# check_tenant_branding
#=======================
# Purpose:
#   Parse realm discovery JSON and extract branding/identity-mode properties
#   commonly returned by the getuserrealm endpoint (Managed vs. Federated,
#   federation brand name, protocol, etc.).
#
# Inputs:
#   - Expects the full JSON string previously returned by do_realm_discovery,
#     which has the envelope: { "realm": { ...fields from Microsoft... } }
#
# Globals:
#   (none)
#
# Arguments:
#   $1 - realm_json (string containing JSON)
#
# Output (stdout):
#   {
#     "tenant_branding": {
#       "name_space_type":       "Managed|Federated|Unknown",
#       "domain_name":           "contoso.com",
#       "federation_brand_name": "Contoso",
#       "cloud_instance":        "AzurePublicCloud|AzureUSGovernment|AzureChinaCloud|...",
#       "auth_url":              "https://idp.contoso.com/adfs/ls/...",
#       "federation_protocol":   "WSTrust|SAML|Unknown",
#       "state":                 "Active|Disabled|Unknown"
#     }
#   }
#
# Notes:
#   - Each field is extracted defensively; absent values become empty strings.
###############################################################################
function check_tenant_branding() {
    local realm_json="${1}"

    info "Tenant: evaluating branding & identity mode from realm JSON ..."

    # Extract known fields defensively. jq -r with // empty ensures empty string
    # on missing keys instead of 'null'.
    local ns_type domain_name fed_brand cloud_instance auth_url fed_protocol state
    ns_type="$(jq -r '.realm.NameSpaceType        // empty' <<< "${realm_json}")"
    domain_name="$(jq -r '.realm.DomainName        // empty' <<< "${realm_json}")"
    fed_brand="$(jq -r '.realm.FederationBrandName // empty' <<< "${realm_json}")"
    cloud_instance="$(jq -r '.realm.CloudInstanceName // empty' <<< "${realm_json}")"
    auth_url="$(jq -r '.realm.AuthURL             // empty' <<< "${realm_json}")"
    fed_protocol="$(jq -r '.realm.FederationProtocol // empty' <<< "${realm_json}")"
    state="$(jq -r '.realm.State                  // empty' <<< "${realm_json}")"

    # Emit a normalized, namespaced object.
    jq -n \
        --arg ns "${ns_type}" \
        --arg dn "${domain_name}" \
        --arg fb "${fed_brand}" \
        --arg ci "${cloud_instance}" \
        --arg au "${auth_url}" \
        --arg fp "${fed_protocol}" \
        --arg st "${state}" \
        '{ tenant_branding:
           { name_space_type:$ns, domain_name:$dn, federation_brand_name:$fb,
             cloud_instance:$ci, auth_url:$au, federation_protocol:$fp, state:$st } }'
}

###############################################################################
# check_legacy_auth
#===================
# Purpose:
#   Heuristically assess exposure of legacy authentication on Exchange Online
#   endpoints by probing EWS and ActiveSync. No credentials are used; this
#   inspects HTTP status and WWW-Authenticate headers only.
#
# Globals:
#   (none)
#
# Arguments:
#   $1 - outlook_host (e.g., "outlook.office365.com" or cloud-variant)
#
# Output (stdout):
#   {
#     "legacy_auth": {
#       "ews": { "url":"...", "status":200, "www_auth":"Basic ...; Bearer ...; ..." },
#       "eas": { "url":"...", "status":401, "www_auth":"Bearer ..." }
#     }
#   }
#
# Notes:
#   - Presence of "Basic" in WWW-Authenticate does not guarantee it’s enabled
#     tenant-wide; it’s a signal only. The analyzer interprets this conservatively.
###############################################################################
function check_legacy_auth() {
    local outlook_host="${1}"

    info "Legacy Auth: probing EWS and ActiveSync headers on ${outlook_host} ..."

    # Target endpoints
    local ews="https://${outlook_host}/EWS/Exchange.asmx"
    local eas="https://${outlook_host}/Microsoft-Server-ActiveSync"

    # Fetch headers only (-I) with moderate timeouts; tolerate errors and capture raw.
    local s1 s2
    s1="$(run_with_timeout 7s curl -sSI -m 7 --retry 0 -A "${CURL_UA}" "${ews}" 2> /dev/null || true)"
    s2="$(run_with_timeout 7s curl -sSI -m 7 --retry 0 -A "${CURL_UA}" "${eas}" 2> /dev/null || true)"

    # Consolidate WWW-Authenticate header lines (there may be multiple).
    local h1 h2
    h1="$(grep -i '^WWW-Authenticate:' <<< "${s1}" | tr -d '\r' | paste -sd ';' - || true)"
    h2="$(grep -i '^WWW-Authenticate:' <<< "${s2}" | tr -d '\r' | paste -sd ';' - || true)"

    # Extract HTTP codes from the first status line.
    local c1 c2
    c1="$(grep -i '^HTTP/' <<< "${s1}" | awk '{print $2}' | head -n 1)"
    c2="$(grep -i '^HTTP/' <<< "${s2}" | awk '{print $2}' | head -n 1)"

    # Emit structured JSON with numeric status (0 on parse failure).
    jq -n \
        --arg ews "${ews}" --arg eas "${eas}" \
        --arg h1 "${h1}" --arg h2 "${h2}" \
        --arg c1 "${c1}" --arg c2 "${c2}" \
        '{ legacy_auth:
           { ews:{url:$ews, status:($c1|tonumber? // 0), www_auth:$h1},
             eas:{url:$eas, status:($c2|tonumber? // 0), www_auth:$h2} } }'
}

###############################################################################
# check_conditional_access
#==========================
# Purpose:
#   Very lightweight heuristic for Conditional Access visibility by testing the
#   tenant's device-authorization endpoint (from OIDC discovery) for reachability.
#   No credentials are used; only HTTP status is observed.
#
# Globals:
#   (none)
#
# Arguments:
#   $1 - device_endpoint (e.g., ".../oauth2/v2.0/devicecode")
#
# Output (stdout):
#   {
#     "conditional_access": {
#       "device_authorization_endpoint":"https://...",
#       "status": 200
#     }
#   }
#
# Notes:
#   - A 200/400 typically means reachable/working; network blocks or unusual
#     policies could yield 403/404/5xx. This is a heuristic, not a verdict.
###############################################################################
function check_conditional_access() {
    local device_endpoint="${1}"

    info "Conditional Access: probing device authorization endpoint ..."

    # If the caller didn't supply an endpoint (e.g., OIDC discovery failed),
    # return a clear error object instead of empty/null.
    if [[ -z "${device_endpoint}" ]]; then
        jq -n '{ conditional_access: { error:"no_device_authorization_endpoint" } }'
        return 0
    fi

    # Fetch only HTTP code, with sane timeout.
    local code
    code="$(run_with_timeout 7s curl -s -o /dev/null -w '%{http_code}' -m 7 --retry 0 -A "${CURL_UA}" "${device_endpoint}" || true)"

    jq -n --arg u "${device_endpoint}" --arg c "${code}" \
        '{ conditional_access: { device_authorization_endpoint:$u, status: ($c|tonumber? // 0) } }'
}

###############################################################################
# check_provisioning_endpoints
#==============================
# Purpose:
#   Probe tenant provisioning endpoints unauthenticated to infer whether
#   B2B invitations and device join/enrollment are reachable.
# Arguments:
#   $1 - login_host (e.g., login.microsoftonline.com / .us / .cn)
#   $2 - tenant_id (GUID)
# Output:
#   { tenant_config: { provisioning: { b2b:{...}, device_registration:{...}, device_management:{...} } } }
###############################################################################
function check_provisioning_endpoints() {
    local login_host="${1}"
    local tenant_id="${2}"

    if [[ -z "${tenant_id}" ]]; then
        jq -n '{ tenant_config: { provisioning: {} } }'
        return 0
    fi

    declare -A endpoints
    endpoints["b2b"]="https://${login_host}/${tenant_id}/B2B/invite"
    endpoints["device_registration"]="https://enterpriseregistration.windows.net/${tenant_id}/join"
    endpoints["device_management"]="https://enrollment.manage.microsoft.com/${tenant_id}/enrollmentserver/discovery.svc"

    local obj="{}"
    local name url code status
    for name in "${!endpoints[@]}"; do
        url="${endpoints[${name}]}"
        code="$(http_status_only "${url}")"
        status="not_found"
        if [[ "${code}" == "200" ]]; then
            status="accessible"
        elif [[ "${code}" =~ ^(401|403)$ ]]; then
            status="protected"
        fi
        obj="$(jq -n --arg k "${name}" --arg s "${status}" --arg u "${url}" \
            --arg c "${code}" \
            --argjson cur "${obj}" \
            '$cur + { ($k): { status:$s, url:$u, http:$c } }')"
    done

    jq -n --argjson x "${obj}" '{ tenant_config: { provisioning: $x } }'
}

###############################################################################
# check_aad_connect_status
#==========================
# Purpose:
#   Summarize Managed vs Federated (hybrid) identity posture using
#   getuserrealm.srf unauthenticated JSON.
# Arguments:
#   $1 - login_host
#   $2 - domain (UPN suffix, e.g., example.com)
# Output:
#   { aad_connect: { ... } }
###############################################################################
function check_aad_connect_status() {
    local login_host="${1}"
    local domain="${2}"
    local upn="nonexistent@${domain}"
    local url="https://${login_host}/getuserrealm.srf?login=${upn}&json=1"

    local body=""
    body="$(run_with_timeout 9s curl -fsS -m 9 --retry 1 -A "${CURL_UA}" "${url}" 2> /dev/null || true)"

    if jq -e . > /dev/null 2>&1 <<< "${body}"; then
        local name_space_type domain_type fed_brand cloud_instance auth_url fed_ver hybrid
        name_space_type="$(jq -r '.NameSpaceType // "Unknown"' <<< "${body}")"
        domain_type="$(jq -r '.DomainType // "Unknown"' <<< "${body}")"
        fed_brand="$(jq -r '.FederationBrandName // "Unknown"' <<< "${body}")"
        cloud_instance="$(jq -r '.CloudInstanceName // "Unknown"' <<< "${body}")"
        auth_url="$(jq -r '.AuthURL // empty' <<< "${body}")"
        fed_ver="$(jq -r '.FederationGlobalVersion // empty' <<< "${body}")"

        hybrid="Unknown"
        if [[ "${domain_type}" == "Federated" ]]; then
            hybrid="Federated (Hybrid Identity)"
        elif [[ "${domain_type}" == "Managed" ]]; then
            hybrid="Managed (Cloud Only)"
        fi

        jq -n \
            --arg n "${name_space_type}" --arg d "${domain_type}" --arg fb "${fed_brand}" \
            --arg ci "${cloud_instance}" --arg au "${auth_url}" --arg fv "${fed_ver}" --arg h "${hybrid}" '
          { aad_connect: {
              name_space_type: $n,
              domain_type: $d,
              federation_brand_name: $fb,
              cloud_instance: $ci
            } }
          |
          (if (($au|length)>0) or (($fv|length)>0) or (($h|length)>0)
           then . + { aad_connect: (.aad_connect + {
                    auth_url: (if ($au|length)>0 then $au else null end),
                    federation_version: (if ($fv|length)>0 then $fv else null end),
                    hybrid_config: (if ($h|length)>0 then $h else null end)
                }) }
           else . end)'
    else
        jq -n --arg e "Failed to parse getuserrealm response" '{ aad_connect: { error: $e } }'
    fi
}

###############################################################################
# get_domains
#=============
# Purpose:
#   Use Exchange Autodiscover SOAP GetFederationInformation to enumerate
#   accepted domains and derive the onmicrosoft tenant name. Unauthenticated.
# Arguments:
#   $1 - autodiscover host (e.g., autodiscover-s.outlook.com)
# Output:
#   { domains:[...], tenant:<name-or-null> }
###############################################################################
function get_domains() {
    local autod_host="${1}"

    local soap_body=""
    soap_body="$(
        cat << 'XML'
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:a="http://www.w3.org/2005/08/addressing"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/services/2006/messages/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <exm:GetFederationInformationRequestMessage>
      <exm:Request>
        <ext:Domain>example.com</ext:Domain>
      </exm:Request>
    </exm:GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>
XML
    )"

    local tmp=""
    tmp="$(mktemp)"
    printf '%s' "${soap_body}" > "${tmp}"

    local url="https://${autod_host}/autodiscover/autodiscover.svc"
    local code_and_body=""
    code_and_body="$(http_post_xml_status_and_body "${url}" "${tmp}")"
    rm -f "${tmp}" 2> /dev/null || true

    local code body
    code="$(head -n1 <<< "${code_and_body}")"
    body="$(tail -n +2 <<< "${code_and_body}")"

    # Accept 200/500 since SOAP faults may still carry the needed payload.
    if ! [[ "${code}" =~ ^(200|500)$ ]]; then
        jq -n '{ domains: [], tenant: null }'
        return 0
    fi

    local json_arr=""
    if command -v xmllint > /dev/null 2>&1; then
        json_arr="$(xmllint --xpath '//*[local-name()="Domain"]/text()' 2> /dev/null <<< "${body}" \
            | tr ' ' '\n' | sed '/^$/d' | jq -R -s -c 'split("\n")|map(select(length>0))' || true)"
    else
        json_arr="$(grep -oE '<[^:]*Domain>[^<]+' <<< "${body}" | sed -E 's/.*>(.*)$/\1/' \
            | jq -R -s -c 'split("\n")|map(select(length>0))' || true)"
    fi
    [[ -z "${json_arr}" ]] && json_arr='[]'

    local tenant_name=""
    tenant_name="$(jq -r '.[] | select(test("onmicrosoft\\.com$|partner\\.onmschina\\.cn$|onmicrosoft\\.us$")) | split(".")[0]' <<< "${json_arr}" | head -n1)"

    jq -n --argjson arr "${json_arr}" --arg tn "${tenant_name}" '
    {
      domains: $arr,
      tenant: (if ($tn|length)>0 then $tn else null end)
    }'
}

###############################################################################
# check_mdi_instance
#====================
# Purpose:
#   Unauthenticated probe for Microsoft Defender for Identity by resolving
#   <tenant>.atp.azure.com. If Graph token is provided, a richer inference is
#   performed elsewhere; this is the unauth fallback.
# Arguments:
#   $1 - tenant_name (onmicrosoft prefix), may be empty
# Output:
#   { mdi_instance: { detected:bool, details:string|null } }
###############################################################################
function check_mdi_instance() {
    local tenant_name="${1}"

    local detected="false"
    local details_json="null"

    if [[ -n "${tenant_name}" ]]; then
        local mdihost="${tenant_name}.atp.azure.com"
        # Try DNS A on the MDI host (best-effort).
        local ajson=""
        ajson="$(dns_query_generic "A" "${mdihost}" "1.1.1.1")"
        if jq -e '.|length>0' > /dev/null 2>&1 <<< "${ajson}"; then
            detected="true"
            details_json="$(jq -Rn --arg s 'MDI instance hostname resolved' '$s')"
        fi
    fi

    jq -n --argjson d "${detected}" --argjson det "${details_json}" \
        '{ mdi_instance: { detected: $d, details: $det } }'
}

###############################################################################
# check_aad_applications (unauth)
#--------------------------------
# Purpose:
#   Provide unauthenticated AAD application endpoint hints derived from OIDC.
#   If a Graph token is later supplied, authenticated collectors will augment
#   this with concrete Applications/Service Principals.
# Arguments:
#   $1 - issuer JSON from do_oidc_wellknown (full object)
# Output:
#   { aad_applications: { endpoints:{...}, insights:[...] } }
###############################################################################
function check_aad_applications() {
    local oidc_json="${1}"

    local issuer auth token devicecode
    issuer="$(jq -r '.oidc.issuer // empty' <<< "${oidc_json}" 2> /dev/null || true)"
    auth="$(jq -r '.oidc.authorization_endpoint // empty' <<< "${oidc_json}" 2> /dev/null || true)"
    token="$(jq -r '.oidc.token_endpoint // empty' <<< "${oidc_json}" 2> /dev/null || true)"
    devicecode="$(jq -r '.oidc.device_authorization_endpoint // empty' <<< "${oidc_json}" 2> /dev/null || true)"

    # Emit a minimal object in unauth mode.
    jq -n \
        --arg issuer "${issuer}" \
        --arg authorization_endpoint "${auth}" \
        --arg token_endpoint "${token}" \
        --arg device_authorization_endpoint "${devicecode}" \
        '{ aad_applications:
            { endpoints:
                { issuer:$issuer,
                  authorization_endpoint:$authorization_endpoint,
                  token_endpoint:$token_endpoint,
                  device_authorization_endpoint:$device_authorization_endpoint
                },
              insights:[]
            }
        }'
}

###############################################################################
# check_app_services
#--------------------
# Probe https://${domain_prefix}.azurewebsites.net and classify by HTTP status.
# Output:
#   { azure_services: { app_services: { "<url>":"accessible|auth_required|not_found" } } }
###############################################################################
function check_app_services() {
    local domain="${1}"
    local domain_prefix=""
    domain_prefix="$(_domain_prefix "${domain}")"
    local url="https://${domain_prefix}.azurewebsites.net"
    local code
    code="$(http_status_only "${url}")"
    local status="not_found"
    if [[ "${code}" == "200" ]]; then
        status="accessible"
    elif [[ "${code}" =~ ^(401|403)$ ]]; then
        status="auth_required"
    fi
    jq -n --arg url "${url}" --arg status "${status}" \
        '{ azure_services: { app_services: { ($url): $status } } }'
}

###############################################################################
# check_storage_accounts
#------------------------
# Probe common storage endpoints based on simple prefixes.
# Output:
#   { azure_services: { storage_accounts: [ {url,status}, ... ] } }
###############################################################################
function check_storage_accounts() {
    local domain="${1}"
    local domain_prefix=""
    domain_prefix="$(_domain_prefix "${domain}")"
    local -a prefixes=("storage" "blob" "data" "${domain_prefix}")
    local results="[]"
    local p url code status
    for p in "${prefixes[@]}"; do
        for url in \
            "https://${p}.blob.core.windows.net" \
            "https://${p}${domain_prefix}.blob.core.windows.net" \
            "https://${domain_prefix}${p}.blob.core.windows.net"; do
            code="$(http_status_only "${url}")"
            if [[ "${code}" =~ ^(200|401|403)$ ]]; then
                status="accessible"
                if [[ "${code}" =~ ^(401|403)$ ]]; then
                    status="auth_required"
                fi
                results="$(jq -n --arg url "${url}" --arg status "${status}" --argjson cur "${results}" \
                    '$cur + [ {url:$url,status:$status} ]')"
            fi
        done
    done
    jq -n --argjson arr "${results}" '{ azure_services: { storage_accounts: $arr } }'
}

###############################################################################
# check_power_apps
#------------------
# Probe Power Apps portal conventions.
# Output:
#   { azure_services: { power_apps: [urls...] } }
###############################################################################
function check_power_apps() {
    local domain="${1}"
    local domain_prefix=""
    domain_prefix="$(_domain_prefix "${domain}")"
    local -a urls=(
        "https://${domain_prefix}.powerappsportals.com"
        "https://${domain_prefix}.portal.powerapps.com"
    )
    local arr="[]"
    local url code
    for url in "${urls[@]}"; do
        code="$(http_status_only "${url}")"
        if [[ "${code}" =~ ^(200|401|403)$ ]]; then
            arr="$(jq -n --arg u "${url}" --argjson cur "${arr}" '$cur + [ $u ]')"
        fi
    done
    jq -n --argjson arr "${arr}" '{ azure_services: { power_apps: $arr } }'
}

###############################################################################
# check_azure_cdn
#-----------------
# Resolve common Azure CDN host patterns on azureedge.net.
# Output:
#   { azure_services: { cdn_endpoints: [hosts...] } }
###############################################################################
function check_azure_cdn() {
    local domain="${1}"
    local dns_server="${2}"
    local domain_prefix=""
    domain_prefix="$(_domain_prefix "${domain}")"
    local -a hosts=(
        "${domain_prefix}.azureedge.net"
        "${domain_prefix}-cdn.azureedge.net"
        "cdn-${domain_prefix}.azureedge.net"
    )
    local found="[]"
    local h ajson
    for h in "${hosts[@]}"; do
        ajson="$(dns_query_generic "A" "${h}" "${dns_server}")"
        if jq -e '.|length>0' > /dev/null 2>&1 <<< "${ajson}"; then
            found="$(jq -n --arg h "${h}" --argjson cur "${found}" '$cur + [ $h ]')"
        fi
    done
    jq -n --argjson arr "${found}" '{ azure_services: { cdn_endpoints: $arr } }'
}

###############################################################################
# check_azure_services
#======================
# Purpose:
#   Surface passive hints of Azure resources by resolving common subdomain
#   labels and inspecting CNAME targets for Azure hostnames (CDN, Storage,
#   App Service). This is non-intrusive and DNS-only.
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
#     "azure_services": {
#       "cdn.contoso.com":    {"cname":"...", "hint":"cdn"},
#       "files.contoso.com":  {"cname":"...", "hint":"storage"}
#     }
#   }
#
# Notes:
#   - The label list is intentionally small to avoid noise. Expand safely if
#     you have a vetted subdomain inventory.
###############################################################################
function check_azure_services() {
    local domain="${1}"
    local dns_server="${2}"

    info "Azure services: passive CNAME hints on common subdomains for ${domain} ..."

    # Pragmatic label set; add/remove as needed.
    local -a labels=(cdn static files media img blob storage app api www)

    # We'll accumulate into a JSON object string (obj); start as "{}".
    local obj="{}"

    local lbl host cname targets status
    for lbl in "${labels[@]}"; do
        host="${lbl}.${domain}"

        # Look up CNAME for the candidate host; json array -> take first entry string.
        cname="$(dns_query_generic "CNAME" "${host}" "${dns_server}")"
        targets="$(printf '%s\n' "${cname}" | jq -r '.[0] // empty')"

        # Classify common Azure backends.
        status="unknown"
        if grep -Eq 'azure(edge|fd)\.net$' <<< "${targets}"; then
            status="cdn"
        elif grep -Eq 'blob\.core\.windows\.net$' <<< "${targets}"; then
            status="storage"
        elif grep -Eq 'azurewebsites\.net$' <<< "${targets}"; then
            status="app_service"
        fi

        # If we have a target, merge into the accumulator object.
        if [[ -n "${targets}" ]]; then
            obj="$(jq -c --arg k "${host}" --arg t "${targets}" --arg s "${status}" \
                   '. + {($k):{cname:$t, hint:$s}}' <<< "${obj}")"
        fi
    done

    jq -n --argjson x "${obj}" '{ azure_services: $x }'
}

###############################################################################
# check_azure_services_deep
#------------------------------------------------------------------------------
# PURPOSE:
#   Perform a **deeper Azure footprint sweep** by resolving CNAMEs for a large
#   set of subdomains (provided via a wordlist) and classifying targets with
#   `_azure_hint_from_cname`. This augments the shallow, fixed-label check with
#   breadth and **simple concurrency** (background jobs).
#
# ARGUMENTS:
#   $1 - domain            (e.g., example.com)
#   $2 - dns_server        (resolver IP, e.g., 1.1.1.1)
#   $3 - subdomains_file   (readable file with one label per line; '#' allowed)
#   $4 - threads           (integer >0; number of concurrent resolver jobs)
#
# OUTPUT (stdout):
#   JSON object:
#   {
#     "azure_services_deep": {
#       "app.example.com": { "cname":"myapp.azurewebsites.net", "hint":"app_service" },
#       "cdn.example.com": { "cname":"edge123.azureedge.net",   "hint":"cdn" },
#       ...
#     }
#   }
#
# BEHAVIOR:
#   - Skips blank/commented lines in the wordlist.
#   - For each label, resolves CNAME of <label>.<domain>.
#   - If a CNAME exists, classifies it and writes a small JSON file to a temp
#     directory, then merges all per-host JSON files at the end.
#
# ROBUSTNESS:
#   - If the subdomain file is unreadable, returns a sentinel error JSON.
#   - Timeouts/errors during DNS resolution result in silence for that label
#     (host omitted), not a hard failure.
#   - Cleans up temporary files/directories best-effort.
###############################################################################
function check_azure_services_deep() {
    local domain="${1}"
    local dns_server="${2}"
    local subdomains_file="${3}"
    local threads="${4}"

    info "Azure services (deep): sweeping subdomains from ${subdomains_file} with ${threads} threads ..."

    if [[ ! -r "${subdomains_file}" ]]; then
        warn "Subdomain file not readable: ${subdomains_file}"
        jq -n '{ azure_services_deep: { error:"subdomain_file_unreadable" } }'
        return 0
    fi

    # Create a temp workspace for per-host JSON outputs.
    local tmpdir
    tmpdir="$(mktemp -d 2> /dev/null || printf '/tmp')"
    local -r outdir="${tmpdir}/asweep"
    mkdir -p "${outdir}" 2> /dev/null || true

    # --- lightweight concurrency control using background jobs ---
    local max_jobs="${threads}"

    function _jobs_running() { jobs -pr | wc -l | tr -d ' '; }
    function _wait_for_slot() {
        local max="${1}"
        while [[ "$(_jobs_running)" -ge "${max}" ]]; do
            sleep 0.05
        done
    }

    # Sweep: read labels, resolve <label>.<domain>, classify, emit per-file JSON.
    local label="" fqdn="" cname_json="" target="" hint=""
    while IFS= read -r label; do
        [[ -z "${label}" ]] && continue
        [[ "${label}" =~ ^# ]] && continue

        fqdn="${label}.${domain}"
        _wait_for_slot "${max_jobs}"

        (   
            # Resolve CNAME (dns_query_generic emits JSON array of strings).
            cname_json="$(dns_query_generic "CNAME" "${fqdn}" "${dns_server}")"
            target="$(printf '%s\n' "${cname_json}" | jq -r '.[0] // empty')"
            hint="$(_azure_hint_from_cname "${target}")"

            # Emit only if we found a CNAME target.
            if [[ -n "${target}" ]]; then
                jq -n --arg host "${fqdn}" --arg target "${target}" --arg hint "${hint}" \
                    '{ host:$host, cname:$target, hint:$hint }'
            fi
        ) > "${outdir}/${label}.json" 2> /dev/null &
    done < "${subdomains_file}"

    # Wait for all background jobs to finish.
    wait

    # Merge the small per-host JSON documents into one object keyed by host.
    local merged="{}"
    if ls "${outdir}"/*.json > /dev/null 2>&1; then
        merged="$(
            jq -s 'reduce .[] as $i ({}; . + { ($i.host): {cname:$i.cname, hint:$i.hint} })' \
                "${outdir}"/*.json 2> /dev/null || echo '{}'
        )"
    fi

    # Cleanup temporary artifacts (best-effort).
    rm -rf "${outdir}" 2> /dev/null || true
    rmdir "${tmpdir}" 2> /dev/null || true

    jq -n --argjson x "${merged}" '{ azure_services_deep: $x }'
}
