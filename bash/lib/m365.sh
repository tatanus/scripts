#!/usr/bin/env bash
###############################################################################
# NAME         : m365.sh
# DESCRIPTION  : Shared library of Microsoft 365 / Azure AD (Entra) OSINT
#                interactions -- tenant discovery, user-realm / MFA info,
#                autodiscover + federation metadata, SaaS-service detection,
#                and domain correlation. All functions are namespaced `m365::`.
#
#                Sourceable by any pentest tool: `source ${SCRIPTS_DIR}/bash/lib/m365.sh`.
#                Assumes common_core is already loaded -- it delegates generic
#                DNS lookups to common_core's `dns::` helpers (util_dns.sh)
#                rather than re-implementing them.
#
#                Requires: dig (via dns::), jq, curl, getent.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-17
###############################################################################

set -uo pipefail
IFS=$'\n\t'

# Guard to prevent multiple sourcing
if [[ -n "${M365_LIB_SH_LOADED:-}" ]]; then
    if (return 0 2> /dev/null); then
        return 0
    fi
else
    declare -g M365_LIB_SH_LOADED=1

    # -------------------------------------------------------------------------
    # Tunables (override in the environment as needed)
    # -------------------------------------------------------------------------
    : "${HTTP_TIMEOUT:=60}"
    : "${CONNECT_TIMEOUT:=10}"
    : "${USE_COLOR:=true}"
    # Resolvers used by m365::resolve_all_a (space/array). Defaults to public.
    if [[ -z "${DNS_SERVERS:-}" ]]; then
        DNS_SERVERS=(8.8.8.8 1.1.1.1)
    fi

    M365_HTTP_HEADERS=(
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        -H "Accept-Language: en-US,en;q=0.5"
        -H "Connection: close"
    )

    # -------------------------------------------------------------------------
    # Small utilities
    # -------------------------------------------------------------------------

    # m365::color <red|green|yellow|cyan|*> <text...> -> colorized to stderr
    function m365::color() {
        local c="$1"
        shift
        if [[ "${USE_COLOR}" == "true" ]]; then
            case "${c}" in
                red) echo -e "\033[31m$*\033[0m" >&2 ;;
                green) echo -e "\033[32m$*\033[0m" >&2 ;;
                yellow) echo -e "\033[33m$*\033[0m" >&2 ;;
                cyan) echo -e "\033[36m$*\033[0m" >&2 ;;
                *) echo "$*" >&2 ;;
            esac
        else
            echo "$*" >&2
        fi
    }

    # m365::safe_json <data> -> echo the data if valid JSON, else "{}"
    function m365::safe_json() {
        local data="$1"
        if [[ -z "${data}" ]]; then
            echo "{}"
            return
        fi
        if printf '%s\n' "${data}" | jq empty > /dev/null 2>&1; then
            printf '%s\n' "${data}"
        else
            echo "{}"
        fi
    }

    # m365::safe_request <METHOD> <url> [extra curl args...] -> body (or empty)
    function m365::safe_request() {
        local method="$1" url="$2"
        shift 2
        curl -sS --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${HTTP_TIMEOUT}" \
            -X "${method}" "${M365_HTTP_HEADERS[@]}" "$@" "${url}" || true
    }

    # -------------------------------------------------------------------------
    # DNS (delegates the primitive lookups to common_core dns::)
    # -------------------------------------------------------------------------

    # m365::resolve_all_a <fqdn> -> unique A records across DNS_SERVERS
    function m365::resolve_all_a() {
        local fqdn="$1" ns
        for ns in "${DNS_SERVERS[@]}"; do
            dns::a "${fqdn}" "${ns}"
        done | sort -u
    }

    # m365::get_root_domain <fqdn> -> registrable domain (last two labels)
    function m365::get_root_domain() {
        dns::root_domain "$@"
    }

    # m365::get_spf_includes <spf_json_array> -> include: hosts (one per line)
    function m365::get_spf_includes() {
        echo "$1" | jq -r '.[]?' | dns::spf_includes
    }

    # m365::get_dns_records <domain> -> {mx,txt,spf,dkim} JSON
    function m365::get_dns_records() {
        local domain="$1"
        local mx txt spf dkim
        mx=$(dns::mx "${domain}" | jq -R . | jq -s .)
        txt=$(dns::txt "${domain}" | jq -R . | jq -s .)
        spf=$(echo "${txt}" | jq '[.[] | select(startswith("v=spf1"))]')

        local dkim_targets=()
        for sel in selector1 selector2; do
            local cname
            cname=$(dns::cname "${sel}._domainkey.${domain}")
            [[ -n "${cname}" ]] && dkim_targets+=("${cname}")
        done
        dkim="[]"
        if [[ ${#dkim_targets[@]} -gt 0 ]]; then
            dkim=$(printf "%s\n" "${dkim_targets[@]}" | jq -R . | jq -s .)
        fi

        jq -n --argjson mx "${mx}" --argjson txt "${txt}" --argjson spf "${spf}" --argjson dkim "${dkim}" \
            '{mx:$mx,txt:$txt,spf:$spf,dkim:$dkim}'
    }

    # m365::get_srv_records <domain> -> {srv_type: [targets]} JSON
    function m365::get_srv_records() {
        local domain="$1"
        local srv_types=("_sip._tls" "_sipfederationtls._tcp" "_autodiscover._tcp" "_kerberos._tcp" "_ldap._tcp")
        local srv_json="{}"
        for srv in "${srv_types[@]}"; do
            local records
            records=$(dns::srv "${srv}.${domain}" | jq -R . | jq -s .)
            srv_json=$(jq --arg key "${srv}" --argjson val "${records}" '. + {($key): $val}' <<< "${srv_json}")
        done
        echo "${srv_json}"
    }

    # -------------------------------------------------------------------------
    # Microsoft federation / login endpoints
    # -------------------------------------------------------------------------

    # m365::get_openid_metadata <domain> -> tenant GUID (or empty)
    function m365::get_openid_metadata() {
        local domain="$1"
        local json
        json=$(m365::safe_request GET "https://login.microsoftonline.com/${domain}/.well-known/openid-configuration")
        [[ -z "${json}" ]] && return
        echo "${json}" | jq -r '.issuer' | grep -Eo '[0-9a-fA-F-]{36}' | head -n 1 || true
    }

    # m365::get_login_and_mfa_info <domain> -> GetCredentialType JSON
    function m365::get_login_and_mfa_info() {
        local domain="$1"
        local url="https://login.microsoftonline.com/common/GetCredentialType"
        local payload="{\"Username\": \"info@${domain}\"}"
        m365::safe_request POST "${url}" -d "${payload}" -H "Content-Type: application/json"
    }

    # m365::get_autodiscover_redirect <domain> -> TargetAutodiscoverEpr (or empty)
    function m365::get_autodiscover_redirect() {
        local domain="$1"
        local url="https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        local body
        body=$(
            cat << EOF
<?xml version="1.0"?>
<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
<soap:Header>
<a:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To>${url}</a:To>
</soap:Header>
<soap:Body>
<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>${domain}</Domain></Request>
</GetFederationInformationRequestMessage>
</soap:Body>
</soap:Envelope>
EOF
        )
        local resp
        resp=$(m365::safe_request POST "${url}" -H "Content-Type: text/xml; charset=utf-8" -d "${body}")
        echo "${resp}" | sed -n 's:.*<TargetAutodiscoverEpr>\([^<]*\).*:\1:p' | head -n 1
    }

    # m365::get_federation_metadata <tenant_id> -> bindings/locations JSON array
    function m365::get_federation_metadata() {
        local tenant_id="$1"
        local url="https://login.microsoftonline.com/${tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
        m365::safe_request GET "${url}" | grep -Eo 'Binding="[^"]+"|Location="[^"]+"' | jq -R . | jq -s .
    }

    # -------------------------------------------------------------------------
    # SaaS service detection
    # -------------------------------------------------------------------------

    # m365::check_service_fqdn <url> <keyword1> <keyword2> -> per-service JSON
    function m365::check_service_fqdn() {
        local url="$1" keyword1="$2" keyword2="$3"
        local host
        host=$(echo "${url}" | awk -F/ '{print $3}')
        if ! getent hosts "${host}" > /dev/null 2>&1; then
            return 1
        fi

        local resp code title
        resp=$(curl -s -k -L --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${HTTP_TIMEOUT}" -D - "${url}" --output -)
        code=$(echo "${resp}" | head -1 | awk '{print $2}')
        title=$(echo "${resp}" | sed -n 's:.*<title>\([^<]*\)</title>.*:\1:p' | head -n 1)

        local matches=()
        for k in "${keyword1}" "${keyword2}"; do
            [[ -n "${k}" && "${resp}" == *"${k}"* ]] && matches+=("${k}")
        done

        jq -n \
            --arg initial_url "${url}" \
            --arg final_url "${url}" \
            --arg title "${title:-}" \
            --argjson matches "$(printf '%s\n' "${matches[@]}" | jq -R . | jq -s .)" \
            --arg code "${code}" \
            '{initial_url:$initial_url,final_url:$final_url,title:$title,status_code:$code,keyword_matches:$matches}'
    }

    # m365::check_services <domain> -> {service_name: per-service JSON} (parallel)
    function m365::check_services() {
        local domain="$1"
        local prefix
        prefix=$(echo "${domain}" | cut -d. -f1)

        declare -A urls=(
            ["Azure AD (Microsoft 365)"]="https://${prefix}.onmicrosoft.com"
            ["Azure AD Login"]="https://login.microsoftonline.com/${prefix}.onmicrosoft.com"
            ["Azure AD B2C"]="https://${prefix}.b2clogin.com"
            ["OneDrive"]="https://${prefix}-my.sharepoint.com"
            ["SharePoint"]="https://${prefix}.sharepoint.com"
            ["Teams"]="https://teams.microsoft.com/l/domain/${domain}"
            ["Mail (OWA)"]="https://mail.${domain}"
            ["Outlook (OWA)"]="https://outlook.${domain}"
            ["Portal (CNAME)"]="https://portal.${domain}"
            ["Autodiscover"]="https://autodiscover.${domain}/autodiscover.xml"
            ["Autodiscover2"]="https://autodiscover.${domain}/autodiscover/autodiscover.xml"
            ["ADFS (root)"]="https://adfs.${domain}"
            ["ADFS (SSO)"]="https://adfs.${domain}/adfs/ls/idpinitiatedsignon.aspx"
            ["Okta"]="https://${prefix}.okta.com"
            ["Okta (Kerberos)"]="https://${prefix}.kerberos.okta.com"
            ["Okta (Preview)"]="https://${prefix}.oktapreview.com"
            ["AWS IAM Identity Center"]="https://${prefix}.awsapps.com"
            ["AWS SSO Start"]="https://${prefix}.awsapps.com/start"
            ["OneLogin"]="https://${prefix}.onelogin.com"
            ["Auth0"]="https://${prefix}.auth0.com"
            ["IBM Security Verify"]="https://${prefix}.verify.ibm.com"
            ["Ping Identity"]="https://${prefix}.pingidentity.com"
            ["Duo Security"]="https://${prefix}.duosecurity.com"
            ["Slack"]="https://${prefix}.slack.com"
            ["Atlassian (Jira/Confluence)"]="https://${prefix}.atlassian.net"
            ["ServiceNow"]="https://${prefix}.service-now.com"
            ["Salesforce"]="https://${prefix}.my.salesforce.com"
            ["Cisco Webex"]="https://${prefix}.webex.com"
            ["Zendesk"]="https://${prefix}.zendesk.com"
            ["Freshdesk"]="https://${prefix}.freshdesk.com"
            ["Shopify"]="https://${prefix}.myshopify.com"
            ["Dropbox Business"]="https://${prefix}.dropbox.com"
            ["Box"]="https://${prefix}.box.com"
            ["HubSpot"]="https://${prefix}.hubspot.com"
            ["GitHub Enterprise"]="https://${prefix}.githubenterprise.com"
            ["GitLab"]="https://${prefix}.gitlab.com"
            ["Heroku Enterprise"]="https://${prefix}.herokuapp.com"
            ["Netlify"]="https://${prefix}.netlify.app"
            ["Vercel"]="https://${prefix}.vercel.app"
            ["Zoom"]="https://${prefix}.zoom.us"
            ["GoToMeeting"]="https://${prefix}.gotomeeting.com"
            ["BlueJeans"]="https://${prefix}.bluejeans.com"
            ["Trello Enterprise"]="https://${prefix}.trello.com"
            ["Asana"]="https://${prefix}.asana.com"
            ["Monday.com"]="https://${prefix}.monday.com"
            ["Basecamp"]="https://${prefix}.basecamp.com"
            ["Smartsheet"]="https://${prefix}.smartsheet.com"
            ["Workday"]="https://${prefix}.workday.com"
            ["Oracle Cloud"]="https://${prefix}.oraclecloud.com"
            ["SAP Cloud"]="https://${prefix}.sapcloud.io"
            ["CrowdStrike Falcon"]="https://${prefix}.crowdstrike.com"
            ["Palo Alto Cortex XDR"]="https://${prefix}.xdr.us.paloaltonetworks.com"
            ["VMware Workspace ONE"]="https://${prefix}.workspaceoneaccess.com"
            ["Proofpoint"]="https://${prefix}.proofpoint.com"
            ["Zscaler"]="https://${prefix}.zscaler.net"
            ["Cloudflare Teams"]="https://${prefix}.cloudflareaccess.com"
            ["Citrix Cloud"]="https://${prefix}.cloud.com"
            ["Rapid7 Insight"]="https://${prefix}.insight.rapid7.com"
            ["Splunk Cloud"]="https://${prefix}.splunkcloud.com"
            ["Snowflake"]="https://${prefix}.snowflakecomputing.com"
            ["SentinelOne"]="https://${prefix}.sentinelone.net"
            ["Dynamics 365"]="https://${prefix}.crm.dynamics.com"
        )

        export -f m365::check_service_fqdn
        export CONNECT_TIMEOUT HTTP_TIMEOUT

        local tmpfile
        tmpfile=$(mktemp)

        for svc in "${!urls[@]}"; do
            echo "${svc}|${urls[${svc}]}" >> "${tmpfile}"
        done

        xargs -I{} -P 10 bash -c "
            svc=\"\${1%%|*}\"
            url=\"\${1#*|}\"
            prefix=\$(echo \"\$url\" | cut -d/ -f3 | cut -d. -f1)
            domain=\$(echo \"\$url\" | cut -d/ -f3)
            out=\$(m365::check_service_fqdn \"\$url\" \"\$prefix\" \"\$domain\" || echo \"\")
            if [[ -n \"\$out\" ]]; then
                echo \"{\\\"name\\\":\\\"\$svc\\\",\\\"data\\\":\$out}\"
            fi
        " _ < "${tmpfile}" | jq -s 'reduce .[] as $i ({}; . + {($i.name): $i.data})'

        rm -f "${tmpfile}"
    }

    # -------------------------------------------------------------------------
    # Correlation + orchestration
    # -------------------------------------------------------------------------

    # m365::extended_correlate_domains <base_domain> <subdomains_json> \
    #     <base_tenant_id> <base_mx> <base_spf> -> [{domain,score,reasons}]
    function m365::extended_correlate_domains() {
        local base_domain="$1" subdomains_json="$2" base_tenant_id="$3" base_mx="$4" base_spf="$5"
        local related="[]"
        local base_root
        base_root=$(m365::get_root_domain "${base_domain}")

        local spf_includes
        spf_includes=$(m365::get_spf_includes "${base_spf}")

        local len
        len=$(echo "${subdomains_json}" | jq length)
        for i in $(seq 0 $((len - 1))); do
            local dom score=0
            dom=$(echo "${subdomains_json}" | jq -r ".[${i}].domain")

            [[ "${dom}" == "${base_domain}" ]] && continue
            [[ "$(m365::get_root_domain "${dom}")" == "${base_root}" ]] && continue

            local reasons=()

            local tid
            tid=$(m365::get_openid_metadata "${dom}" || echo "")
            if [[ -n "${tid}" && "${tid}" == "${base_tenant_id}" ]]; then
                score=$((score + 40))
                reasons+=("tenant_id")
            fi

            local mx_list
            mx_list=$(m365::get_dns_records "${dom}" | jq -r '.mx[]')
            for mx in ${mx_list}; do
                if echo "${base_mx}" | grep -q "${mx}"; then
                    score=$((score + 15))
                    reasons+=("mx")
                    break
                fi
            done

            local spf_list
            spf_list=$(m365::get_spf_includes "$(m365::get_dns_records "${dom}" | jq '.spf')")
            for s in ${spf_list}; do
                if echo "${spf_includes}" | grep -q "${s}"; then
                    score=$((score + 10))
                    reasons+=("spf")
                    break
                fi
            done

            if m365::resolve_all_a "${dom}" > /dev/null; then
                score=$((score + 5))
                reasons+=("resolves")
            fi

            local ns
            ns=$(m365::safe_request GET "https://login.microsoftonline.com/common/userrealm?user=test@${dom}&api-version=2.1" | jq -r '.NameSpaceType')
            if [[ "${ns}" == "Federated" ]]; then
                score=$((score + 10))
                reasons+=("federated")
            fi

            if ((score > 0)); then
                related=$(jq --arg d "${dom}" --argjson s "${score}" --argjson r "$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)" \
                    '. + [{domain:$d,score:$s,reasons:$r}]' <<< "${related}")
            fi
        done
        echo "${related}"
    }

    # m365::analyze <domain> -> full tenant/DNS/OSINT/services/federation JSON
    function m365::analyze() {
        local domain="$1"

        local tenant_id userrealm dns srv ct services login
        tenant_id="$(m365::get_openid_metadata "${domain}" || true)"
        userrealm="$(m365::safe_json "$(m365::safe_request GET "https://login.microsoftonline.com/common/userrealm?user=test@${domain}&api-version=2.1")")"
        dns="$(m365::safe_json "$(m365::get_dns_records "${domain}")")"
        srv="$(m365::safe_json "$(m365::get_srv_records "${domain}")")"
        ct="$(m365::safe_json "$(m365::safe_request GET "https://crt.sh/?q=${domain}&output=json")")"
        services="$(m365::safe_json "$(m365::check_services "${domain}")")"
        login="$(m365::safe_json "$(m365::get_login_and_mfa_info "${domain}")")"

        local onmicrosoft_domain
        onmicrosoft_domain=$(echo "${dns}" | jq -r '.dkim[] | select(test("_domainkey.*onmicrosoft.com"))' | sed -E 's/.*_domainkey\.([^.]+)\.onmicrosoft\.com.*/\1.onmicrosoft.com/' | head -n 1 || echo "")
        local is_federated branding_name sts_url
        is_federated=$(echo "${userrealm}" | jq -r '.NameSpaceType // ""')
        branding_name=$(echo "${userrealm}" | jq -r '.FederationBrandName // ""')
        sts_url=$(echo "${userrealm}" | jq -r '.STSAuthURL // ""')

        local related
        related=$(m365::extended_correlate_domains "${domain}" "${ct}" "${tenant_id}" "$(echo "${dns}" | jq '.mx')" "$(echo "${dns}" | jq '.spf')")

        local autodiscover
        autodiscover=$(m365::get_autodiscover_redirect "${domain}")

        local federation_meta
        if [[ -n "${tenant_id}" ]]; then
            federation_meta=$(m365::get_federation_metadata "${tenant_id}")
        else
            federation_meta="[]"
        fi

        jq -n \
            --arg domain "${domain}" \
            --arg tenant_id "${tenant_id}" \
            --arg onmicrosoft_domain "${onmicrosoft_domain}" \
            --arg is_federated "${is_federated}" \
            --arg branding_name "${branding_name}" \
            --arg sts_url "${sts_url}" \
            --arg autodiscover "${autodiscover}" \
            --argjson dns "${dns}" \
            --argjson srv "${srv}" \
            --argjson userrealm "${userrealm}" \
            --argjson ct "${ct}" \
            --argjson services "${services}" \
            --argjson login "${login}" \
            --argjson related "${related}" \
            --argjson federation_meta "${federation_meta}" '
{
  TENANT_INFO: {
    domain: $domain,
    tenant_id: $tenant_id,
    onmicrosoft_domain: $onmicrosoft_domain,
    is_federated: $is_federated,
    branding_name: $branding_name,
    sts_url: $sts_url,
    autodiscover_redirect: $autodiscover
  },
  DNS: ($dns + { SRV: $srv }),
  USERREALM: $userrealm,
  OSINT: { crt:$ct, related:$related },
  SERVICES: $services,
  LOGIN: $login,
  FEDERATION_METADATA: $federation_meta
}'
    }
fi
