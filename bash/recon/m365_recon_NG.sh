#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : m365_recon.sh
# DESCRIPTION  : Comprehensive Microsoft 365 / Entra ID external recon script
#                combining DNS/EOP/SMTP/OSINT and Entra discovery with robust
#                logging, resilient fallbacks, cloud-instance switching, and
#                JSON-first outputs suitable for downstream tooling.
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
source "${script_dir}/analysis_and_output.sh" 2> /dev/null || true
source "${script_dir}/cloud_surface_utils.sh" 2> /dev/null || true
source "${script_dir}/dns_email_recon.sh" 2> /dev/null || true
source "${script_dir}/entra_azure_recon.sh" 2> /dev/null || true
source "${script_dir}/osint.sh" 2> /dev/null || true
source "${script_dir}/smtp_recon.sh" 2> /dev/null || true
source "${script_dir}/msgraph_recon.sh" 2> /dev/null || true
source "${script_dir}/services_recon.sh" 2> /dev/null || true

#==============================================================================
# CLI
#==============================================================================

###############################################################################
# usage
# Print help/usage information.
###############################################################################
###############################################################################
# usage
#------------------------------------------------------------------------------
# PURPOSE:
#   Print help/usage information, clearly distinguishing what is done
#   unauthenticated versus requiring a Microsoft Graph token.
###############################################################################
function usage() {
    cat << 'USAGE'
m365_recon_NG.sh - Unified M365/Entra Recon

Usage:
  m365_recon_NG.sh --domain <example.com> [options]

Required:
  -d, --domain <domain>         Target primary domain (e.g., example.com)

===============================================================================
 Test selection (default: --all, all unauthenticated checks)
===============================================================================
  -a, --all                     Run all unauthenticated tests (see below)

  --dns                         DNS suite (A/AAAA/MX/TXT/SPF/DMARC/DKIM) [unauth]
  --srv                         SRV suite (_sip._tls, _sipfederationtls._tcp, _autodiscover._tcp) [unauth]
  --smtp                        SMTP banner / STARTTLS on MX hosts [unauth]
  --direct-send                 Minimal SMTP dialog to MX/postmaster (no DATA) [unauth]

  --sharepoint                  SharePoint Online presence [unauth]
  --teams                       Teams presence inference [unauth]
  --b2c                         Azure AD B2C presence & policy-shaped URLs [unauth]
  --saml                        SAML federation endpoint discovery [unauth]
  --azure-services              Passive Azure services (CNAME hints, App Services, Storage, PowerApps, CDN) [unauth]
  --saas                        SaaS/IdP fingerprints (basic list) [unauth]
  --saas-extended               SaaS/IdP fingerprints (broader built-in catalog) [unauth]
  --osint                       crt.sh certificate transparency query [unauth]

===============================================================================
 Deep enumeration (all unauthenticated)
===============================================================================
  --subdomains <file>           Deep Azure surface sweep via wordlist
  --threads <N>                 Concurrency for deep sweep (default: 20)
  --saas-extra-file <file>      Append additional SaaS/IdP endpoints (used with --saas/--saas-extended)

===============================================================================
 Entra / Tenant posture (all unauthenticated)
===============================================================================
  --entra                       Entra/Identity posture checks:
                                  • Realm discovery
                                  • OIDC /.well-known endpoints
                                  • Autodiscover federation probe
                                  • Tenant branding probe
                                  • Legacy auth signals
                                  • Conditional Access signals
                                  • SAML endpoints
                                  • B2C presence
                                  • AAD Connect status
                                  • Provisioning endpoints
                                  • AAD application endpoint hints
                                  • Tenant domain enumeration
                                  • Microsoft Defender for Identity (MDI) presence (unauth)

===============================================================================
 Microsoft Graph (authenticated, requires --with-token)
===============================================================================
  --with-token <token>          Supply Bearer token (requires Graph API scopes)
  --graph-apps                  Collect full Applications snapshot [auth]
  --mdi                         Infer Defender for Identity from Service Principals [auth]
  --graph-limit <N>             Max objects to pull for paged Graph queries (default: 300)

===============================================================================
 Cloud / DNS
===============================================================================
  --cloud <na|gov|china>        Cloud instance (default: na)
  --dns-server <ip>             DNS server for lookups (default: 1.1.1.1)

===============================================================================
 Output / Behavior
===============================================================================
  -j, --json-out <file>         Write final merged JSON to file
      --no-color                Disable colorized log output
  -q, --quiet                   Minimal logging (errors + summary only)
  -v, --verbose                 Extra debug logging
      --report                  Print detailed long report

Examples:
  m365_recon_NG.sh -d contoso.com --all
  m365_recon_NG.sh -d contoso.com.gov --cloud gov --dns --entra --srv
  m365_recon_NG.sh -d contoso.com.cn --cloud china --dns --smtp --json-out out.json
USAGE
}

#==============================================================================
# Main
#==============================================================================

###############################################################################
# main
#------------------------------------------------------------------------------
# PURPOSE:
#   Orchestrate CLI parsing, select and run requested collectors, merge their
#   JSON outputs, perform analysis, and print both machine and human summaries.
#
# NEW FLAGS ADDED HERE:
#   --with-token <token>         Use Microsoft Graph (authenticated) collectors.
#   --graph-max-items <n>        Cap Graph pagination (default: 4000).
#   --saas-extended              Use extended SaaS/IdP list (vs basic).
#   --saas-extra-file <path>     Append additional SaaS/IdP URLs from file.
#   --subdomains <file>          Enable deep Azure services sweep (wordlist).
#   --threads <n>                Concurrency for deep sweep (default: 20).
###############################################################################
function main() {
    # -----------------------------
    # Defaults / State
    # -----------------------------
    local domain="" cloud="na" dns_server="1.1.1.1" json_out=""
    # Feature flags for existing groups
    local run_dns=0 run_srv=0 run_entra=0 run_smtp=0 run_direct=0 run_osint=0
    local run_sharepoint=0 run_teams=0 run_b2c=0 run_saml=0 run_azure=0 run_saas=0
    # New: deep Azure sweep & SaaS options
    local subdomains_file="" threads="20"
    local saas_extended=0 saas_extra_file=""
    # New: Microsoft Graph (authenticated) options
    local token="" graph_max_items="4000"

    # Verbosity / UX
    local quiet=0 verbose=0
    local long_report=0

    # -----------------------------
    # CLI parsing
    # -----------------------------
    if (("$#" == 0)); then
        usage
        exit 1
    fi
    while (("$#" > 0)); do
        case "${1}" in
            -d | --domain)
                shift
                domain="${1:-}"
                ;;
            --dns-server)
                shift
                dns_server="${1:-}"
                ;;
            --cloud)
                shift
                cloud="${1:-na}"
                ;;
            -a | --all)
                run_dns=1
                run_srv=1
                run_entra=1
                run_smtp=1
                run_direct=1
                run_osint=1
                run_sharepoint=1
                run_teams=1
                run_b2c=1
                run_saml=1
                run_azure=1
                run_saas=1
                ;;
            --dns)                  run_dns=1 ;;
            --srv)                  run_srv=1 ;;
            --entra)                run_entra=1 ;;
            --smtp)                 run_smtp=1 ;;
            --direct-send)          run_direct=1 ;;
            --sharepoint)           run_sharepoint=1 ;;
            --teams)                run_teams=1 ;;
            --b2c)                  run_b2c=1 ;;
            --saml)                 run_saml=1 ;;
            --azure-services)       run_azure=1 ;;
            --saas)                 run_saas=1 ;;
            --osint)                run_osint=1 ;;
            -j | --json-out)
                shift
                json_out="${1:-}"
                ;;
            --no-color)             ENABLE_COLOR=0 ;;
            -q | --quiet)           quiet=1 ;;
            -v | --verbose)         verbose=1 ;;
            --subdomains)
                shift
                subdomains_file="${1:-}"
                ;;
            --threads)
                shift
                threads="${1:-20}"
                ;;
            --saas-extended)        saas_extended=1 ;;
            --saas-extra-file)
                shift
                saas_extra_file="${1:-}"
                ;;
            --with-token)
                shift
                token="${1:-}"
                ;;
            --graph-max-items)
                shift
                graph_max_items="${1:-4000}"
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            --report | --long-report)
                long_report=1
                ;;
            *)
                error "Unknown option: ${1}"
                usage
                exit 1
                ;;
        esac
        shift || true
    done

    # Required target domain.
    [[ -z "${domain}" ]] && die 2 "A target --domain is required."

    # Quiet mode => silence info/debug + disable file logging.
    if ((quiet == 1)); then
        function info()  { :; }
        function debug() { :; }
        ENABLE_FILE_LOGGING=0
    fi
    if ((verbose == 1)); then   debug "Verbose logging enabled."; fi

    # Ensure required tools (curl, jq, dig/host, timeout).
    validate_tools

    # -----------------------------
    # Resolve cloud endpoints
    # -----------------------------
    local endpoints="" login_host="" outlook_host="" autodiscover_global="" eop_suffix=""
    endpoints="$(get_cloud_endpoints "${cloud}")"
    login_host="$(cut -d'|' -f1 <<< "${endpoints}")"
    outlook_host="$(cut -d'|' -f2 <<< "${endpoints}")"
    autodiscover_global="$(cut -d'|' -f3 <<< "${endpoints}")"
    eop_suffix="$(cut -d'|' -f4 <<< "${endpoints}")"

    info "Target: ${domain} | Cloud: ${cloud} | DNS: ${dns_server}"

    # If no collectors chosen, default to everything (including new bits).
    if ((run_dns + run_srv + run_entra + run_smtp + run_direct + run_osint + run_sharepoint + run_teams + run_b2c + run_saml + run_azure + run_saas == 0)) \
        && [[ -z "${subdomains_file}" ]] && [[ -z "${token}" ]]; then
        run_dns=1
        run_srv=1
        run_entra=1
        run_smtp=1
        run_direct=1
        run_osint=1
        run_sharepoint=1
        run_teams=1
        run_b2c=1
        run_saml=1
        run_azure=1
        run_saas=1
        info "No tests selected; defaulting to --all."
    fi

    # -----------------------------
    # Execute selected collectors
    # -----------------------------
    local -a frags=()  # array of JSON fragments
    local j=""

    # DNS + EOP
    if ((run_dns == 1)); then
        j="$(do_dns_suite "${domain}" "${dns_server}")"
        frags+=("${j}")
        j="$(do_eop_eval "${domain}" "${dns_server}" "${eop_suffix}")"
        frags+=("${j}")
    fi

    # SRV records
    if ((run_srv == 1)); then
        j="$(do_dns_srv_suite "${domain}" "${dns_server}")"
        frags+=("${j}")
    fi

    if ((run_dns == 1 || run_srv == 1)); then
        frags+=("$(analyze_spf_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_dmarc_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_mx_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_mta_sts_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_tls_rpt_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_bimi_json "${domain}" "${dns_server}")")
        frags+=("$(analyze_dkim_json "${domain}" "${dns_server}" "${selectors_file:-}")")
    fi

    # SMTP
    if ((run_smtp == 1)); then
        j="$(do_smtp_probe "${domain}" "${dns_server}")"
        frags+=("${j}")
    fi

    # Direct-send (no DATA)
    if ((run_direct == 1)); then
        info "SMTP: direct-send check (no DATA)..."

        local mx_hosts_json="[]"

        # Prefer MX already resolved in fragments, but always transform to pure hostnames.
        local mx_src="[]"
        if ((run_dns == 1)); then
            local merged_so_far=""
            merged_so_far="$(json_merge "${frags[@]}")"
            mx_src="$(jq -r '[ .eop.mx_hosts[]? ]' <<< "${merged_so_far}" 2> /dev/null || echo '[]')"
        else
            mx_src="$(dns_query_generic "MX" "${domain}" "${dns_server}")"
        fi

        # Transform "10 host." -> "host" (strip pref/priority and trailing dot).
        mx_hosts_json="$(
            printf '%s\n' "${mx_src}" \
                | jq '
                [ .[]
                  | (if test("^[0-9]+\\s+") then capture("(?<pref>^[0-9]+)\\s+(?<host>.+)$").host else . end)
                  | rtrimstr(".")
                ]'
        )"

        # Uses your helper in this script that consults cloud_surface_utils.get_cloud_endpoints
        # Cloud selection comes from $SMTP_CLOUD if set, else defaults to "na".
        local eop_host=""
        eop_host="$(_eop_host_for_domain "${domain}" "${SMTP_CLOUD:-na}")" || eop_host=""
        if [[ -n "${eop_host}" ]]; then
            # Append if not already in the array
            if ! jq -e --arg h "${eop_host}" 'index($h)' <<< "${mx_hosts_json}" > /dev/null; then
                mx_hosts_json="$(jq -n --argjson cur "${mx_hosts_json}" --arg h "${eop_host}" '$cur + [ $h ]')"
                debug "SMTP: added synthesized EOP host to probe list: ${eop_host}"
            fi
        fi
        # Dedupe the list just in case
        mx_hosts_json="$(jq 'unique' <<< "${mx_hosts_json}")"

        local results="[]" mx_host=""
        for mx_host in $(jq -r '.[]' <<< "${mx_hosts_json}"); do
            local ds=""
            ds="$(detect_direct_send_for_domain "${domain}" "${mx_host}" "9")"

            if jq -e . > /dev/null 2>&1 <<< "${ds}"; then
                results="$(jq -n --argjson cur "${results}" --argjson ds "${ds}" '$cur + [ $ds ]')"
            else
                warn "Direct-send: probe returned no JSON for ${mx_host}; skipping."
            fi
        done

        frags+=("$(jq -n --argjson r "${results}" '{ direct_send: { results:$r } }')")
    fi

    # Entra identity / OIDC / realm / autodiscover / branding / legacy / CA / SAML
    if ((run_entra == 1)); then
        local realm="" oidc="" ad=""
        realm="$(do_realm_discovery "${login_host}" "${domain}")"
        frags+=("${realm}")
        oidc="$(do_oidc_wellknown "${login_host}" "${domain}")"
        frags+=("${oidc}")
        ad="$(autodiscover_probe "${domain}" "${autodiscover_global}")"
        frags+=("${ad}")
        frags+=("$(check_tenant_branding "${realm}")")
        frags+=("$(check_legacy_auth "${outlook_host}")")
        frags+=("$(check_conditional_access "$(jq -r '.oidc.device_authorization_endpoint // ""' <<< "${oidc}")")")
        frags+=("$(check_saml_endpoints "${realm}")")

        # ---- NEW unauth posture checks from msftrecon.sh ----
        # AAD Connect / Hybrid status
        frags+=("$(check_aad_connect_status "${login_host}" "${domain}")")

        # Provisioning endpoints (needs tenant ID; derive from OIDC if present)
        local tenant_id=""
        tenant_id="$(jq -r '.oidc.tenant_id // empty' <<< "${oidc}" 2> /dev/null || true)"
        frags+=("$(check_provisioning_endpoints "${login_host}" "${tenant_id}")")

        # AAD Applications (unauth endpoint hints from OIDC doc)
        frags+=("$(check_aad_applications "${oidc}")")

        # Attempt to derive onmicrosoft tenant name via Autodiscover SOAP, then try MDI unauth
        local domains_json="" tenant_name=""
        domains_json="$(get_domains "${autodiscover_global}")"
        tenant_name="$(jq -r '.tenant // empty' <<< "${domains_json}" 2> /dev/null || true)"
        if [[ -n "${tenant_name}" ]]; then
            frags+=("$(check_mdi_instance "${tenant_name}")")
        else
            debug "MDI: could not derive tenant onmicrosoft name; skipping unauth MDI probe."
        fi
    fi

    # SharePoint
    if ((run_sharepoint == 1)); then
        frags+=("$(check_sharepoint "${domain}")")
    fi

    # Teams (uses SRV context if available)
    if ((run_teams == 1)); then
        local srv_json="{}"
        if ((run_srv == 1)); then   srv_json="$(json_merge "${frags[@]}")"; fi
        frags+=("$(check_teams_presence "${srv_json}")")
    fi

    # B2C
    if ((run_b2c == 1)); then
        frags+=("$(check_b2c_configuration "${domain}")")
    fi

    # Azure services (shallow + explicit surface checks)
    if ((run_azure == 1)); then
        frags+=("$(check_azure_services "${domain}" "${dns_server}")")   # existing shallow CNAME hints
        frags+=("$(check_app_services "${domain}")")                     # NEW explicit App Services
        frags+=("$(check_storage_accounts "${domain}")")                 # NEW explicit Storage
        frags+=("$(check_power_apps "${domain}")")                       # NEW explicit Power Apps portals
        frags+=("$(check_azure_cdn "${domain}" "${dns_server}")")        # NEW explicit CDN patterns
    fi

    # Azure services (deep, only if a wordlist is provided)
    if [[ -n "${subdomains_file}" ]]; then
        frags+=("$(check_azure_services_deep "${domain}" "${dns_server}" "${subdomains_file}" "${threads}")")
    fi

    # SaaS/IdP (basic or extended + extras)
    if ((run_saas == 1)); then
        frags+=("$(do_saas_idp_probe "${domain}" "${saas_extended}" "${saas_extra_file}" "${tenant_name}")")
    fi

    # OSINT (crt.sh query)
    if ((run_osint == 1)); then
        frags+=("$(do_osint_crtsh "${domain}")")
    fi

    # Microsoft Graph collectors (authenticated, optional)
    if [[ -n "${token}" ]]; then
        info "Graph: authenticated collectors enabled."
        local g_apps="" g_sps="" g_merge=""
        g_apps="$(graph_collect_applications "${token}" "${graph_max_items}")"
        g_sps="$(graph_collect_service_principals "${token}" "${graph_max_items}")"
        g_merge="$(json_merge "${g_apps}" "${g_sps}")"
        frags+=("${g_merge}")
        # Derive MDI presence from the merged Graph data.
        frags+=("$(graph_infer_mdi_from_service_principals "${g_merge}")")
    fi

    # -----------------------------
    # Merge -> Analyze -> Emit
    # -----------------------------
    local merged="" analysis=""
    merged="$(json_merge "${frags[@]}")"              # consolidate
    analysis="$(analyze_results "${merged}")"         # derived findings + risk
    merged="$(json_merge "${merged}" "${analysis}")"  # attach analysis

    # Output JSON (file or stdout) and a human summary.
    if [[ -n "${json_out}" ]]; then
        printf '%s\n' "${merged}" > "${json_out}" || die 3 "Failed writing JSON to ${json_out}"
        pass "Wrote JSON output to: ${json_out}"
    else
        printf '%s\n' "${merged}"
    fi

    if ((long_report == 1)); then
        print_long_report "${merged}"
    else
        print_summary "${merged}"
    fi
}

main "$@"
