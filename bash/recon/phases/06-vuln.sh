#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 06-vuln.sh
# DESCRIPTION  : Phase 6 - vulnerability assessment. Template scanning with
#                nuclei over the live URLs, nmap NSE vuln scripts over the live
#                hosts, and an opt-in Metasploit (msfconsole) resource-script
#                pass driven from the nmap results. TestSSL is available as an
#                opt-in TLS-analysis step (RECON_TESTSSL_ENABLED=1).
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_vuln
###############################################################################
function run_phase_vuln() {
    local d="${RECON_OUTDIR}/06-vuln"
    mkdir -p "${d}"
    local ran=0

    vuln_nuclei "${d}" && ran=1
    vuln_nmap_nse "${d}" && ran=1
    vuln_msf "${d}" && ran=1
    vuln_testssl "${d}" && ran=1
    vuln_vulnx "${d}" # enrichment only; never the sole reason a phase "ran"

    [[ "${ran}" -eq 0 ]] && RECON_STAGE_NOTE="skipped (no inputs / tools)"
    return 0
}

###############################################################################
# vuln_nuclei : template scan over the live URL list.
###############################################################################
function vuln_nuclei() {
    local d="${1}"
    local urls="${RECON_OUTDIR}/urls.txt"
    have_cmd nuclei || {
        LOG info "nuclei not installed - skipping"
        return 1
    }
    if [[ ! -s "${urls}" ]]; then
        LOG warn "no urls.txt - nuclei has nothing to scan"
        return 1
    fi
    # Template selection matches the mandated command form: a fixed -t set,
    # overridable via RECON_NUCLEI_TEMPLATES. httpx pre-filters to live hosts.
    local templates="${RECON_NUCLEI_TEMPLATES:-${RECON_NUCLEI_TEMPLATES_DEFAULT}}"
    LOG info "nuclei: template scan"
    run_pipe "cat $(printf '%q' "${urls}") | httpx -silent -threads ${RECON_THREADS:-50} \
        | nuclei -ni -o $(printf '%q' "${d}/nuclei.out") ${templates}" nuclei ||
        LOG warn "nuclei returned non-zero"
    return 0
}

###############################################################################
# vuln_vulnx : enrich CVE IDs found by nuclei / nmap NSE with vulnx metadata
#              (severity, CVSS, EPSS, KEV). Enrichment only; opt-in.
###############################################################################
function vuln_vulnx() {
    local d="${1}"
    [[ "${VULNX_ENABLED:-1}" -eq 1 ]] || return 0
    have_cmd vulnx || return 0
    local cves="${d}/cve-ids.txt"
    grep -rhoE 'CVE-[0-9]{4}-[0-9]+' \
        "${d}/nuclei.out" "${d}/nmap-nse.nmap" "${d}/nmap-nse.gnmap" 2> /dev/null |
        sort -u > "${cves}" || true
    if [[ ! -s "${cves}" ]]; then
        LOG debug "vulnx: no CVE IDs to enrich"
        return 0
    fi
    LOG info "vulnx: enriching $(count_lines "${cves}") CVE ID(s)"
    run_pipe "vulnx id --file $(printf '%q' "${cves}") --json \
        --output $(printf '%q' "${d}/vulnx.json") 2>/dev/null || true" vulnx
    return 0
}

###############################################################################
# vuln_nmap_nse : NSE vuln scripts over the live hosts from phase 04.
###############################################################################
function vuln_nmap_nse() {
    local d="${1}"
    [[ "${NMAP_NSE_ENABLED:-1}" -eq 1 ]] || return 1
    have_cmd nmap || return 1
    local hosts="${RECON_NMAP_LIVE_HOSTS:-}"
    [[ -n "${hosts}" ]] && [[ -s "${hosts}" ]] || hosts="${RECON_EXPANDED_TARGETS:-${TARGETS_FILE}}"
    [[ -s "${hosts}" ]] || return 1
    LOG info "nmap NSE: ${NMAP_NSE_SCRIPTS:-vuln} scripts over $(count_lines "${hosts}") host(s)"
    run nmap -Pn -n -T"${NMAP_TIMING:-4}" -sV \
        --script "${NMAP_NSE_SCRIPTS:-vuln}" \
        -iL "${hosts}" -oA "${d}/nmap-nse" > /dev/null 2>&1 ||
        LOG warn "nmap NSE returned non-zero"
    return 0
}

###############################################################################
# vuln_msf : opt-in Metasploit resource-script pass driven from nmap XML.
###############################################################################
function vuln_msf() {
    local d="${1}"
    local IFS=$' \t\n' # split MSF_MODULES on spaces
    [[ "${MSF_ENABLED:-0}" -eq 1 ]] || return 1
    have_cmd msfconsole || {
        LOG warn "MSF_ENABLED=1 but msfconsole not installed - skipping"
        return 1
    }

    local rc="${d}/recon.rc"
    if [[ -n "${MSF_RESOURCE:-}" ]] && [[ -f "${MSF_RESOURCE}" ]]; then
        rc="${MSF_RESOURCE}"
    else
        # Import the nmap results, then run any operator-listed aux modules.
        {
            printf 'workspace -a recon_%s\n' "$(date +%Y%m%d_%H%M%S)"
            local xml
            for xml in "${RECON_NMAP_XMLDIR:-${RECON_OUTDIR}/04-portscan/nmap_xml}"/*.xml; do
                [[ -f "${xml}" ]] && printf 'db_import %s\n' "${xml}"
            done
            printf 'hosts\nservices\n'
            local mod
            for mod in ${MSF_MODULES:-}; do
                printf 'use %s\nrun\n' "${mod}"
            done
            printf 'exit\n'
        } > "${rc}"
    fi

    LOG info "msfconsole: running resource script ${rc}"
    run msfconsole -q -r "${rc}" > "${d}/msf.log" 2>&1 || LOG warn "msfconsole returned non-zero"
    return 0
}

###############################################################################
# vuln_testssl : opt-in SSL/TLS analysis over TLS-bearing web services.
###############################################################################
function vuln_testssl() {
    local d="${1}"
    [[ "${RECON_TESTSSL_ENABLED:-0}" -eq 1 ]] || return 1
    local cmd=""
    if have_cmd testssl.sh; then
        cmd="testssl.sh"
    elif have_cmd testssl; then
        cmd="testssl"
    else
        LOG warn "RECON_TESTSSL_ENABLED=1 but testssl(.sh) not installed - skipping"
        return 1
    fi
    local targets="${RECON_WEB_SERVICES:-}"
    [[ -n "${targets}" ]] && [[ -s "${targets}" ]] || {
        LOG warn "no web-service list for testssl - skipping"
        return 1
    }
    local results="${d}/testssl"
    mkdir -p "${results}"
    LOG info "testssl: analyzing https services"
    local url host
    while IFS= read -r url; do
        case "${url}" in
            https://*) : ;;
            *) continue ;;
        esac
        host="${url#https://}"
        run "${cmd}" --quiet --jsonfile "${results}/${host//[:\/]/_}.json" \
            "${host}" > /dev/null 2>&1 || LOG warn "testssl failed for ${host}"
        sleep 2 # be gentle on the target between hosts
    done < "${targets}"

    vuln_testssl_aggregate "${d}" "${results}"
    return 0
}

###############################################################################
# vuln_testssl_aggregate
# Purpose : Combine per-host testssl JSON into an aggregate summary and a
#           vulnerable_hosts.txt of hosts with CRITICAL/HIGH findings.
# Args    : $1 phase dir ; $2 per-host results dir
###############################################################################
function vuln_testssl_aggregate() {
    local d="${1}" results="${2}"
    have_cmd jq || {
        LOG debug "jq not installed - skipping testssl aggregation"
        return 0
    }
    compgen -G "${results}/*.json" > /dev/null 2>&1 || return 0

    local agg_json="${d}/testssl-aggregate.json"
    local agg_txt="${d}/testssl-summary.txt"
    local vuln_hosts="${d}/testssl-vulnerable-hosts.txt"

    jq -s 'add // []' "${results}"/*.json > "${agg_json}" 2> /dev/null ||
        LOG warn "failed to aggregate testssl JSON"

    {
        printf 'SSL/TLS Security Testing Summary\n'
        printf 'Generated: %s\n\n' "$(date '+%F %T')"
        printf '=== Severity distribution ===\n'
        jq -r '.[] | select(.severity) | .severity' "${agg_json}" 2> /dev/null |
            sort | uniq -c | sort -rn
        printf '\n=== Critical / High findings ===\n'
        jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH")
               | "\(.severity)\t\(.ip // .fqdn // "?")\t\(.id): \(.finding)"' \
            "${agg_json}" 2> /dev/null || printf 'None found\n'
        printf '\n=== Known protocol vulnerabilities ===\n'
        jq -r '.[] | select(.id | test("heartbleed|ccs|ticketbleed|ROBOT|BREACH|CRIME|POODLE";"i"))
               | "\(.ip // .fqdn // "?"): \(.id) - \(.finding)"' \
            "${agg_json}" 2> /dev/null || printf 'None found\n'
    } > "${agg_txt}"

    jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH") | (.ip // .fqdn)' \
        "${agg_json}" 2> /dev/null | sort -u > "${vuln_hosts}" || true
    if [[ -s "${vuln_hosts}" ]]; then
        LOG warn "$(count_lines "${vuln_hosts}") host(s) with critical/high TLS issues: ${vuln_hosts}"
        export RECON_TESTSSL_VULN_HOSTS="${vuln_hosts}"
    fi
    LOG pass "testssl summary: ${agg_txt}"
    return 0
}
