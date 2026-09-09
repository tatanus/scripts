#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2086,SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Intentional word-splitting on the shfmt-preserved stats line (SC2086).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 01-osint.sh
# DESCRIPTION  : Phase 1 - passive OSINT and subdomain enumeration. When a
#                domains file exists it runs subfinder + bbot (passive),
#                asnmap, cdncheck, crt.sh and dnsx resolution. When it does
#                not, it derives candidate domains from the IP scope via the
#                8-technique discovery engine and raises the review gate.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_osint
###############################################################################
function run_phase_osint() {
    local d="${RECON_OUTDIR}/01-osint"
    mkdir -p "${d}"

    local have_domains=0
    if [[ -n "${DOMAINS_FILE:-}" ]] && [[ -s "${DOMAINS_FILE}" ]]; then
        have_domains=1
    fi

    # --- No domains yet: derive candidates from the IP scope, then stop -------
    if [[ "${have_domains}" -eq 0 ]] || [[ "${RECON_REDISCOVER:-0}" -eq 1 ]]; then
        LOG info "running IP->domain discovery (results require operator review)"
        discovery_run "${RECON_DISC_ONLY:-}" "${RECON_DISC_SKIP:-}"
        if [[ "${have_domains}" -eq 0 ]]; then
            RECON_STAGE_NOTE="discovery only (awaiting domain review)"
            return 0
        fi
    fi

    # --- Subdomain enumeration ------------------------------------------------
    local subs="${RECON_OUTDIR}/subdomains.txt"
    : > "${subs}"

    if have_cmd subfinder; then
        LOG info "subfinder: enumerating subdomains"
        run subfinder -dL "${DOMAINS_FILE}" -all -silent \
            -o "${d}/subfinder.txt" > /dev/null 2>&1 || LOG warn "subfinder returned non-zero"
        [[ -f "${d}/subfinder.txt" ]] && cat "${d}/subfinder.txt" >> "${subs}"
    else
        LOG info "subfinder not installed - skipping"
    fi

    if have_cmd bbot; then
        LOG info "bbot: passive subdomain-enum (active modules disabled)"
        run bbot -t "${DOMAINS_FILE}" -f subdomain-enum -ef active \
            -om txt,json,subdomains -o "${d}/bbot" -n scan --yes > /dev/null 2>&1 ||
            LOG warn "bbot returned non-zero"
        find "${d}/bbot" -type f -name 'subdomains.txt' -exec cat {} + >> "${subs}" 2> /dev/null || true
    else
        LOG info "bbot not installed - skipping"
    fi

    # Clamp discovered names to the roots in domains.txt (scope safety).
    if [[ -s "${subs}" ]]; then
        osint_clamp_to_roots "${subs}" "${DOMAINS_FILE}"
        LOG pass "$(count_lines "${subs}") in-scope subdomain(s)"
    fi

    # tldfinder: sibling/related org domains (acme.com -> acme.net, acme.io).
    # These are NEW scope, so they go to a review file, never straight to
    # enumeration - the same discipline as the IP->domain review gate.
    if have_cmd tldfinder; then
        LOG info "tldfinder: related-domain discovery"
        local related="${RECON_OUTDIR}/related-domains-candidates.txt"
        local root
        while IFS= read -r root; do
            [[ -n "${root}" ]] || continue
            run tldfinder -d "${root}" -dm domain -silent \
                >> "${d}/tldfinder.txt" 2> /dev/null || true
        done < "${DOMAINS_FILE}"
        if [[ -s "${d}/tldfinder.txt" ]]; then
            # Keep only apexes not already in domains.txt.
            grep -vxF -f "${DOMAINS_FILE}" "${d}/tldfinder.txt" 2> /dev/null |
                sort -u > "${related}" || true
            [[ -s "${related}" ]] &&
                LOG warn "$(count_lines "${related}") related domain(s) for review: ${related}"
        fi
    fi

    # --- ASN / CDN context ----------------------------------------------------
    if have_cmd asnmap; then
        LOG info "asnmap: ASN mapping"
        run asnmap -l "${TARGETS_FILE}" -silent -o "${d}/asnmap.txt" > /dev/null 2>&1 || true
    fi
    if have_cmd cdncheck; then
        LOG info "cdncheck: CDN/WAF detection"
        run cdncheck -l "${TARGETS_FILE}" -resp -o "${d}/cdncheck.txt" > /dev/null 2>&1 || true
    fi

    # --- Certificate transparency --------------------------------------------
    if have_cmd curl; then
        LOG info "crt.sh: certificate transparency"
        local domain url
        while IFS= read -r domain; do
            [[ -n "${domain}" ]] || continue
            url="https://crt.sh/?q=%25.${domain}&output=json"
            if [[ "${RECON_DRY_RUN:-0}" -eq 1 ]]; then
                LOG debug "curl ${url}"
            else
                curl -sS --connect-timeout 10 --max-time 30 "${url}" \
                    >> "${d}/crtsh.json" 2> /dev/null || true
            fi
        done < "${DOMAINS_FILE}"
    fi

    # --- Resolve enumerated names (record IPs for RECON only; never scanned) --
    if have_cmd dnsx && [[ -s "${subs}" ]]; then
        LOG info "dnsx: resolving enumerated names (A/ASN/recursion)"
        run_pipe "cat $(printf '%q' "${subs}") | dnsx -a -asn -re -silent \
            -t ${RECON_THREADS:-50} -o $(printf '%q' "${d}/dnsx.txt")" dnsx || true
        run_pipe "cat $(printf '%q' "${subs}") | dnsx -a -resp-only -silent \
            -t ${RECON_THREADS:-50} | sort -u > $(printf '%q' "${RECON_OUTDIR}/resolved-ips.txt")" dnsx || true
        LOG pass "$(count_lines "${RECON_OUTDIR}/resolved-ips.txt") resolved IP(s) recorded (not scanned)"
    fi

    return 0
}

###############################################################################
# osint_clamp_to_roots
# Purpose : Normalize a name list and keep only names inside the given roots.
# Args    : $1 names-file (rewritten in place) ; $2 roots-file
###############################################################################
function osint_clamp_to_roots() {
    local names="${1}" roots="${2}"
    local tmp_names="${names}.tmp" tmp_roots="${names}.roots"

    tr '[:upper:]' '[:lower:]' < "${names}" |
        sed -e 's/^\*\.//' -e 's/\.$//' -e 's/[[:space:]]//g' |
        grep -E '^[a-z0-9._-]+\.[a-z0-9-]{2,}$' |
        sort -u > "${tmp_names}" || true

    tr '[:upper:]' '[:lower:]' < "${roots}" |
        sed -e 's/[[:space:]]//g' -e '/^$/d' -e 's/^\*\.//' |
        sort -u > "${tmp_roots}"

    awk 'NR==FNR { r[$0]=1; next }
         {
             for (k in r) {
                 if ($0 == k) { print; break }
                 if (length($0) > length(k) &&
                     substr($0, length($0) - length(k)) == "." k) { print; break }
             }
         }' "${tmp_roots}" "${tmp_names}" | sort -u > "${names}"

    rm -f "${tmp_names}" "${tmp_roots}"
}
