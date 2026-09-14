#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: DOMAINS_FOUND_FILE / DOMAINS_FILE / DNS_OUT_DIR / DC_FILE /
# DNS_SERVERS and the LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 03-domain-controllers
# DESCRIPTION: For every domain identified in task 02 (plus any seed
#              domains.txt), locate the Active Directory domain controllers via
#              DNS and resolve them to IPs. Writes a de-duplicated list of DC
#              hostnames/IPs to domain_controllers.txt .
#
#              Two complementary DNS methods are used per domain:
#                1. SRV records that advertise DCs (_ldap._tcp.dc._msdcs, ...).
#                2. A record of the bare domain apex ("DA" lookup) -- in AD the
#                   domain name itself resolves to every DC's IP.
#
#              Internal PTR/SRV/A records only resolve against the environment's
#              own DNS (typically the DCs), so queries honor DNS_SERVERS the
#              same way task 02 does.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

# SRV records that locate domain controllers in an Active Directory forest.
readonly -a DC_SRV_PREFIXES=(
    "_ldap._tcp.dc._msdcs"
    "_kerberos._tcp.dc._msdcs"
    "_ldap._tcp"
    "_gc._tcp"
)

###############################################################################
# _srv_targets <domain> [server]  -> prints SRV target hostnames
###############################################################################
function _srv_targets() {
    local domain="${1}" server="${2:-}" prefix fqdn
    for prefix in "${DC_SRV_PREFIXES[@]}"; do
        fqdn="${prefix}.${domain}"
        if cmd::exists dig; then
            # SRV answer: prio weight port target
            dig +short SRV "${fqdn}" ${server:+@"${server}"} 2> /dev/null | awk '{print $4}' | sed 's/\.$//'
        elif cmd::exists host; then
            host -t SRV "${fqdn}" ${server:+"${server}"} 2> /dev/null | awk '/SRV record/ {print $NF}' | sed 's/\.$//'
        elif cmd::exists nslookup; then
            nslookup -type=SRV "${fqdn}" ${server:+"${server}"} 2> /dev/null | awk '/service =/ {print $NF}' | sed 's/\.$//'
        fi
    done
}

###############################################################################
# _resolve_a <host> [server]  -> prints A record(s)
###############################################################################
function _resolve_a() {
    local name="${1}" server="${2:-}"
    if cmd::exists dig; then
        dig +short A "${name}" ${server:+@"${server}"} 2> /dev/null
    elif cmd::exists host; then
        host "${name}" ${server:+"${server}"} 2> /dev/null | awk '/has address/ {print $NF}'
    elif cmd::exists nslookup; then
        nslookup "${name}" ${server:+"${server}"} 2> /dev/null | awk '/^Address: / {print $2}'
    fi
}

###############################################################################
# run_task_03_domain_controllers
###############################################################################
function run_task_03_domain_controllers() {
    if ! cmd::exists dig && ! cmd::exists host && ! cmd::exists nslookup; then
        LOG error "No DNS resolver found (need dig, host, or nslookup)"
        return 1
    fi

    # Prefer the domains discovered in task 02; fall back to seed domains.txt.
    local domains_src="${DOMAINS_FOUND_FILE}"
    [[ -s "${domains_src}" ]] || domains_src="${DOMAINS_FILE}"

    if [[ ! -s "${domains_src}" ]]; then
        LOG warn "No domains to query for domain controllers; skipping"
        return 0
    fi

    # dig/host/nslookup take a single server; use the first of DNS_SERVERS.
    local server="${DNS_SERVERS%%,*}"
    if [[ -n "${server}" ]]; then
        LOG info "Querying internal DNS server: ${server}"
    else
        LOG info "Using the host's configured DNS resolver (set DNS_SERVERS for internal DNS)"
    fi

    mkdir -p "${DNS_OUT_DIR}" "$(dirname "${DC_FILE}")"
    local detail="${DNS_OUT_DIR}/domain_controllers_detail.txt"
    local tmp
    tmp="$(mktemp)"
    : > "${detail}"

    local summary="${DNS_OUT_DIR}/domain_controllers_by_domain.txt"
    : > "${summary}"

    local domain host ip dom_ips dom_n
    while IFS= read -r domain; do
        [[ -z "${domain}" ]] && continue
        LOG info "Locating DCs for: ${domain} (SRV + apex-A)"
        if internal::is_dry_run; then
            LOG info "[DRY RUN] would query SRV + A records for ${domain}"
            continue
        fi

        # Per-domain set of DC IPs, so we can report a count for each domain.
        dom_ips="$(mktemp)"

        # 1. SRV records advertising DCs -> hostname -> A.
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            printf '%s\tsrv-host=%s\n' "${domain}" "${host}" >> "${detail}"
            printf '%s\n' "${host}" >> "${tmp}"
            while IFS= read -r ip; do
                [[ -z "${ip}" ]] && continue
                printf '%s\tsrv-host=%s\tip=%s\n' "${domain}" "${host}" "${ip}" >> "${detail}"
                printf '%s\n' "${ip}" >> "${tmp}"
                printf '%s\n' "${ip}" >> "${dom_ips}"
            done < <(_resolve_a "${host}" "${server}")
        done < <(_srv_targets "${domain}" "${server}" | sort -u)

        # 2. "DA" lookup: A record of the domain apex. In AD the domain name
        #    itself resolves to every DC's IP.
        while IFS= read -r ip; do
            [[ -z "${ip}" ]] && continue
            printf '%s\tapex-A\tip=%s\n' "${domain}" "${ip}" >> "${detail}"
            printf '%s\n' "${ip}" >> "${tmp}"
            printf '%s\n' "${ip}" >> "${dom_ips}"
        done < <(_resolve_a "${domain}" "${server}")

        dom_n="$(sort -u "${dom_ips}" | grep -cvE '^$')"
        rm -f "${dom_ips}"
        printf '%s\t%s\n' "${domain}" "${dom_n}" >> "${summary}"
        if ((dom_n > 0)); then
            LOG pass "  ${domain}: ${dom_n} domain controller(s)"
        else
            LOG warn "  ${domain}: no domain controllers resolved"
        fi
    done < <(internal::clean_list "${domains_src}")

    sort -u "${tmp}" | grep -vE '^$' > "${DC_FILE}" || true
    rm -f "${tmp}"

    local n
    n="$(wc -l < "${DC_FILE}" | tr -d ' ')"
    if ((n > 0)); then
        LOG pass "Domain controllers found: ${n} total -> ${DC_FILE}"
        LOG info "Per-domain counts -> ${summary}"
    else
        LOG warn "No domain controllers resolved (SRV or apex-A)"
    fi
    return 0
}
