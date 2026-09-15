#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: DOMAINS_FOUND_FILE / DOMAINS_FILE / DNS_OUT_DIR / DC_FILE /
# DC_IP_FILE / DC_FQDN_FILE / DC_LIST_FILE / DC_RAW_FILE /
# DNS_SERVER and the LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 03-domain-controllers
# DESCRIPTION: For every domain identified in task 02 (plus any seed
#              domains.txt), locate the Active Directory domain controllers via
#              DNS and resolve them to IPs. Two complementary methods per
#              domain:
#                1. SRV records advertising DCs (_ldap._tcp.dc._msdcs, ...).
#                2. A record of the bare domain apex ("DA" lookup) -- in AD the
#                   domain name itself resolves to every DC's IP.
#
#              Outputs (in WORK_DIR):
#                DC_IP_LIST.txt    - unique DC IPs
#                DC_FQDN_LIST.txt  - unique DC FQDNs
#                DC_LIST.txt       - IP<TAB>FQDN mapping
#              Raw dig/host/nslookup output is saved to DC_RAW_FILE, and a
#              per-domain count to domain_controllers_by_domain.txt .
#
#              Internal SRV/A/PTR records only resolve against the environment's
#              own DNS (typically the DCs), so queries honor DNS_SERVER.
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
# _append_raw <label> <raw-output>  -> record a query's raw output
###############################################################################
function _append_raw() {
    {
        printf '===== %s =====\n' "${1}"
        printf '%s\n\n' "${2}"
    } >> "${DC_RAW_FILE}"
}

###############################################################################
# _srv_targets <domain> <server>  -> prints SRV target hostnames (FQDNs)
# Logs the raw command output to DC_RAW_FILE.
###############################################################################
function _srv_targets() {
    local domain="${1}" server="${2:-}" prefix fqdn raw
    for prefix in "${DC_SRV_PREFIXES[@]}"; do
        fqdn="${prefix}.${domain}"
        if cmd::exists dig; then
            raw="$(dig SRV "${fqdn}" ${server:+@"${server}"} 2>&1)"
            _append_raw "dig SRV ${fqdn}${server:+ @${server}}" "${raw}"
            printf '%s\n' "${raw}" | awk '$0 !~ /^;/ && $4 == "SRV" {print $NF}' | sed 's/\.$//'
        elif cmd::exists host; then
            raw="$(host -t SRV "${fqdn}" ${server:+"${server}"} 2>&1)"
            _append_raw "host -t SRV ${fqdn}${server:+ ${server}}" "${raw}"
            printf '%s\n' "${raw}" | awk '/SRV record/ {print $NF}' | sed 's/\.$//'
        elif cmd::exists nslookup; then
            raw="$(nslookup -type=SRV "${fqdn}" ${server:+"${server}"} 2>&1)"
            _append_raw "nslookup -type=SRV ${fqdn}${server:+ ${server}}" "${raw}"
            printf '%s\n' "${raw}" | awk '/service =/ {print $NF}' | sed 's/\.$//'
        fi
    done
}

###############################################################################
# _resolve_a <host> <server>  -> prints A record(s); logs raw output
###############################################################################
function _resolve_a() {
    local name="${1}" server="${2:-}" raw
    if cmd::exists dig; then
        raw="$(dig A "${name}" ${server:+@"${server}"} 2>&1)"
        _append_raw "dig A ${name}${server:+ @${server}}" "${raw}"
        printf '%s\n' "${raw}" | awk '$0 !~ /^;/ && $4 == "A" {print $5}'
    elif cmd::exists host; then
        raw="$(host "${name}" ${server:+"${server}"} 2>&1)"
        _append_raw "host ${name}${server:+ ${server}}" "${raw}"
        printf '%s\n' "${raw}" | awk '/has address/ {print $NF}'
    elif cmd::exists nslookup; then
        raw="$(nslookup "${name}" ${server:+"${server}"} 2>&1)"
        _append_raw "nslookup ${name}${server:+ ${server}}" "${raw}"
        printf '%s\n' "${raw}" | awk '/^Address: / {print $2}'
    fi
}

###############################################################################
# _resolve_ptr <ip> <server>  -> prints PTR name (FQDN) for an IP; logs raw
###############################################################################
function _resolve_ptr() {
    local ip="${1}" server="${2:-}" raw
    if cmd::exists dig; then
        raw="$(dig +short -x "${ip}" ${server:+@"${server}"} 2>&1)"
        _append_raw "dig -x ${ip}${server:+ @${server}}" "${raw}"
        printf '%s\n' "${raw}" | grep -vE '^;|^$' | sed 's/\.$//' | head -n 1
    elif cmd::exists host; then
        raw="$(host "${ip}" ${server:+"${server}"} 2>&1)"
        _append_raw "host ${ip}${server:+ ${server}}" "${raw}"
        printf '%s\n' "${raw}" | awk '/pointer|name pointer/ {print $NF}' | sed 's/\.$//' | head -n 1
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

    # dig/host/nslookup take a single server; use the first of DNS_SERVER.
    local server="${DNS_SERVER%%,*}"
    if [[ -n "${server}" ]]; then
        LOG info "Querying internal DNS server: ${server}"
    else
        LOG info "Using the host's configured DNS resolver (set DNS_SERVER for internal DNS)"
    fi

    mkdir -p "${DNS_OUT_DIR}" "$(dirname "${DC_LIST_FILE}")"
    local summary="${DNS_OUT_DIR}/domain_controllers_by_domain.txt"
    : > "${summary}"
    : > "${DC_RAW_FILE}"

    # All discovered IP<TAB>FQDN pairs (FQDN "-" when unknown).
    local pairs
    pairs="$(mktemp)"

    local domain host ip fqdn dom_ips dom_n
    while IFS= read -r domain; do
        [[ -z "${domain}" ]] && continue
        LOG info "Locating DCs for: ${domain} (SRV + apex-A)"
        if internal::is_dry_run; then
            LOG info "[DRY RUN] would query SRV + A records for ${domain}"
            continue
        fi

        dom_ips="$(mktemp)"

        # 1. SRV records -> DC FQDN -> A record(s).
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            while IFS= read -r ip; do
                [[ -z "${ip}" ]] && continue
                printf '%s\t%s\n' "${ip}" "${host}" >> "${pairs}"
                printf '%s\n' "${ip}" >> "${dom_ips}"
            done < <(_resolve_a "${host}" "${server}")
        done < <(_srv_targets "${domain}" "${server}" | sort -u)

        # 2. "DA" lookup: the domain apex A records ARE the DC IPs. Reverse-
        #    resolve each to recover the DC FQDN for the mapping.
        while IFS= read -r ip; do
            [[ -z "${ip}" ]] && continue
            fqdn="$(_resolve_ptr "${ip}" "${server}")"
            printf '%s\t%s\n' "${ip}" "${fqdn:--}" >> "${pairs}"
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

    # Build the three output files from the collected pairs.
    sort -u "${pairs}" | grep -vE '^[[:space:]]*$' > "${DC_LIST_FILE}" || true
    cut -f1 "${DC_LIST_FILE}" | grep -vE '^$' | sort -u > "${DC_IP_FILE}" || true
    cut -f2 "${DC_LIST_FILE}" | grep -vE '^-?$' | sort -u > "${DC_FQDN_FILE}" || true
    cp -f "${DC_LIST_FILE}" "${DC_FILE}" 2> /dev/null || true # backward compat
    rm -f "${pairs}"

    local ipn fqn
    ipn="$(wc -l < "${DC_IP_FILE}" | tr -d ' ')"
    fqn="$(wc -l < "${DC_FQDN_FILE}" | tr -d ' ')"
    if ((ipn > 0 || fqn > 0)); then
        LOG pass "DC IPs:   ${ipn} -> ${DC_IP_FILE}"
        LOG pass "DC FQDNs: ${fqn} -> ${DC_FQDN_FILE}"
        LOG pass "DC map:   ${DC_LIST_FILE} (IP -> FQDN)"
        LOG info "Raw queries -> ${DC_RAW_FILE}; per-domain counts -> ${summary}"
    else
        LOG warn "No domain controllers resolved (SRV or apex-A)"
    fi
    return 0
}
