#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: DOMAINS_FOUND_FILE / DOMAINS_FILE / DNS_OUT_DIR / DC_FILE and the
# LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 03-domain-controllers
# DESCRIPTION: For every domain identified in task 02 (plus any seed
#              domains.txt), query the AD SRV records that advertise domain
#              controllers and resolve them to IPs. Writes a de-duplicated list
#              of DC hostnames/IPs to domain_controllers.txt .
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
# _srv_targets <domain>  -> prints SRV target hostnames
###############################################################################
function _srv_targets() {
    local domain="${1}" prefix fqdn
    for prefix in "${DC_SRV_PREFIXES[@]}"; do
        fqdn="${prefix}.${domain}"
        if cmd::exists dig; then
            # SRV answer: prio weight port target
            dig +short SRV "${fqdn}" 2> /dev/null | awk '{print $4}' | sed 's/\.$//'
        elif cmd::exists host; then
            host -t SRV "${fqdn}" 2> /dev/null | awk '/SRV record/ {print $NF}' | sed 's/\.$//'
        elif cmd::exists nslookup; then
            nslookup -type=SRV "${fqdn}" 2> /dev/null | awk '/service =/ {print $NF}' | sed 's/\.$//'
        fi
    done
}

###############################################################################
# _resolve_a <host>  -> prints A record(s)
###############################################################################
function _resolve_a() {
    local name="${1}"
    if cmd::exists dig; then
        dig +short A "${name}" 2> /dev/null
    elif cmd::exists host; then
        host "${name}" 2> /dev/null | awk '/has address/ {print $NF}'
    elif cmd::exists nslookup; then
        nslookup "${name}" 2> /dev/null | awk '/^Address: / {print $2}'
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

    mkdir -p "${DNS_OUT_DIR}" "$(dirname "${DC_FILE}")"
    local detail="${DNS_OUT_DIR}/domain_controllers_detail.txt"
    local tmp
    tmp="$(mktemp)"
    : > "${detail}"

    local domain host ip
    while IFS= read -r domain; do
        [[ -z "${domain}" ]] && continue
        LOG info "Querying DC SRV records for: ${domain}"
        if internal::is_dry_run; then
            LOG info "[DRY RUN] would query SRV records for ${domain}"
            continue
        fi
        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            printf '%s\t%s\n' "${domain}" "${host}" >> "${detail}"
            printf '%s\n' "${host}" >> "${tmp}"
            while IFS= read -r ip; do
                [[ -z "${ip}" ]] && continue
                printf '%s\thost=%s\tip=%s\n' "${domain}" "${host}" "${ip}" >> "${detail}"
                printf '%s\n' "${ip}" >> "${tmp}"
            done < <(_resolve_a "${host}")
        done < <(_srv_targets "${domain}" | sort -u)
    done < <(internal::clean_list "${domains_src}")

    sort -u "${tmp}" | grep -vE '^$' > "${DC_FILE}" || true
    rm -f "${tmp}"

    local n
    n="$(wc -l < "${DC_FILE}" | tr -d ' ')"
    if ((n > 0)); then
        LOG pass "Domain controllers found: ${n} -> ${DC_FILE}"
    else
        LOG warn "No domain controllers resolved from SRV records"
    fi
    return 0
}
