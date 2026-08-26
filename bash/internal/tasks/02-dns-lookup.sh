#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: TARGETS_FILE / DOMAINS_FILE / DNS_OUT_DIR / DOMAINS_FOUND_FILE and
# the LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 02-dns-lookup
# DESCRIPTION: Resolve every entry in targets.txt - reverse (PTR) lookups for
#              bare IPs, forward (A) lookups for hostnames - and harvest the
#              discovered domain names into domains_found.txt (merged with any
#              seed domains.txt) for the domain-controller task that follows.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# _resolver
# Echo the name of an available DNS lookup tool, or empty if none.
###############################################################################
function _resolver() {
    if cmd::exists dig; then
        echo dig
    elif cmd::exists host; then
        echo host
    elif cmd::exists nslookup; then
        echo nslookup
    fi
}

###############################################################################
# _ptr_lookup <resolver> <ip>  -> prints resolved name(s)
###############################################################################
function _ptr_lookup() {
    local r="${1}" ip="${2}"
    case "${r}" in
        dig) dig +short -x "${ip}" 2> /dev/null | sed 's/\.$//' ;;
        host) host "${ip}" 2> /dev/null | awk '/pointer|name pointer/ {print $NF}' | sed 's/\.$//' ;;
        nslookup) nslookup "${ip}" 2> /dev/null | awk -F'= ' '/name =/ {print $2}' | sed 's/\.$//' ;;
        *) ;;
    esac
}

###############################################################################
# _a_lookup <resolver> <host>  -> prints resolved A record(s)
###############################################################################
function _a_lookup() {
    local r="${1}" name="${2}"
    case "${r}" in
        dig) dig +short A "${name}" 2> /dev/null ;;
        host) host "${name}" 2> /dev/null | awk '/has address/ {print $NF}' ;;
        nslookup) nslookup "${name}" 2> /dev/null | awk '/^Address: / {print $2}' ;;
        *) ;;
    esac
}

###############################################################################
# run_task_02_dns_lookup
###############################################################################
function run_task_02_dns_lookup() {
    local resolver
    resolver="$(_resolver)"
    if [[ -z "${resolver}" ]]; then
        LOG error "No DNS resolver found (need dig, host, or nslookup)"
        return 1
    fi
    LOG info "Using resolver: ${resolver}"

    mkdir -p "${DNS_OUT_DIR}" "$(dirname "${DOMAINS_FOUND_FILE}")"
    local reverse_out="${DNS_OUT_DIR}/reverse_lookups.txt"
    local forward_out="${DNS_OUT_DIR}/forward_lookups.txt"
    : > "${reverse_out}"
    : > "${forward_out}"

    # Accumulate discovered FQDNs (host records) and their parent domains.
    local -a discovered_domains=()

    local entry names name
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        # Skip CIDR ranges for per-host resolution.
        [[ "${entry}" == */* ]] && continue

        if internal::is_ipv4 "${entry}"; then
            if internal::is_dry_run; then
                LOG info "[DRY RUN] would PTR lookup ${entry}"
                continue
            fi
            names="$(_ptr_lookup "${resolver}" "${entry}")"
            [[ -z "${names}" ]] && continue
            while IFS= read -r name; do
                [[ -z "${name}" ]] && continue
                printf '%s\t%s\n' "${entry}" "${name}" >> "${reverse_out}"
                # Parent domain = everything after the first dot.
                [[ "${name}" == *.* ]] && discovered_domains+=("${name#*.}")
            done <<< "${names}"
        else
            if internal::is_dry_run; then
                LOG info "[DRY RUN] would A lookup ${entry}"
                continue
            fi
            names="$(_a_lookup "${resolver}" "${entry}")"
            while IFS= read -r name; do
                [[ -z "${name}" ]] && continue
                printf '%s\t%s\n' "${entry}" "${name}" >> "${forward_out}"
            done <<< "${names}"
            [[ "${entry}" == *.* ]] && discovered_domains+=("${entry#*.}")
        fi
    done < <(internal::clean_list "${TARGETS_FILE}")

    # Merge discovered domains with any seed domains.txt, unique + sorted.
    {
        internal::clean_list "${DOMAINS_FILE}"
        ((${#discovered_domains[@]} > 0)) && printf '%s\n' "${discovered_domains[@]}"
    } | sort -u | grep -vE '^$' > "${DOMAINS_FOUND_FILE}" || true

    local rc dc
    rc="$(wc -l < "${reverse_out}" | tr -d ' ')"
    dc="$(wc -l < "${DOMAINS_FOUND_FILE}" | tr -d ' ')"
    LOG pass "Reverse lookups: ${rc} -> ${reverse_out}"
    LOG pass "Domains identified: ${dc} -> ${DOMAINS_FOUND_FILE}"
    return 0
}
