#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: TARGETS_FILE / DOMAINS_FILE / DNS_OUT_DIR / DOMAINS_FOUND_FILE /
# DNS_SERVERS and the LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 02-dns-lookup
# DESCRIPTION: Resolve the internal scope in targets.txt and harvest domain
#              names into domains_found.txt (merged with any seed domains.txt)
#              for the domain-controller task that follows.
#
#              Primary path: `nmap -sL` over targets.txt. A list scan sends no
#              probes to the hosts, expands CIDRs itself, and performs reverse
#              (PTR) resolution on every address in one pass -- which the old
#              per-host `dig` loop did not, since it skipped CIDR entries
#              entirely (the common case for an internal engagement).
#
#              Because this is INTERNAL recon, PTR records only resolve against
#              the environment's own DNS (typically the domain controllers).
#              Set DNS_SERVERS to point nmap at them; otherwise the host's
#              configured resolver is used (correct when the box already points
#              at internal DNS).
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
# _ptr_lookup <resolver> <ip> [server]  -> prints resolved name(s)
###############################################################################
function _ptr_lookup() {
    local r="${1}" ip="${2}" server="${3:-}"
    case "${r}" in
        dig) dig +short -x "${ip}" ${server:+@"${server}"} 2> /dev/null | sed 's/\.$//' ;;
        host) host "${ip}" ${server:+"${server}"} 2> /dev/null | awk '/pointer|name pointer/ {print $NF}' | sed 's/\.$//' ;;
        nslookup) nslookup "${ip}" ${server:+"${server}"} 2> /dev/null | awk -F'= ' '/name =/ {print $2}' | sed 's/\.$//' ;;
        *) ;;
    esac
}

###############################################################################
# _a_lookup <resolver> <host> [server]  -> prints resolved A record(s)
###############################################################################
function _a_lookup() {
    local r="${1}" name="${2}" server="${3:-}"
    case "${r}" in
        dig) dig +short A "${name}" ${server:+@"${server}"} 2> /dev/null ;;
        host) host "${name}" ${server:+"${server}"} 2> /dev/null | awk '/has address/ {print $NF}' ;;
        nslookup) nslookup "${name}" ${server:+"${server}"} 2> /dev/null | awk '/^Address: / {print $2}' ;;
        *) ;;
    esac
}

###############################################################################
# _dns_via_nmap <reverse_out> <domains_out>  -> resolve the scope via `nmap -sL`
# Appends "ip<TAB>name" rows to <reverse_out> and parent domains to <domains_out>.
###############################################################################
function _dns_via_nmap() {
    local reverse_out="${1}" domains_out="${2}"
    local nmap_out="${DNS_OUT_DIR}/nmap_sl.txt"

    local -a nmap_args=(-sL -R)
    [[ -n "${DNS_SERVERS:-}" ]] && nmap_args+=(--dns-servers "${DNS_SERVERS}")
    nmap_args+=(-iL "${TARGETS_FILE}" -oN "${nmap_out}")

    # nmap also prints to stdout; -oN captures the parseable copy, so discard
    # stdout (logging still goes to stderr).
    internal::run "nmap -sL reverse-DNS sweep${DNS_SERVERS:+ via ${DNS_SERVERS}}" \
        nmap "${nmap_args[@]}" > /dev/null || return 1
    internal::is_dry_run && return 0

    # nmap -oN prints one of:
    #   "Nmap scan report for <name> (<ip>)"  -> PTR/forward resolved
    #   "Nmap scan report for <ip>"           -> no name; skip
    local line rest name ip
    while IFS= read -r line; do
        rest="${line#Nmap scan report for }"
        if [[ "${rest}" =~ ^(.+)\ \(([0-9.]+)\)$ ]]; then
            name="${BASH_REMATCH[1]}"
            ip="${BASH_REMATCH[2]}"
            printf '%s\t%s\n' "${ip}" "${name}" >> "${reverse_out}"
            [[ "${name}" == *.* ]] && printf '%s\n' "${name#*.}" >> "${domains_out}"
        fi
    done < <(grep '^Nmap scan report for ' "${nmap_out}" 2> /dev/null)
    return 0
}

###############################################################################
# _dns_via_resolver <reverse_out> <forward_out> <domains_out> -> dig/host fallback
# Handles bare IPs (PTR) and hostnames (A) but NOT CIDRs (nmap is preferred).
# Appends parent domains to <domains_out>.
###############################################################################
function _dns_via_resolver() {
    local reverse_out="${1}" forward_out="${2}" domains_out="${3}"
    local resolver first_server="${DNS_SERVERS%%,*}"
    resolver="$(_resolver)"
    if [[ -z "${resolver}" ]]; then
        LOG error "No DNS resolver found (need nmap, dig, host, or nslookup)"
        return 1
    fi
    LOG info "Using resolver: ${resolver}${first_server:+ @${first_server}}"
    LOG warn "nmap not found; CIDR ranges in ${TARGETS_FILE} will be skipped"

    local entry names name
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        [[ "${entry}" == */* ]] && continue # can't expand CIDRs without nmap

        if internal::is_ipv4 "${entry}"; then
            internal::is_dry_run && {
                LOG info "[DRY RUN] would PTR lookup ${entry}"
                continue
            }
            names="$(_ptr_lookup "${resolver}" "${entry}" "${first_server}")"
            [[ -z "${names}" ]] && continue
            while IFS= read -r name; do
                [[ -z "${name}" ]] && continue
                printf '%s\t%s\n' "${entry}" "${name}" >> "${reverse_out}"
                [[ "${name}" == *.* ]] && printf '%s\n' "${name#*.}" >> "${domains_out}"
            done <<< "${names}"
        else
            internal::is_dry_run && {
                LOG info "[DRY RUN] would A lookup ${entry}"
                continue
            }
            names="$(_a_lookup "${resolver}" "${entry}" "${first_server}")"
            while IFS= read -r name; do
                [[ -z "${name}" ]] && continue
                printf '%s\t%s\n' "${entry}" "${name}" >> "${forward_out}"
            done <<< "${names}"
            [[ "${entry}" == *.* ]] && printf '%s\n' "${entry#*.}" >> "${domains_out}"
        fi
    done < <(internal::clean_list "${TARGETS_FILE}")
    return 0
}

###############################################################################
# run_task_02_dns_lookup
###############################################################################
function run_task_02_dns_lookup() {
    mkdir -p "${DNS_OUT_DIR}" "$(dirname "${DOMAINS_FOUND_FILE}")"
    local reverse_out="${DNS_OUT_DIR}/reverse_lookups.txt"
    local forward_out="${DNS_OUT_DIR}/forward_lookups.txt"
    : > "${reverse_out}"
    : > "${forward_out}"

    if [[ -n "${DNS_SERVERS:-}" ]]; then
        LOG info "Querying internal DNS server(s): ${DNS_SERVERS}"
    else
        LOG info "Using the host's configured DNS resolver (set DNS_SERVERS for internal DNS)"
    fi

    # Collect discovered parent domains from whichever path runs.
    local discovered_file="${DNS_OUT_DIR}/.domains.tmp"
    : > "${discovered_file}"
    if cmd::exists nmap; then
        _dns_via_nmap "${reverse_out}" "${discovered_file}" || return 1
    else
        _dns_via_resolver "${reverse_out}" "${forward_out}" "${discovered_file}" || return 1
    fi

    if internal::is_dry_run; then
        rm -f "${discovered_file}"
        return 0
    fi

    # Merge discovered domains with any seed domains.txt, unique + sorted.
    {
        internal::clean_list "${DOMAINS_FILE}"
        cat "${discovered_file}" 2> /dev/null
    } | sort -u | grep -vE '^$' > "${DOMAINS_FOUND_FILE}" || true
    rm -f "${discovered_file}"

    local rc dc
    rc="$(wc -l < "${reverse_out}" | tr -d ' ')"
    dc="$(wc -l < "${DOMAINS_FOUND_FILE}" | tr -d ' ')"
    LOG pass "Resolved names: ${rc} -> ${reverse_out}"
    LOG pass "Domains identified: ${dc} -> ${DOMAINS_FOUND_FILE}"
    return 0
}
