#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: EXCLUDES_FILE and the LOG / internal::* helpers come from
# internal_lib.sh (sourced by the orchestrator before this task loads).

###############################################################################
# TASK: 01-excludes
# DESCRIPTION: If excludes.txt exists, use iptables to DROP all traffic to and
#              from each listed IP / CIDR. Rules live in a dedicated
#              INTERNAL_EXCLUDES chain so the block is idempotent and trivially
#              reversible:
#                  iptables -F INTERNAL_EXCLUDES     # clear the drops
###############################################################################

set -uo pipefail
IFS=$'\n\t'

readonly INTERNAL_EXCLUDES_CHAIN="INTERNAL_EXCLUDES"

###############################################################################
# _ipt_ensure_chain
# Create the custom chain (if absent) and wire INPUT/OUTPUT/FORWARD to jump to
# it exactly once. Flush it so repeated runs do not stack duplicate rules.
###############################################################################
function _ipt_ensure_chain() {
    local ipt="${1}"
    "${ipt}" -N "${INTERNAL_EXCLUDES_CHAIN}" 2> /dev/null || true
    "${ipt}" -F "${INTERNAL_EXCLUDES_CHAIN}"

    local hook
    for hook in INPUT OUTPUT FORWARD; do
        if ! "${ipt}" -C "${hook}" -j "${INTERNAL_EXCLUDES_CHAIN}" 2> /dev/null; then
            "${ipt}" -I "${hook}" -j "${INTERNAL_EXCLUDES_CHAIN}"
        fi
    done
}

###############################################################################
# run_task_01_excludes
###############################################################################
function run_task_01_excludes() {
    if [[ ! -s "${EXCLUDES_FILE}" ]]; then
        LOG info "No excludes file present, nothing to block: ${EXCLUDES_FILE}"
        return 0
    fi

    internal::require_cmd iptables "install iptables" || return 1

    if [[ "${EUID:-$(id -u)}" -ne 0 ]] && ! internal::is_dry_run; then
        LOG error "Blocking excludes requires root (iptables). Re-run with sudo."
        return 1
    fi

    if internal::is_dry_run; then
        LOG info "[DRY RUN] would create ${INTERNAL_EXCLUDES_CHAIN} and DROP:"
        internal::clean_list "${EXCLUDES_FILE}" | while IFS= read -r entry; do
            LOG info "[DRY RUN]   ${entry}"
        done
        return 0
    fi

    _ipt_ensure_chain iptables

    local entry blocked=0
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        # Drop both directions for the excluded network.
        if iptables -A "${INTERNAL_EXCLUDES_CHAIN}" -s "${entry}" -j DROP &&
            iptables -A "${INTERNAL_EXCLUDES_CHAIN}" -d "${entry}" -j DROP; then
            ((blocked += 1))
            LOG info "Blocked: ${entry}"
        else
            LOG warn "Failed to add rule for: ${entry}"
        fi
    done < <(internal::clean_list "${EXCLUDES_FILE}")

    LOG pass "Applied iptables DROP rules for ${blocked} exclude entr(y|ies)"
    LOG info "To undo: iptables -F ${INTERNAL_EXCLUDES_CHAIN}"
    return 0
}
