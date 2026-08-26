#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: LIVE_HOSTS_FILE / OUTPUT_DIR and the LOG / internal::* helpers
# come from internal_lib.sh.

###############################################################################
# TASK: 09-netexec
# DESCRIPTION: Run NetExec (nxc) against the hosts discovered by spoonmap:
#                nxc smb  <hosts> -u '' -p '' --pass-pol | tee passpoll.nxc.tee
#                nxc ldap <hosts>                         | tee ldap.nxc.tee
#              Uses hosts.txt as the target list so nxc handles fan-out.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_09_netexec
###############################################################################
function run_task_09_netexec() {
    if [[ ! -s "${LIVE_HOSTS_FILE}" ]]; then
        LOG warn "No spoonmap hosts (${LIVE_HOSTS_FILE}); skipping NetExec"
        return 0
    fi
    internal::require_cmd nxc "pipx install netexec" || return 1

    mkdir -p "${OUTPUT_DIR}"
    local passpol_tee="${OUTPUT_DIR}/passpoll.nxc.tee"
    local ldap_tee="${OUTPUT_DIR}/ldap.nxc.tee"
    local n
    n="$(wc -l < "${LIVE_HOSTS_FILE}" | tr -d ' ')"

    if internal::is_dry_run; then
        LOG info "[DRY RUN] would run: nxc smb ${LIVE_HOSTS_FILE} -u '' -p '' --pass-pol"
        LOG info "[DRY RUN] would run: nxc ldap ${LIVE_HOSTS_FILE}"
        return 0
    fi

    # ---- SMB password policy (null session) --------------------------------
    LOG info "nxc smb --pass-pol against ${n} host(s)"
    nxc smb "${LIVE_HOSTS_FILE}" -u '' -p '' --pass-pol 2>&1 | tee -a "${passpol_tee}" || {
        LOG warn "nxc smb returned non-zero"
    }
    LOG info "SMB pass-pol output -> ${passpol_tee}"

    # ---- LDAP enumeration ---------------------------------------------------
    LOG info "nxc ldap against ${n} host(s)"
    nxc ldap "${LIVE_HOSTS_FILE}" 2>&1 | tee -a "${ldap_tee}" || {
        LOG warn "nxc ldap returned non-zero"
    }
    LOG info "LDAP output -> ${ldap_tee}"

    LOG pass "NetExec sweeps complete"
    return 0
}
