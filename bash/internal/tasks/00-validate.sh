#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: TARGETS_FILE / EXCLUDES_FILE / DOMAINS_FILE / RECON_DIR and the
# LOG / internal::* helpers are provided by internal_lib.sh, sourced by the
# orchestrator before this task is loaded. ShellCheck cannot follow that chain.

###############################################################################
# TASK: 00-validate
# DESCRIPTION: Ensure the DATA/ layout exists and that a usable targets file
#              is present. If targets.txt is missing, prompt for a path (or a
#              single target) so the run can proceed.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_00_validate
###############################################################################
function run_task_00_validate() {
    internal::ensure_layout

    # ---- targets.txt (required) --------------------------------------------
    if [[ ! -s "${TARGETS_FILE}" ]]; then
        LOG warn "Targets file missing or empty: ${TARGETS_FILE}"

        if [[ ! -t 0 ]]; then
            LOG error "No targets file and no interactive terminal to prompt on"
            return 1
        fi

        local answer
        answer="$(tui::prompt_input \
            "Path to a targets file, or a single IP/CIDR/host to scan" "")"
        answer="${answer//[[:space:]]/}"

        if [[ -z "${answer}" ]]; then
            LOG error "No target provided; cannot continue"
            return 1
        fi

        if [[ -f "${answer}" ]]; then
            if [[ "${answer}" != "${TARGETS_FILE}" ]]; then
                mkdir -p "$(dirname "${TARGETS_FILE}")"
                cp -f "${answer}" "${TARGETS_FILE}"
                LOG info "Copied ${answer} -> ${TARGETS_FILE}"
            fi
        else
            mkdir -p "$(dirname "${TARGETS_FILE}")"
            printf '%s\n' "${answer}" > "${TARGETS_FILE}"
            LOG info "Wrote single target to ${TARGETS_FILE}"
        fi
    fi

    if [[ ! -s "${TARGETS_FILE}" ]]; then
        LOG error "Targets file still empty after prompt: ${TARGETS_FILE}"
        return 1
    fi

    local n_targets
    n_targets="$(internal::clean_list "${TARGETS_FILE}" | wc -l | tr -d ' ')"
    LOG pass "Targets file OK: ${TARGETS_FILE} (${n_targets} entr(y|ies))"

    # ---- excludes.txt (optional) -------------------------------------------
    if [[ -s "${EXCLUDES_FILE}" ]]; then
        local n_excl
        n_excl="$(internal::clean_list "${EXCLUDES_FILE}" | wc -l | tr -d ' ')"
        LOG info "Excludes file present: ${EXCLUDES_FILE} (${n_excl} entr(y|ies))"
    else
        LOG info "No excludes file (optional): ${EXCLUDES_FILE}"
    fi

    # ---- domains.txt (optional) --------------------------------------------
    if [[ -s "${DOMAINS_FILE}" ]]; then
        local n_dom
        n_dom="$(internal::clean_list "${DOMAINS_FILE}" | wc -l | tr -d ' ')"
        LOG info "Domains file present: ${DOMAINS_FILE} (${n_dom} entr(y|ies))"
    else
        LOG info "No domains file (optional): ${DOMAINS_FILE}"
    fi

    return 0
}
