#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: MSF_SCRIPTS_DIR / DATA_DIR / MSF_OUT_DIR / TEE_DIR and the LOG /
# internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 08-msf-modules
# DESCRIPTION: Run every Metasploit resource script under
#              ${MSF_SCRIPTS_DIR}/modules/*.rc with "msfconsole -q -r <rc>".
#              Each rc loads msf_common_runner.rb and targets the hosts/services
#              already imported into the MSF database (task 05). The runner's
#              base/tee directory is steered via MSF_SCRIPTS_HOME so its spool
#              logs land under ${DATA_DIR}/OUTPUT/TEE.
#
#              The shipped rc files hardcode
#                  load '/root/DATA/TOOLS/SCRIPTS/MSF/msf_common_runner.rb'
#              If the runner actually lives elsewhere (non-root HOME, lowercase
#              'msf', etc.) we run patched temp copies pointing at the real
#              path instead.
#
#              Selection is filterable via MSF_MODULES_INCLUDE / _EXCLUDE
#              (space-separated basename globs, without the .rc suffix).
###############################################################################

set -uo pipefail
IFS=$'\n\t'

readonly MSF_HARDCODED_RUNNER="/root/DATA/TOOLS/SCRIPTS/MSF/msf_common_runner.rb"

###############################################################################
# _module_selected <basename-without-ext>
# Honour MSF_MODULES_INCLUDE / MSF_MODULES_EXCLUDE glob filters.
###############################################################################
function _module_selected() {
    local name="${1}" glob
    if [[ -n "${MSF_MODULES_EXCLUDE:-}" ]]; then
        for glob in ${MSF_MODULES_EXCLUDE}; do
            # shellcheck disable=SC2053
            [[ "${name}" == ${glob} ]] && return 1
        done
    fi
    if [[ -n "${MSF_MODULES_INCLUDE:-}" ]]; then
        for glob in ${MSF_MODULES_INCLUDE}; do
            # shellcheck disable=SC2053
            [[ "${name}" == ${glob} ]] && return 0
        done
        return 1
    fi
    return 0
}

###############################################################################
# _resolve_rc <rc-file>
# Echo a path to an rc whose runner-load line points at the real runner.
# Prints the original path if it is already correct; otherwise writes a patched
# copy to a temp file and prints that. Caller removes temp files it created.
###############################################################################
function _resolve_rc() {
    local rc="${1}"
    local runner="${MSF_SCRIPTS_DIR}/msf_common_runner.rb"

    if [[ "${runner}" == "${MSF_HARDCODED_RUNNER}" ]] || [[ ! -f "${runner}" ]]; then
        printf '%s\n' "${rc}"
        return 0
    fi

    if ! grep -qF "${MSF_HARDCODED_RUNNER}" "${rc}"; then
        printf '%s\n' "${rc}"
        return 0
    fi

    local patched
    patched="$(mktemp --suffix=.rc 2> /dev/null || mktemp)"
    sed "s#${MSF_HARDCODED_RUNNER}#${runner}#g" "${rc}" > "${patched}"
    printf '%s\n' "${patched}"
}

###############################################################################
# run_task_08_msf_modules
###############################################################################
function run_task_08_msf_modules() {
    internal::require_cmd msfconsole "install metasploit-framework" || return 1

    local mod_dir="${MSF_SCRIPTS_DIR}/modules"
    if [[ ! -d "${mod_dir}" ]]; then
        LOG warn "MSF modules directory not found: ${mod_dir}; skipping"
        return 0
    fi

    mkdir -p "${MSF_OUT_DIR}" "${TEE_DIR}"
    # Steer msf_common_runner.rb's base_dir (=> OUTPUT/TEE) to the engagement.
    export MSF_SCRIPTS_HOME="${DATA_DIR}"

    local -a rc_files=()
    local f name
    while IFS= read -r f; do
        name="$(basename "${f}" .rc)"
        _module_selected "${name}" && rc_files+=("${f}")
    done < <(find "${mod_dir}" -maxdepth 1 -type f -name '*.rc' | sort)

    if ((${#rc_files[@]} == 0)); then
        LOG warn "No matching module rc files in ${mod_dir}"
        return 0
    fi
    LOG info "Running ${#rc_files[@]} Metasploit module script(s)"

    local ran=0 rc run_rc tee_log
    for rc in "${rc_files[@]}"; do
        name="$(basename "${rc}" .rc)"
        tee_log="${TEE_DIR}/msf_module_${name}.tee"

        if internal::is_dry_run; then
            LOG info "[DRY RUN] would run: msfconsole -q -r ${rc}"
            ((ran++))
            continue
        fi

        run_rc="$(_resolve_rc "${rc}")"
        LOG info "[${name}] msfconsole -q -r ${rc}"
        msfconsole -q -r "${run_rc}" 2>&1 | tee -a "${tee_log}" || {
            LOG warn "[${name}] msfconsole returned non-zero"
        }
        # Clean up a patched temp copy if one was made.
        [[ "${run_rc}" != "${rc}" ]] && rm -f "${run_rc}"
        ((ran++))
    done

    LOG pass "Executed ${ran} Metasploit module script(s); logs in ${TEE_DIR}"
    return 0
}
