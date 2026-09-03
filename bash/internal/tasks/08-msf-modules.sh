#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: MSF_SCRIPTS_DIR / DATA_DIR / MSF_OUT_DIR / TEE_DIR and the LOG /
# internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 08-msf-modules
# DESCRIPTION: Run every Metasploit resource script under
#              ${MSF_SCRIPTS_DIR}/modules/*.rc against the hosts/services
#              already imported into the MSF database (task 05).
#
#              Preferred path: hand off to the shipped run_all_modules.sh
#              (deployed beside the modules by pentest_setup). That runs all
#              modules in a single msfconsole session (paying console/DB startup
#              once) and then parses the OUTPUT/TEE spool logs for Metasploit
#              successes ([+]) -- so an internal run ends with a consolidated
#              findings summary instead of just a pile of .tee files.
#
#              Fallback path: a per-module "msfconsole -q -r <rc>" loop, used
#              when run_all_modules.sh is absent, when glob filters are set
#              (MSF_MODULES_INCLUDE / _EXCLUDE, richer than run_all_modules'
#              single --pattern), or when the install is relocated off the
#              canonical /root/DATA path (the shipped rc files hardcode
#                  load '/root/DATA/TOOLS/SCRIPTS/MSF/msf_common_runner.rb'
#              which the loop rewrites in patched temp copies).
#
#              Either way the runner's base/tee directory is steered via
#              MSF_SCRIPTS_HOME so spool logs land under ${DATA_DIR}/OUTPUT/TEE.
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
# _can_delegate
# True when task 08 can safely hand off to the shipped run_all_modules.sh:
#   - the helper exists beside the MSF scripts,
#   - no include/exclude glob filters are set (run_all_modules takes a single
#     --pattern; the inline loop supports the richer space-separated lists),
#   - the install lives at the canonical /root/DATA path, so the rc files'
#     hardcoded `load '/root/DATA/.../msf_common_runner.rb'` lines resolve
#     inside run_all_modules' concatenated resource (the inline loop is the
#     one that rewrites that path for relocated installs).
###############################################################################
function _can_delegate() {
    [[ -f "${MSF_SCRIPTS_DIR}/run_all_modules.sh" ]] || return 1
    [[ -z "${MSF_MODULES_INCLUDE:-}" && -z "${MSF_MODULES_EXCLUDE:-}" ]] || return 1
    [[ "${MSF_SCRIPTS_DIR}/msf_common_runner.rb" == "${MSF_HARDCODED_RUNNER}" ]] || return 1
    return 0
}

###############################################################################
# _run_via_run_all
# Delegate to run_all_modules.sh: single msfconsole session + TEE success
# parsing. MSF_TEE_DIR points its parser at the engagement TEE; MSF_SCRIPTS_HOME
# steers the runner's spool to the same place; MSF_MODULES_DIR is explicit so
# it never guesses the wrong directory.
###############################################################################
function _run_via_run_all() {
    local helper="${MSF_SCRIPTS_DIR}/run_all_modules.sh"
    local tee_log
    tee_log="${TEE_DIR}/msf_modules_run_all_$(date +%Y%m%d_%H%M%S).tee"

    local -a cmd=(bash "${helper}")
    internal::is_dry_run && cmd+=(--dry-run)

    LOG info "Delegating to run_all_modules.sh (single session + success parsing)"
    MSF_MODULES_DIR="${MSF_SCRIPTS_DIR}/modules" \
        MSF_TEE_DIR="${TEE_DIR}" \
        MSF_SCRIPTS_HOME="${DATA_DIR}" \
        "${cmd[@]}" 2>&1 | tee -a "${tee_log}" || {
        LOG warn "run_all_modules.sh returned non-zero"
    }
    LOG pass "run_all_modules.sh complete; combined log: ${tee_log}"
    return 0
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

    # Preferred path: the shipped single-session runner with success parsing.
    if _can_delegate; then
        _run_via_run_all
        return 0
    fi
    LOG info "Using per-module fallback loop (filters set, helper absent, or relocated install)"

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
