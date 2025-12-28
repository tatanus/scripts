#!/usr/bin/env bash

# =============================================================================
# NAME        : safe_source.sh
# DESCRIPTION : Safely source and revert scripts by snapshotting the environment.
# AUTHOR      : Adam Compton
# DATE CREATED: 2024-12-19 15:24:14
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY    | DESCRIPTION OF CHANGE
# ---------------------|--------------|----------------------------------------
# 2024-12-19 15:24:14  | Adam Compton | Initial creation.
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# Guard to prevent multiple sourcing (portable for old bash)
if [[ -n "${SAFE_SOURCE_SH_LOADED:-}" ]]; then
    # If we're sourced, we can return; if not, do nothing (no-op)
    if ( return 0 2> /dev/null); then
        return 0
    else
        :  # not in a sourced context; continue without re-running body
    fi
else
    SAFE_SOURCE_SH_LOADED=1
fi

#==============================================================================
# Logger bootstrap (local, minimal)
#==============================================================================
function __script_dir() {
    local src="${BASH_SOURCE[0]:-$0}"
    local dir
    dir="$(cd -- "$(dirname -- "${src}")" > /dev/null 2>&1 && pwd -P)" || dir="."
    printf '%s\n' "${dir}"
}

# Try local logger if present (standalone-friendly)
if [[ -r "$(__script_dir)/logger.sh" ]]; then
    # shellcheck source=/dev/null
    . "$(__script_dir)/logger.sh"
fi

# Fallback logging if logger not provided
if ! declare -f info  > /dev/null; then function info() { printf '[* INFO  ] %s\n' "${1}"; }; fi
if ! declare -f warn  > /dev/null; then function warn() { printf '[! WARN  ] %s\n' "${1}" >&2; }; fi
if ! declare -f error > /dev/null; then function error() { printf '[- ERROR ] %s\n' "${1}" >&2; }; fi
if ! declare -f pass  > /dev/null; then function pass() { printf '[+ PASS  ] %s\n' "${1}"; }; fi
if ! declare -f fail  > /dev/null; then function fail() { printf '[! FAIL  ] %s\n' "${1}" >&2; }; fi
if ! declare -f debug > /dev/null; then function debug() { printf '[# DEBUG ] %s\n' "${1}"; }; fi

#==============================================================================
# Globals
#==============================================================================
declare -a _safe_source_stack=()

function _mktemp_dir() {
    local d
    d="$(mktemp -d 2> /dev/null || mktemp -d -t safe_source)" || return 1
    printf '%s\n' "${d}"
}

# Sorted helpers
function _sorted_unique_file() { # usage: _sorted_unique_file <in> <out>
    LC_ALL=C sort -u -- "${1}" > "${2}"
}

# Snapshot helpers
function _snapshot_alias_names() { alias | sed -E 's/^alias[[:space:]]+([^=]+)=.*/\1/' | LC_ALL=C sort -u; }
function _snapshot_alias_defs()  { alias; }
function _snapshot_functions_list() { compgen -A function | LC_ALL=C sort -u; }
function _snapshot_functions_bodies() {
    local fn
    while IFS= read -r fn; do
        declare -f "${fn}" 2> /dev/null || true
        printf '\n'
    done
}
function _snapshot_vars_list()      { compgen -A variable | LC_ALL=C sort -u; }
function _snapshot_exports_list()   { env | LC_ALL=C sort; }
function _snapshot_export_names()   { cut -d= -f1; }

#==============================================================================
# take_env_snapshot <dir>
#==============================================================================
function take_env_snapshot() {
    local dir="${1:-}"
    [[ -z "${dir}" ]] && {
        error "take_env_snapshot: missing dir"
        return 2
    }

    _snapshot_vars_list                                > "${dir}/vars.list"
    _snapshot_exports_list                             > "${dir}/exports.list"
    _snapshot_exports_list | _snapshot_export_names    > "${dir}/exports.names"
    _snapshot_alias_names                              > "${dir}/aliases.names"
    _snapshot_alias_defs                               > "${dir}/aliases.defs"
    _snapshot_functions_list                           > "${dir}/funcs.names"
    _snapshot_functions_list | _snapshot_functions_bodies > "${dir}/funcs.bodies"
}

#==============================================================================
# save_environment <script_path>
#==============================================================================
function save_environment() {
    local script="${1:-}"
    local dir
    dir="$(_mktemp_dir)" || {
        error "mktemp failed"
        return 1
    }
    if ! take_env_snapshot "${dir}"; then
        rm -rf -- "${dir}"
        return 1
    fi
    printf '%s\n' "${script}" > "${dir}/script.path"
    _safe_source_stack+=("${dir}")
    debug "Snapshot saved: ${dir}"
}

#==============================================================================
# safe_source <path>
#==============================================================================
function safe_source() {
    local script="${1:-}"
    if [[ -z "${script}" ]]; then
        error "safe_source: missing path"
        return 2
    fi
    if [[ ! -e "${script}" ]]; then
        error "safe_source: not found: ${script}"
        return 1
    fi
    if [[ ! -r "${script}" ]]; then
        error "safe_source: not readable: ${script}"
        return 1
    fi

    save_environment "${script}" || return 1

    # shellcheck source=/dev/null
    if . "${script}"; then
        info "sourced: ${script}"
        return 0
    fi

    # sourcing failed → pop snapshot and cleanup
    local idx=$((${#_safe_source_stack[@]} - 1))
    local dir="${_safe_source_stack[${idx}]}"
    unset "_safe_source_stack[${idx}]"
    rm -rf -- "${dir}"
    error "safe_source: failed sourcing: ${script}"
    return 1
}

#==============================================================================
# safe_unsource
#==============================================================================
function safe_unsource() {
    local n="${#_safe_source_stack[@]}"
    if ((n == 0)); then
        error "safe_unsource: no snapshot to revert"
        return 1
    fi

    local idx=$((n - 1))
    local before_dir="${_safe_source_stack[${idx}]}"
    unset "_safe_source_stack[${idx}]"

    local after_dir
    after_dir="$(_mktemp_dir)" || {
        error "mktemp failed (after)"
        return 1
    }
    if ! take_env_snapshot "${after_dir}"; then
        rm -rf -- "${after_dir}"
        return 1
    fi

    # Prepare sorted files (avoid process substitution touching locals under set -u)
    local b_fn a_fn b_an a_an b_vn a_vn b_en a_en tmp
    b_fn="${before_dir}/funcs.sorted"
    a_fn="${after_dir}/funcs.sorted"
    b_an="${before_dir}/aliases.sorted"
    a_an="${after_dir}/aliases.sorted"
    b_vn="${before_dir}/vars.sorted"
    a_vn="${after_dir}/vars.sorted"
    b_en="${before_dir}/exports.names.sorted"
    a_en="${after_dir}/exports.names.sorted"
    _sorted_unique_file "${before_dir}/funcs.names"   "${b_fn}"
    _sorted_unique_file "${after_dir}/funcs.names"    "${a_fn}"
    _sorted_unique_file "${before_dir}/aliases.names" "${b_an}"
    _sorted_unique_file "${after_dir}/aliases.names"  "${a_an}"
    _sorted_unique_file "${before_dir}/vars.list"     "${b_vn}"
    _sorted_unique_file "${after_dir}/vars.list"      "${a_vn}"
    _sorted_unique_file "${before_dir}/exports.names" "${b_en}"
    _sorted_unique_file "${after_dir}/exports.names"  "${a_en}"

    #--------------------------
    # Functions: unset new, restore originals
    #--------------------------
    tmp="$(_mktemp_dir)"/new_funcs
    LC_ALL=C comm -13 "${b_fn}" "${a_fn}" > "${tmp}"
    while IFS= read -r fn; do
        [[ -n "${fn}" ]] || continue
        unset -f "${fn}" 2> /dev/null || true
    done < "${tmp}" 2> /dev/null || true
    rm -f -- "${tmp}" 2> /dev/null || true

    # Restore original function bodies (restores changed ones)
    # shellcheck source=/dev/null
    . "${before_dir}/funcs.bodies"

    #--------------------------
    # Aliases: unalias new, restore originals
    #--------------------------
    tmp="$(_mktemp_dir)"/new_aliases
    LC_ALL=C comm -13 "${b_an}" "${a_an}" > "${tmp}"
    while IFS= read -r an; do
        [[ -n "${an}" ]] || continue
        unalias "${an}" 2> /dev/null || true
    done < "${tmp}" 2> /dev/null || true
    rm -f -- "${tmp}" 2> /dev/null || true

    # Restore original alias definitions (the file contains valid `alias name='...'` lines)
    # shellcheck disable=SC1090
    . "${before_dir}/aliases.defs"

    #--------------------------
    # Variables: unset newly introduced (non-exported)
    #--------------------------
    tmp="$(_mktemp_dir)"/new_vars
    LC_ALL=C comm -13 "${b_vn}" "${a_vn}" > "${tmp}"
    while IFS= read -r vn; do
        [[ -n "${vn}" ]] || continue
        unset -v "${vn}" 2> /dev/null || true
    done < "${tmp}" 2> /dev/null || true
    rm -f -- "${tmp}" 2> /dev/null || true

    #--------------------------
    # Exported variables:
    #   - remove new exports,
    #   - restore values for existing exports that changed.
    #--------------------------
    tmp="$(_mktemp_dir)"/new_exports
    LC_ALL=C comm -13 "${b_en}" "${a_en}" > "${tmp}"
    while IFS= read -r en; do
        [[ -n "${en}" ]] || continue
        # shellcheck disable=SC2163  # dynamic name intended
        export -n "${en?}" 2> /dev/null || true # drop export attribute
        if ! grep -qx -- "${en}" "${before_dir}/vars.list"; then
            unset -v "${en}" 2> /dev/null || true
        fi
    done < "${tmp}" 2> /dev/null || true
    rm -f -- "${tmp}" 2> /dev/null || true

    # Restore values for exports that existed before
    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        local name before_val now_val
        name="${line%%=*}"
        before_val="${line#*=}"
        now_val="$(env | LC_ALL=C grep -E "^${name}=" 2> /dev/null | head -n1 | cut -d= -f2- || true)"
        if [[ "${now_val}" != "${before_val}" ]]; then
            printf -v "${name}" '%s' "${before_val}"
            # shellcheck disable=SC2163  # dynamic name intended
            export "${name?}"
        fi
    done < "${before_dir}/exports.list"

    # Cleanup snapshot dirs
    rm -rf -- "${after_dir}" "${before_dir}" || warn "safe_unsource: cleanup incomplete"

    info "Environment reverted to pre-source snapshot."
    return 0
}
