#!/usr/bin/env bash
###############################################################################
# NAME         : install.sh
# DESCRIPTION  : Deploy the bash/ and python/ subtrees of this repo into
#                ${HOME}/DATA/TOOLS/SCRIPTS/{bash,python}/. install / update /
#                uninstall flow modelled on bash_setup's installer. Assumes
#                common_core and bash_setup are already installed; preflight
#                refuses to run otherwise.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-06-27
###############################################################################
# EDIT HISTORY:
# DATE        | EDITED BY      | DESCRIPTION
# ------------|----------------|------------------------------------------------
# 2026-06-27  | Adam Compton   | Initial creation.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

#===============================================================================
# Globals
#===============================================================================
: "${QUIET:=false}"
: "${PASS:=0}"
: "${FAIL:=1}"

#===============================================================================
# Logging Fallbacks
#-------------------------------------------------------------------------------
# Defined only if common_core has not already provided richer versions. The
# bootstrap path runs BEFORE common_core is sourced, so we need these to
# print sensible output during preflight.
#===============================================================================
if ! declare -F info > /dev/null 2>&1; then
    function info() {
        [[ "${QUIET}" == "true" ]] && return 0
        printf '[INFO ] %s\n' "${*}" >&2
    }
fi
if ! declare -F warn > /dev/null 2>&1; then
    function warn() { printf '[WARN ] %s\n' "${*}" >&2; }
fi
if ! declare -F error > /dev/null 2>&1; then
    function error() { printf '[ERROR] %s\n' "${*}" >&2; }
fi
if ! declare -F debug > /dev/null 2>&1; then
    function debug() {
        [[ "${QUIET}" == "true" ]] && return 0
        printf '[DEBUG] %s\n' "${*}" >&2
    }
fi
if ! declare -F pass > /dev/null 2>&1; then
    function pass() {
        [[ "${QUIET}" == "true" ]] && return 0
        printf '[PASS ] %s\n' "${*}" >&2
    }
fi
if ! declare -F fail > /dev/null 2>&1; then
    # shellcheck disable=SC2317,SC2329  # fallback called by sourced modules (SC2317 = older shellcheck, SC2329 = newer)
    function fail() { printf '[FAIL ] %s\n' "${*}" >&2; }
fi

#===============================================================================
# Constants
#===============================================================================
readonly SCRIPT_NAME="${0##*/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Read version from project VERSION file
if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
    VERSION="$(< "${SCRIPT_DIR}/VERSION")"
else
    VERSION="unknown"
fi
readonly VERSION

# System paths
readonly COMMON_CORE_DIR="${HOME}/.config/bash/lib/common_core"
readonly COMMON_CORE_UTIL="${COMMON_CORE_DIR}/util.sh"
readonly BASH_RC="${HOME}/.bashrc"
readonly TARGET_ROOT="${HOME}/DATA/TOOLS/SCRIPTS"
# Marker written on a successful install; its presence (and contents) let a
# later run detect a prior install and prompt before overwriting.
readonly SCRIPTS_VERSION_FILE="${TARGET_ROOT}/VERSION"

# Source trees in this repo (relative to SCRIPT_DIR)
readonly -a SOURCE_TREES=(
    "bash"
    "python"
)

# Runtime flags
DRY_RUN="false"
FORCE="false"
SHA256_TOOL=""

#===============================================================================
# Usage
#===============================================================================
function usage() {
    cat << EOF
${SCRIPT_NAME} v${VERSION} - deploy bash/ and python/ to ${TARGET_ROOT}

USAGE:
    ${SCRIPT_NAME} [COMMAND] [OPTIONS]

COMMANDS:
    install     Deploy bash/ and python/ subtrees to ${TARGET_ROOT}/ (default)
    update      Refresh only files that have changed (checksum comparison)
    uninstall   Remove ${TARGET_ROOT}/{bash,python}/ from the user's home

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version
    -q, --quiet     Suppress non-error output
    -f, --force     Update over an existing install without prompting
    -n, --dry-run   Preview actions without making any changes

EXAMPLES:
    ${SCRIPT_NAME}              # Install (default)
    ${SCRIPT_NAME} install      # Install bash/ + python/ trees
    ${SCRIPT_NAME} update       # Update changed files only
    ${SCRIPT_NAME} uninstall    # Remove deployed copies

REQUIREMENTS:
    - Bash 4.0+
    - common_core installed at: ${COMMON_CORE_DIR}
    - bash_setup installed (deployed: ${BASH_RC})

NOTES:
    - Target directory is created if missing (and its parents along with it).
    - update mode falls back to "always copy" when no SHA-256 tool is
      available (sha256sum or shasum).
EOF
}

#===============================================================================
# Preflight
#===============================================================================

###############################################################################
# preflight_checks
#------------------------------------------------------------------------------
# Purpose  : Verify the host has everything install.sh assumes:
#              * Bash 4+
#              * non-empty HOME pointing at a real directory
#              * common_core installed at the documented system path
#              * bash_setup installed (proxy: ${HOME}/.bashrc exists)
#              * source trees in this repo present
# Returns  : 0 if all checks pass; 1+ on failure (one tally per failure)
# Globals  : SHA256_TOOL (sets to "sha256sum" or "shasum" if available)
###############################################################################
function preflight_checks() {
    local errors=0

    # Bash version
    if [[ -z "${BASH_VERSION:-}" ]]; then
        fail "This script must be run under Bash."
        ((errors++))
    elif [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        fail "Bash 4.0+ required. Current: ${BASH_VERSION}"
        ((errors++))
    fi

    # HOME sanity
    if [[ -z "${HOME:-}" ]]; then
        fail "HOME environment variable not set."
        ((errors++))
    elif [[ ! -d "${HOME}" ]]; then
        fail "HOME does not exist or is not a directory: ${HOME}"
        ((errors++))
    fi

    # common_core
    if [[ ! -d "${COMMON_CORE_DIR}" ]]; then
        fail "common_core library not found at: ${COMMON_CORE_DIR}"
        fail "Install common_core first (https://github.com/tatanus/common_core)."
        ((errors++))
    elif [[ ! -f "${COMMON_CORE_UTIL}" ]]; then
        fail "common_core util.sh not found at: ${COMMON_CORE_UTIL}"
        ((errors++))
    fi

    # bash_setup proxy: ${HOME}/.bashrc must exist. We deliberately do not
    # inspect its contents -- the user is free to layer their own changes
    # on top.
    if [[ ! -f "${BASH_RC}" ]]; then
        fail "bash_setup not installed: missing ${BASH_RC}"
        fail "Install bash_setup first (https://github.com/tatanus/bash_setup)."
        ((errors++))
    fi

    # Source trees we are about to deploy must exist
    local t
    for t in "${SOURCE_TREES[@]}"; do
        if [[ ! -d "${SCRIPT_DIR}/${t}" ]]; then
            fail "Missing source tree: ${SCRIPT_DIR}/${t}"
            ((errors++))
        fi
    done

    # Capability detection: SHA-256
    if command -v sha256sum > /dev/null 2>&1; then
        SHA256_TOOL="sha256sum"
    elif command -v shasum > /dev/null 2>&1; then
        SHA256_TOOL="shasum"
    else
        warn "No SHA-256 tool (sha256sum or shasum) found."
        warn "update mode will treat every file as different and re-copy."
    fi

    if ((errors > 0)); then
        return 1
    fi
    pass "Preflight passed."
    return 0
}

###############################################################################
# load_common_core
#------------------------------------------------------------------------------
# Purpose  : Source common_core's util.sh and confirm the helpers we use
#            (file::copy, dir::create, cmd::exists) are present.
# Returns  : 0 on success, 1 if any required symbol is missing.
###############################################################################
function load_common_core() {
    # shellcheck source=/dev/null
    if ! source "${COMMON_CORE_UTIL}"; then
        fail "Failed to source common_core: ${COMMON_CORE_UTIL}"
        return 1
    fi

    local required_funcs=(
        cmd::exists
        file::copy
        dir::create
        info warn debug pass fail
    )

    local f
    for f in "${required_funcs[@]}"; do
        if ! declare -F "${f}" > /dev/null 2>&1; then
            fail "common_core is missing required function: ${f}"
            return 1
        fi
    done

    pass "Loaded common_core utilities."
    return 0
}

###############################################################################
# ensure_target_root
#------------------------------------------------------------------------------
# Purpose  : Create ${TARGET_ROOT} (and any missing parents) if it does not
#            exist yet. Honors --dry-run.
# Returns  : 0 on success, 1 if creation fails.
###############################################################################
function ensure_target_root() {
    if [[ -d "${TARGET_ROOT}" ]]; then
        debug "Target root already exists: ${TARGET_ROOT}"
        return 0
    fi

    info "Creating target root: ${TARGET_ROOT}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        info "[DRY-RUN] would create: ${TARGET_ROOT}"
        return 0
    fi

    if ! dir::create "${TARGET_ROOT}"; then
        fail "Could not create target root: ${TARGET_ROOT}"
        return 1
    fi
    pass "Created target root: ${TARGET_ROOT}"
    return 0
}

#===============================================================================
# File operations
#===============================================================================

###############################################################################
# sha256_of
#------------------------------------------------------------------------------
# Purpose  : Compute the SHA-256 of a single file using whichever tool was
#            detected in preflight. Prints the hex digest to stdout.
# Arguments:
#   $1 : file path
# Returns  : 0 on success, 1 on error or no tool available
###############################################################################
function sha256_of() {
    local f="${1:-}"
    [[ -z "${f}" || ! -f "${f}" ]] && return 1

    case "${SHA256_TOOL}" in
        sha256sum)
            sha256sum -- "${f}" 2> /dev/null | awk '{print $1}'
            ;;
        shasum)
            shasum -a 256 -- "${f}" 2> /dev/null | awk '{print $1}'
            ;;
        *)
            return 1
            ;;
    esac
}

###############################################################################
# files_differ
#------------------------------------------------------------------------------
# Purpose  : Return success if two files differ (or if either side is
#            missing, or if we lack a SHA-256 tool). The "no tool" case is
#            biased toward "different" so update mode does not silently
#            skip files.
# Arguments:
#   $1 : source path
#   $2 : destination path
# Returns  : 0 if different (or undetermined), 1 if identical
###############################################################################
function files_differ() {
    local src="${1:-}"
    local dst="${2:-}"

    [[ -f "${src}" ]] || return 0
    [[ -f "${dst}" ]] || return 0

    if [[ -z "${SHA256_TOOL}" ]]; then
        return 0
    fi

    local src_hash dst_hash
    src_hash=$(sha256_of "${src}") || return 0
    dst_hash=$(sha256_of "${dst}") || return 0
    [[ "${src_hash}" != "${dst_hash}" ]]
}

###############################################################################
# deploy_tree
#------------------------------------------------------------------------------
# Purpose  : Mirror one source subtree into ${TARGET_ROOT}/<tree>/, creating
#            intermediate directories as needed and preserving executable
#            bits. Skips files whose checksum matches the destination unless
#            --force.
# Arguments:
#   $1 : tree name (relative to SCRIPT_DIR), e.g. "bash" or "python"
# Returns  : 0 on success, 1 if any copy fails
###############################################################################
function deploy_tree() {
    local tree="${1:?tree name required}"
    local src_root="${SCRIPT_DIR}/${tree}"
    local dst_root="${TARGET_ROOT}/${tree}"

    if [[ ! -d "${src_root}" ]]; then
        fail "Source tree missing: ${src_root}"
        return 1
    fi

    info "Deploying ${tree}/ -> ${dst_root}/"

    if [[ "${DRY_RUN}" == "true" ]]; then
        local count
        count=$(find "${src_root}" -type f | wc -l | tr -d ' ')
        info "[DRY-RUN] would copy ${count} file(s) from ${src_root}/"
        return 0
    fi

    # Mirror directory structure first so file::copy never has to materialize
    # a parent for us.
    local d
    while IFS= read -r d; do
        local rel="${d#"${src_root}/"}"
        local target="${dst_root}/${rel}"
        if [[ ! -d "${target}" ]]; then
            dir::create "${target}" > /dev/null
        fi
    done < <(find "${src_root}" -mindepth 1 -type d)

    # Ensure dst_root itself exists (for empty subtrees)
    if [[ ! -d "${dst_root}" ]]; then
        dir::create "${dst_root}" > /dev/null
    fi

    local copied=0 skipped=0 failed=0
    local f rel target
    while IFS= read -r f; do
        rel="${f#"${src_root}/"}"
        target="${dst_root}/${rel}"

        if [[ "${FORCE}" != "true" ]] && [[ -f "${target}" ]] && ! files_differ "${f}" "${target}"; then
            ((skipped++))
            continue
        fi

        if file::copy "${f}" "${target}" > /dev/null 2>&1; then
            # Preserve executable bit from source (common_core's file::copy
            # uses cp which honors mode, but be defensive in case a future
            # common_core release changes that).
            if [[ -x "${f}" ]]; then
                chmod +x "${target}" 2> /dev/null || true
            fi
            ((copied++))
        else
            fail "Copy failed: ${f} -> ${target}"
            ((failed++))
        fi
    done < <(find "${src_root}" -type f)

    info "${tree}: copied=${copied} skipped=${skipped} failed=${failed}"
    ((failed == 0))
}

###############################################################################
# remove_tree
#------------------------------------------------------------------------------
# Purpose  : Remove one deployed subtree from ${TARGET_ROOT}/<tree>/.
#            Preserves anything else the user has placed under
#            ${TARGET_ROOT} (i.e. only removes the subtrees we deployed,
#            not the target root itself).
# Arguments:
#   $1 : tree name, e.g. "bash" or "python"
# Returns  : 0 on success, 1 if removal fails
###############################################################################
function remove_tree() {
    local tree="${1:?tree name required}"
    local dst_root="${TARGET_ROOT}/${tree}"

    if [[ ! -d "${dst_root}" ]]; then
        info "Already absent: ${dst_root}"
        return 0
    fi

    info "Removing ${dst_root}/"

    if [[ "${DRY_RUN}" == "true" ]]; then
        local count
        count=$(find "${dst_root}" -type f | wc -l | tr -d ' ')
        info "[DRY-RUN] would remove ${count} file(s) under ${dst_root}/"
        return 0
    fi

    if ! rm -rf -- "${dst_root}"; then
        fail "Could not remove: ${dst_root}"
        return 1
    fi
    pass "Removed: ${dst_root}"
    return 0
}

#===============================================================================
# Commands
#===============================================================================

###############################################################################
# confirm_overwrite
#------------------------------------------------------------------------------
# Purpose  : When a prior install is detected (SCRIPTS_VERSION_FILE exists),
#            decide whether to proceed. FORCE=true or DRY_RUN=true proceed
#            without prompting; a non-interactive shell refuses (advise
#            --force); otherwise ask [y/N].
# Returns  : 0 to proceed, 1 to abort.
###############################################################################
function confirm_overwrite() {
    [[ -f "${SCRIPTS_VERSION_FILE}" ]] || return 0

    local installed="unknown"
    installed="$(cat "${SCRIPTS_VERSION_FILE}" 2> /dev/null || printf 'unknown')"
    info "Existing ${SCRIPT_NAME} install detected: version ${installed}"

    if [[ "${FORCE}" == "true" ]]; then
        info "Force mode: updating over existing install (${installed} -> ${VERSION})"
        return 0
    fi
    if [[ "${DRY_RUN}" == "true" ]]; then
        info "[DRY-RUN] would prompt to overwrite existing install (${installed} -> ${VERSION})"
        return 0
    fi
    if [[ ! -t 0 ]]; then
        info "Non-interactive shell; updating existing install (${installed} -> ${VERSION})"
        return 0
    fi

    local reply
    printf '%s %s already installed; update to %s? [y/N] ' \
        "${SCRIPT_NAME}" "${installed}" "${VERSION}" >&2
    read -r reply
    case "${reply}" in
        [yY] | [yY][eE][sS]) return 0 ;;
        *)
            info "Left existing installation unchanged."
            return 1
            ;;
    esac
}

function cmd_install() {
    local t rc=0

    # Detect a prior install and confirm before overwriting (unless --force).
    confirm_overwrite || return 0

    ensure_target_root || return 1
    for t in "${SOURCE_TREES[@]}"; do
        deploy_tree "${t}" || rc=1
    done

    if ((rc == 0)); then
        # Record the installed version so a later run can detect this install.
        if [[ "${DRY_RUN}" != "true" ]]; then
            printf '%s\n' "${VERSION}" > "${SCRIPTS_VERSION_FILE}" 2> /dev/null ||
                warn "Could not write version marker: ${SCRIPTS_VERSION_FILE}"
        fi
        pass "Installation complete."
    else
        fail "Installation had errors."
    fi
    return "${rc}"
}

function cmd_update() {
    # update is the same code path as install -- checksum comparison
    # already short-circuits unchanged files, and the target root is
    # ensured at the top of cmd_install.
    cmd_install
}

function cmd_uninstall() {
    local t rc=0
    for t in "${SOURCE_TREES[@]}"; do
        remove_tree "${t}" || rc=1
    done
    # Drop the version marker so a later install is treated as fresh.
    [[ "${DRY_RUN}" != "true" ]] && rm -f "${SCRIPTS_VERSION_FILE}" 2> /dev/null
    if ((rc == 0)); then
        pass "Uninstall complete."
    else
        fail "Uninstall had errors."
    fi
    return "${rc}"
}

#===============================================================================
# main
#===============================================================================

function main() {
    local command="install"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            install | update | uninstall)
                command="$1"
                shift
                ;;
            -h | --help)
                usage
                return 0
                ;;
            -v | --version)
                echo "${SCRIPT_NAME} v${VERSION}"
                return 0
                ;;
            -q | --quiet)
                QUIET="true"
                shift
                ;;
            -f | --force)
                FORCE="true"
                shift
                ;;
            -n | --dry-run)
                DRY_RUN="true"
                shift
                ;;
            *)
                fail "Unknown option: $1"
                usage >&2
                return 1
                ;;
        esac
    done

    preflight_checks || return 1
    load_common_core || return 1

    case "${command}" in
        install) cmd_install ;;
        update) cmd_update ;;
        uninstall) cmd_uninstall ;;
        *)
            fail "Unknown command: ${command}"
            return 1
            ;;
    esac
}

main "$@"
