#!/usr/bin/env bash
# shellcheck disable=SC2034
# Rationale: The path constants and INTERNAL_* work-file variables defined
# here are consumed by the orchestrator and by the task scripts under
# tasks/ (sourced into the same shell). ShellCheck analyses each file in
# isolation and cannot follow that source chain, so it reports these as
# unused where they are only read downstream.

###############################################################################
# NAME         : internal_lib.sh
# DESCRIPTION  : Shared bootstrap + helpers for the Internal Penetration Test
#                suite. Loads common_core (the stack's hard dependency),
#                defines the canonical DATA/ directory layout, and exposes a
#                small set of helpers (LOG, internal::* ) used by every task.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-08-26
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|--------------------------------------------
# 2026-08-26 | Adam Compton | Initial creation - internal pentest suite
###############################################################################

set -uo pipefail
IFS=$'\n\t'

#===============================================================================
# Library Guard
#===============================================================================
if [[ -n "${INTERNAL_LIB_SH_LOADED:-}" ]]; then
    if (return 0 2> /dev/null); then
        return 0
    else
        exit 0
    fi
else
    declare -g INTERNAL_LIB_SH_LOADED=1
fi

#===============================================================================
# common_core Bootstrap
#------------------------------------------------------------------------------
# common_core is the stack's hard dependency, installed by the user at
# ~/.config/bash/lib/common_core/util.sh (see CLAUDE.md). Source it when
# available so we get info/warn/fail/pass/debug, cmd::*, dir::*, tui::* .
# Fall back to minimal local implementations otherwise so the suite still
# runs on a stripped host.
#===============================================================================
# Default common_core's log level to 'info' so the suite's progress messages
# are visible; respect an explicit level chosen by the caller. Must be set
# BEFORE sourcing util.sh, which reads it during early startup.
export UTIL_LOG_LEVEL="${UTIL_LOG_LEVEL:-info}"

INTERNAL_COMMON_CORE_UTIL="${COMMON_CORE_UTIL:-${HOME}/.config/bash/lib/common_core/util.sh}"

if [[ -f "${INTERNAL_COMMON_CORE_UTIL}" ]]; then
    # shellcheck source=/dev/null
    source "${INTERNAL_COMMON_CORE_UTIL}"
fi

# Minimal fallbacks (only defined if common_core did not provide them).
if ! declare -F info > /dev/null 2>&1; then
    function info() { printf '[* INFO  ] %s\n' "$*" >&2; }
    function warn() { printf '[! WARN  ] %s\n' "$*" >&2; }
    function error() { printf '[- ERROR ] %s\n' "$*" >&2; }
    function fail() { printf '[- FAIL  ] %s\n' "$*" >&2; }
    function pass() { printf '[+ PASS  ] %s\n' "$*" >&2; }
    function debug() {
        [[ -n "${INTERNAL_DEBUG:-}" ]] && printf '[  DEBUG ] %s\n' "$*" >&2
        return 0
    }
fi

if ! declare -F cmd::exists > /dev/null 2>&1; then
    function cmd::exists() { command -v "${1:-}" > /dev/null 2>&1; }
fi

if ! declare -F dir::ensure_exists > /dev/null 2>&1; then
    function dir::ensure_exists() { mkdir -p "${1:?dir required}"; }
fi

if ! declare -F tui::prompt_input > /dev/null 2>&1; then
    function tui::prompt_input() {
        local prompt="$1" default="${2:-}" result
        read -rp "${prompt} [${default}]: " result
        printf '%s\n' "${result:-${default}}"
    }
fi

if ! declare -F tui::prompt_yes_no > /dev/null 2>&1; then
    function tui::prompt_yes_no() {
        local prompt="${1:-Continue?}" response
        while true; do
            read -rp "${prompt} [y/n]: " response
            case "${response,,}" in
                y | yes) return 0 ;;
                n | no) return 1 ;;
                *) ;;
            esac
        done
    }
fi

# Unified logging front-end (mirrors run_external_recon_suite.sh).
function LOG() {
    local level="${1:-info}"
    shift
    case "${level}" in
        info) info "$*" ;;
        warn) warn "$*" ;;
        error | fail) fail "$*" ;;
        pass) pass "$*" ;;
        debug) debug "$*" ;;
        *) printf '[%s] %s\n' "${level}" "$*" >&2 ;;
    esac
}

#===============================================================================
# Canonical DATA/ Directory Layout
#------------------------------------------------------------------------------
# Matches pentest_setup/config/config.sh so the two stay interoperable. Every
# path is overridable via the environment (or the suite config file) to keep
# the suite host-agnostic and testable.
#===============================================================================
export DATA_DIR="${DATA_DIR:-${HOME}/DATA}"

export RECON_DIR="${RECON_DIR:-${DATA_DIR}/RECON}"
export PORTS_DIR="${PORTS_DIR:-${RECON_DIR}/PORTS}"

export OUTPUT_DIR="${OUTPUT_DIR:-${DATA_DIR}/OUTPUT}"
export TEE_DIR="${TEE_DIR:-${OUTPUT_DIR}/TEE}"
export PORTSCAN_DIR="${PORTSCAN_DIR:-${OUTPUT_DIR}/PORTSCAN}"
export SPOONMAP_OUT_DIR="${SPOONMAP_OUT_DIR:-${PORTSCAN_DIR}/SPOONMAP}"
export DNS_OUT_DIR="${DNS_OUT_DIR:-${OUTPUT_DIR}/DNS}"
export WEB_OUT_DIR="${WEB_OUT_DIR:-${OUTPUT_DIR}/WEB}"
export GOWITNESS_OUT_DIR="${GOWITNESS_OUT_DIR:-${OUTPUT_DIR}/GOWITNESS}"
export MSF_OUT_DIR="${MSF_OUT_DIR:-${OUTPUT_DIR}/MSF}"
export WORK_DIR="${WORK_DIR:-${OUTPUT_DIR}/INTERNAL}"

export TOOLS_DIR="${TOOLS_DIR:-${DATA_DIR}/TOOLS}"
export SCRIPTS_DIR="${SCRIPTS_DIR:-${TOOLS_DIR}/SCRIPTS}"
# MSF scripts ship from pentest_setup to SCRIPTS/MSF (uppercase); fall back to
# a lowercase 'msf' directory if that is what a given host actually has.
if [[ -z "${MSF_SCRIPTS_DIR:-}" ]]; then
    if [[ -d "${SCRIPTS_DIR}/MSF" ]]; then
        MSF_SCRIPTS_DIR="${SCRIPTS_DIR}/MSF"
    elif [[ -d "${SCRIPTS_DIR}/msf" ]]; then
        MSF_SCRIPTS_DIR="${SCRIPTS_DIR}/msf"
    else
        MSF_SCRIPTS_DIR="${SCRIPTS_DIR}/MSF"
    fi
fi
export MSF_SCRIPTS_DIR
export SPOONMAP_DIR="${SPOONMAP_DIR:-${TOOLS_DIR}/spoonmap}"

# Input files (defaults follow the spec: /root/DATA/RECON/*.txt).
export TARGETS_FILE="${TARGETS_FILE:-${RECON_DIR}/targets.txt}"
export EXCLUDES_FILE="${EXCLUDES_FILE:-${RECON_DIR}/excludes.txt}"
export DOMAINS_FILE="${DOMAINS_FILE:-${RECON_DIR}/domains.txt}"

# Shared work files produced by one task and consumed by later ones.
export LIVE_HOSTS_FILE="${LIVE_HOSTS_FILE:-${WORK_DIR}/hosts.txt}"
export IPPORTS_FILE="${IPPORTS_FILE:-${WORK_DIR}/ipports.txt}"
export WEB_IPPORTS_FILE="${WEB_IPPORTS_FILE:-${WORK_DIR}/web_ipports.txt}"
export WEB_URLS_FILE="${WEB_URLS_FILE:-${WORK_DIR}/web_urls.txt}"
export DOMAINS_FOUND_FILE="${DOMAINS_FOUND_FILE:-${WORK_DIR}/domains_found.txt}"
export DC_FILE="${DC_FILE:-${WORK_DIR}/domain_controllers.txt}"

# Tunables (overridable via config file / environment).
export MSF_THREADS="${MSF_THREADS:-10}"
export INTERNAL_DRY_RUN="${INTERNAL_DRY_RUN:-false}"

#===============================================================================
# Helpers
#===============================================================================

###############################################################################
# internal::ensure_layout
# Create the full DATA/ directory tree the suite reads from and writes to.
###############################################################################
function internal::ensure_layout() {
    local d
    for d in \
        "${RECON_DIR}" "${PORTS_DIR}" \
        "${OUTPUT_DIR}" "${TEE_DIR}" "${PORTSCAN_DIR}" "${SPOONMAP_OUT_DIR}" \
        "${DNS_OUT_DIR}" "${WEB_OUT_DIR}" "${GOWITNESS_OUT_DIR}" \
        "${MSF_OUT_DIR}" "${WORK_DIR}"; do
        dir::ensure_exists "${d}" > /dev/null 2>&1 || mkdir -p "${d}"
    done
}

###############################################################################
# internal::require_cmd
# Return 0 if a binary is present, else LOG error and return 1.
# Arguments: $1 - binary name; $2 - optional hint on how to install it.
###############################################################################
function internal::require_cmd() {
    local bin="${1:?binary name required}" hint="${2:-}"
    if cmd::exists "${bin}"; then
        return 0
    fi
    # Under dry-run, don't abort - let the task preview what it would do.
    if internal::is_dry_run; then
        LOG warn "[DRY RUN] required tool missing (would be needed): ${bin}${hint:+ (${hint})}"
        return 0
    fi
    LOG error "Required tool not found: ${bin}${hint:+ (${hint})}"
    return 1
}

###############################################################################
# internal::optional_cmd
# Return 0 if a binary is present, else LOG warn and return 1 (task may skip).
###############################################################################
function internal::optional_cmd() {
    local bin="${1:?binary name required}" hint="${2:-}"
    if cmd::exists "${bin}"; then
        return 0
    fi
    LOG warn "Optional tool not found, skipping: ${bin}${hint:+ (${hint})}"
    return 1
}

###############################################################################
# internal::is_dry_run
###############################################################################
function internal::is_dry_run() {
    [[ "${INTERNAL_DRY_RUN}" == "true" ]]
}

###############################################################################
# internal::run
# Log and execute a command (honoring dry-run). All arguments after the
# description form the command to run.
# Arguments: $1 - human description; $@ - command + args
###############################################################################
function internal::run() {
    local desc="${1:?description required}"
    shift
    LOG info "${desc}"
    LOG debug "exec: $*"
    if internal::is_dry_run; then
        LOG info "[DRY RUN] would run: $*"
        return 0
    fi
    "$@"
}

###############################################################################
# internal::is_ipv4
# Return 0 if the argument is a bare IPv4 address (no CIDR suffix).
###############################################################################
function internal::is_ipv4() {
    [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

###############################################################################
# internal::clean_list
# Read a file, strip comments/blank lines and surrounding whitespace, and
# print the remaining entries (one per line). Missing file -> no output.
# Arguments: $1 - file path
###############################################################################
function internal::clean_list() {
    local file="${1:-}"
    [[ -f "${file}" ]] || return 0
    sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "${file}" |
        grep -vE '^$' || true
}
