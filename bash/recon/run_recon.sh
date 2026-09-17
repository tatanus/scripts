#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2086,SC2154
# Rationale: RECON_* config globals are read by lib/*.sh and phases/*.sh
# after export (SC2154/SC2034); --list word-splits the phase list on purpose
# (SC2086).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : run_recon.sh
# DESCRIPTION  : Unified external reconnaissance orchestrator. Runs an ordered
#                set of phases (validate, osint/discovery, dns-email, cloud,
#                portscan, web, vuln, report) with per-phase state/resume,
#                --only/--skip filtering, dry-run, fail-fast, privilege
#                priming, signal cleanup and config profiles. Combines the
#                staged scanning engine of recon_new.sh with the modular
#                breadth of the recon/ suite.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation - unify recon_new.sh + recon/
# =============================================================================

#===============================================================================
# Constants & Globals
#===============================================================================
readonly RECON_VERSION="2.0.0"
RECON_MODULE_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
readonly RECON_MODULE_DIR
RECON_SELF="${BASH_SOURCE[0]}"
readonly RECON_SELF

# Ordered phase list and the "phase:function" mapping. Plain arrays (not an
# associative array keyed by dashed names) so filtering is unambiguous.
readonly RECON_ALL_PHASES="00-validate 01-osint 02-dns-email 03-cloud \
04-portscan 05-web 06-vuln 07-report"
# Phases run by default (dns-email and cloud are opt-in via --only/--enable).
RECON_DEFAULT_PHASES="00-validate 01-osint 04-portscan 05-web 06-vuln 07-report"

# Runtime toggles (overridable by env / config).
RECON_ENGINE="${RECON_ENGINE:-nmap}"
RECON_THREADS="${RECON_THREADS:-50}"
RECON_MAX_HOSTS="${RECON_MAX_HOSTS:-8192}"
RECON_WHOIS_MAX="${RECON_WHOIS_MAX:-64}"
RECON_DRY_RUN=0
RECON_FORCE=0
RECON_FAIL_FAST=0
RECON_SUDO="${RECON_SUDO:-1}"
RECON_REDISCOVER=0
RECON_ONLY=""
RECON_SKIP=""
RECON_ENABLE=""
RECON_DISC_ONLY="${RECON_DISC_ONLY:-}"
RECON_DISC_SKIP="${RECON_DISC_SKIP:-}"

# Default nuclei template selection (overridable via RECON_NUCLEI_TEMPLATES).
# Built by joining an array so the long -t list stays readable and shfmt-stable.
RECON_NUCLEI_TEMPLATES_DEFAULT_ARR=(
    -t dns -t headless
    -t http/default-logins -t http/exposed-panels -t http/exposures
    -t http/fuzzing -t http/global-matchers -t http/honeypot -t http/iot
    -t http/takeovers -t http/vulnerabilities
    -t network/default-login -t network/enumeration -t network/enumeration/smtp
    -t network/exposures -t network/honeypot -t network/misconfig
    -t network/vulnerabilities
)
RECON_NUCLEI_TEMPLATES_DEFAULT="${RECON_NUCLEI_TEMPLATES_DEFAULT:-${RECON_NUCLEI_TEMPLATES_DEFAULT_ARR[*]}}"

#===============================================================================
# Source libraries and phase modules
#===============================================================================
COMMON_CORE_LIB="${COMMON_CORE_LIB:-${HOME}/.config/bash/lib/common_core}"

# common_core is a hard dependency (Bash 4+): it provides logging
# (info/warn/error/pass/debug/fail), cmd::exists, dns::, net::, and
# platform::timeout used throughout the suite and its m365 library.
if [[ -f "${COMMON_CORE_LIB}/util.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_CORE_LIB}/util.sh"
fi
if ! declare -F cmd::exists > /dev/null 2>&1; then
    printf '[ERROR] common_core not found (set COMMON_CORE_LIB or install it at %s)\n' \
        "${HOME}/.config/bash/lib/common_core" >&2
    exit 1
fi

# shellcheck source=lib/recon_lib.sh
source "${RECON_MODULE_DIR}/lib/recon_lib.sh"
# shellcheck source=lib/scope_lib.sh
source "${RECON_MODULE_DIR}/lib/scope_lib.sh"
# shellcheck source=lib/discovery_lib.sh
source "${RECON_MODULE_DIR}/lib/discovery_lib.sh"

#===============================================================================
# Helpers
#===============================================================================

###############################################################################
# print_usage
###############################################################################
function print_usage() {
    cat << EOF
Unified External Reconnaissance Suite v${RECON_VERSION}

Usage: ${0##*/} [OPTIONS]

Required (env or flags):
  ENGAGEMENT_DIR / --engagement DIR   Base directory for outputs
  TARGETS_FILE   / --targets FILE     IP/CIDR/host scan scope (targets.txt)
Optional:
  DOMAINS_FILE   / --domains FILE     Root domains for enumeration

Options:
  -e, --engagement DIR   Engagement base directory
  -t, --targets FILE     Scan scope file (targets.txt)
  -d, --domains FILE     Domains file (domains.txt); if absent, phase 01
                         derives candidates from the IP scope (review gate)
  -r, --resume           Reuse existing state; skip phases already complete
      --only  a,b,c      Run only these phases
      --skip  a,b,c      Run everything except these phases
      --enable a,b,c     Add opt-in phases (e.g. 02-dns-email,03-cloud)
      --engine nmap|naabu|spoonmap  Port-scan engine (default: nmap)
      --update-tools     Update ProjectDiscovery tools via pdtm, then exit
      --config FILE      Source a config profile
      --force            Re-run phases even if marked complete
      --fail-fast        Abort on the first required-phase failure
      --dry-run          Log commands without executing
      --no-sudo          Do not elevate (nmap SYN/UDP degrade; spoonmap fails)
      --rediscover       Run IP->domain discovery even if domains.txt exists
      --list             List phases and exit
  -h, --help             This help
  -V, --version          Version

Exit codes: 0 ok | 1 deps | 2 input | 3 awaiting domain review | 4 phase failed
EOF
}

###############################################################################
# phase_fn : map "01-osint" -> "run_phase_osint".
###############################################################################
function phase_fn() {
    local name="${1#[0-9][0-9]-}"
    printf 'run_phase_%s\n' "${name//-/_}"
}

###############################################################################
# phase_enabled : honor --only / --skip / default+enable set.
###############################################################################
function phase_enabled() {
    local p="${1}"
    if [[ -n "${RECON_ONLY}" ]]; then
        in_list "${p}" "${RECON_ONLY}" && return 0
        return 1
    fi
    in_list "${p}" "${RECON_SKIP}" && return 1
    in_list "${p}" "${RECON_DEFAULT_PHASES}" && return 0
    in_list "${p}" "${RECON_ENABLE}" && return 0
    return 1
}

###############################################################################
# run_one_phase : load, guard on state, time and record a single phase.
###############################################################################
function run_one_phase() {
    local p="${1}" fn start elapsed rc
    fn="$(phase_fn "${p}")"

    if ! phase_enabled "${p}"; then
        recon_record "${p}" "skipped (filter)" "-"
        return 0
    fi
    if recon_is_done "${p}"; then
        LOG info "phase '${p}' already complete (use --force to re-run)"
        recon_record "${p}" "cached" "-"
        return 0
    fi

    # shellcheck source=/dev/null
    source "${RECON_MODULE_DIR}/phases/${p}.sh" || {
        LOG error "failed to load phase ${p}"
        recon_record "${p}" "load error" "-"
        return "${RECON_ERR_PHASE}"
    }
    if ! declare -F "${fn}" > /dev/null 2>&1; then
        LOG error "phase function ${fn} not defined"
        recon_record "${p}" "no function" "-"
        return "${RECON_ERR_PHASE}"
    fi

    LOG info "================ phase: ${p} ================"
    RECON_STAGE_NOTE=""
    start="${SECONDS}"
    "${fn}"
    rc=$?
    elapsed=$((SECONDS - start))

    if [[ "${rc}" -eq 0 ]] && [[ -n "${RECON_STAGE_NOTE}" ]]; then
        recon_record "${p}" "${RECON_STAGE_NOTE}" "-"
        return 0
    fi
    if [[ "${rc}" -eq 0 ]]; then
        recon_mark_done "${p}"
        LOG pass "phase '${p}' finished in $(fmt_dur "${elapsed}")"
        recon_record "${p}" "ok" "$(fmt_dur "${elapsed}")"
    else
        LOG error "phase '${p}' failed (exit ${rc}) after $(fmt_dur "${elapsed}")"
        recon_record "${p}" "FAILED (rc=${rc})" "$(fmt_dur "${elapsed}")"
        RECON_FAILED="${RECON_FAILED} ${p}"
        if [[ "${RECON_FAIL_FAST}" -eq 1 ]]; then
            recon_print_summary
            LOG error "--fail-fast: aborting after '${p}'"
            exit "${RECON_ERR_PHASE}"
        fi
    fi
    return 0
}

#===============================================================================
# Argument parsing
#===============================================================================
function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -e | --engagement)
                RECON_ENGAGEMENT_DIR="${2:?--engagement needs a value}"
                shift 2
                ;;
            -t | --targets)
                TARGETS_FILE="${2:?--targets needs a value}"
                shift 2
                ;;
            -d | --domains)
                DOMAINS_FILE="${2:?--domains needs a value}"
                shift 2
                ;;
            -r | --resume) shift ;;
            --only)
                RECON_ONLY="${2:?--only needs a value}"
                shift 2
                ;;
            --skip)
                RECON_SKIP="${2:?--skip needs a value}"
                shift 2
                ;;
            --enable)
                RECON_ENABLE="${2:?--enable needs a value}"
                shift 2
                ;;
            --engine)
                RECON_ENGINE="${2:?--engine needs a value}"
                shift 2
                ;;
            --config)
                local cfg="${2:?--config needs a value}"
                need_file "${cfg}" || exit "${RECON_ERR_INPUT}"
                # shellcheck source=/dev/null
                source "${cfg}"
                shift 2
                ;;
            --force)
                RECON_FORCE=1
                shift
                ;;
            --fail-fast)
                RECON_FAIL_FAST=1
                shift
                ;;
            --dry-run)
                RECON_DRY_RUN=1
                shift
                ;;
            --no-sudo)
                RECON_SUDO=0
                shift
                ;;
            --rediscover)
                RECON_REDISCOVER=1
                shift
                ;;
            --list)
                printf '%s\n' "${RECON_ALL_PHASES}" | tr ' ' '\n'
                exit 0
                ;;
            --update-tools)
                if have_cmd pdtm; then
                    pdtm -install-all -update-all 2> /dev/null || pdtm -ia -ua || true
                    exit 0
                fi
                printf 'Error: pdtm not installed (see github.com/projectdiscovery/pdtm)\n' >&2
                exit "${RECON_ERR_DEPS}"
                ;;
            -V | --version)
                printf '%s %s\n' "${0##*/}" "${RECON_VERSION}"
                exit 0
                ;;
            -h | --help)
                print_usage
                exit 0
                ;;
            *)
                print_usage >&2
                LOG error "unknown option: ${1}"
                exit "${RECON_ERR_INPUT}"
                ;;
        esac
    done
}

#===============================================================================
# Main
#===============================================================================
function main() {
    # Bind env defaults before parsing so flags win.
    RECON_ENGAGEMENT_DIR="${ENGAGEMENT_DIR:-}"
    TARGETS_FILE="${TARGETS_FILE:-}"
    DOMAINS_FILE="${DOMAINS_FILE:-}"

    parse_args "$@"

    if [[ -z "${RECON_ENGAGEMENT_DIR}" ]] || [[ -z "${TARGETS_FILE}" ]]; then
        print_usage >&2
        printf 'Error: engagement directory and targets file are required.\n' >&2
        exit "${RECON_ERR_INPUT}"
    fi

    # Resolve inputs to absolute paths NOW: several phases cd into output
    # subdirectories (gowitness, spoonmap) before referencing these, so a
    # relative --engagement/--targets/--domains would break after the cd.
    RECON_ENGAGEMENT_DIR="$(recon_abspath "${RECON_ENGAGEMENT_DIR}")"
    TARGETS_FILE="$(recon_abspath "${TARGETS_FILE}")"
    [[ -n "${DOMAINS_FILE:-}" ]] && DOMAINS_FILE="$(recon_abspath "${DOMAINS_FILE}")"

    RECON_OUTDIR="${RECON_ENGAGEMENT_DIR}/RECON"
    RECON_STATE_DIR="${RECON_OUTDIR}/.state"
    RECON_TEE_DIR="${RECON_ENGAGEMENT_DIR}/OUTPUT/TEE"
    mkdir -p "${RECON_STATE_DIR}" "${RECON_TEE_DIR}" \
        "${RECON_ENGAGEMENT_DIR}/LOGS"

    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    recon_init_logging "${RECON_ENGAGEMENT_DIR}/LOGS/recon_${ts}.log"

    # Master session log: capture ALL stdout+stderr of this run (progress,
    # tool passthrough, errors) to one file while still showing on the
    # terminal. Per-tool output additionally lands in OUTPUT/TEE/ via run().
    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]]; then
        RECON_FULL_LOG="${RECON_ENGAGEMENT_DIR}/LOGS/recon_${ts}.full.log"
        exec > >(tee -a "${RECON_FULL_LOG}") 2>&1
    fi

    trap recon_on_interrupt INT TERM

    LOG info "Unified External Recon v${RECON_VERSION}"
    LOG info "engagement=${RECON_ENGAGEMENT_DIR} engine=${RECON_ENGINE}"
    LOG info "tee dir=${RECON_TEE_DIR}"

    # Validate the selected phase names (newline-split so IFS=$'\n\t' is fine).
    local p
    while IFS= read -r p; do
        [[ -n "${p}" ]] || continue
        in_list "${p}" "${RECON_ALL_PHASES}" || {
            LOG error "unknown phase '${p}' (see --list)"
            exit "${RECON_ERR_INPUT}"
        }
    done < <(printf '%s %s %s' "${RECON_ONLY}" "${RECON_SKIP}" "${RECON_ENABLE}" | tr ', ' '\n')

    # Prime privilege once if a privileged phase is pending.
    if phase_enabled "04-portscan" || phase_enabled "06-vuln"; then
        recon_prime_sudo || exit "${RECON_ERR_DEPS}"
    fi

    local run_start="${SECONDS}"
    local IFS=$' \t\n' # split the space-separated phase list below
    for p in ${RECON_ALL_PHASES}; do
        run_one_phase "${p}"
        if [[ "${RECON_AWAITING_REVIEW}" -eq 1 ]] && [[ "${p}" == "01-osint" ]] &&
            [[ -z "${DOMAINS_FILE:-}" || ! -s "${DOMAINS_FILE:-/nonexistent}" ]]; then
            # Discovery produced candidates and there is no approved domain
            # list yet: keep scanning targets, but enumeration stays gated.
            :
        fi
    done

    recon_print_summary
    [[ "${RECON_AWAITING_REVIEW}" -eq 1 ]] && recon_print_review_gate

    local total=$((SECONDS - run_start))
    if [[ -n "${RECON_FAILED}" ]]; then
        LOG warn "completed in $(fmt_dur "${total}") with failures:${RECON_FAILED}"
        exit "${RECON_ERR_PHASE}"
    fi
    if [[ "${RECON_AWAITING_REVIEW}" -eq 1 ]]; then
        LOG warn "completed in $(fmt_dur "${total}") - domain enumeration awaits your review"
        exit "${RECON_ERR_REVIEW}"
    fi
    LOG pass "all selected phases completed in $(fmt_dur "${total}")"
    exit "${RECON_SUCCESS}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
