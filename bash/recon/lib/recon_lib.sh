#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154,SC2329
# Rationale: several constants and palette entries (exit codes, ANSI
# colors, RECON_* globals) are consumed by the orchestrator and by the
# phase modules under phases/, which ShellCheck does not follow across
# the source chain.
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : recon_lib.sh
# DESCRIPTION  : Core library for the unified external recon framework.
#                Provides logging bridge, command runners, state/resume
#                bookkeeping, signal handling, privilege priming, scope
#                expansion and the domain-review gate. Sourced by
#                run_recon.sh and every phases/*.sh module.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation - unify recon_new.sh + recon/
# =============================================================================

# Source guard: prevent double-sourcing across the phase modules.
if [[ -z "${RECON_LIB_LOADED:-}" ]]; then
    RECON_LIB_LOADED=1

    #===========================================================================
    # Constants
    #===========================================================================
    readonly RECON_SUCCESS=0
    readonly RECON_ERR_DEPS=1
    readonly RECON_ERR_INPUT=2
    readonly RECON_ERR_REVIEW=3
    readonly RECON_ERR_PHASE=4

    #===========================================================================
    # Logging bridge
    #---------------------------------------------------------------------------
    # Prefer common_core's logger, then the recon-suite common_utils.sh, then a
    # minimal built-in. A single LOG() front-end is exposed to every module so
    # phases never care which backend is active.
    #===========================================================================
    function recon_init_logging() {
        local logfile="${1:-}"

        if declare -F logger_log > /dev/null 2>&1; then
            # common_core instance logger.
            if declare -F logger_init > /dev/null 2>&1; then
                logger_init "recon" "${logfile}" "${RECON_LOG_LEVEL:-info}" "true" "true"
            fi
            function LOG() { logger_log "recon" "$@"; }
            return 0
        fi

        if declare -F info > /dev/null 2>&1 && declare -F pass > /dev/null 2>&1; then
            # common_utils.sh style helpers already sourced.
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
            return 0
        fi

        # Built-in fallback.
        RECON_RUNLOG="${logfile}"
        function LOG() {
            local level="${1:-info}"
            shift
            local ts
            ts="$(date '+%F %T')"
            printf '[%s] [%s] %s\n' "${ts}" "${level}" "$*" >&2
            if [[ -n "${RECON_RUNLOG:-}" ]]; then
                printf '[%s] [%s] %s\n' "${ts}" "${level}" "$*" >> "${RECON_RUNLOG}"
            fi
        }
        return 0
    }

    #===========================================================================
    # Small helpers
    #===========================================================================

    ###########################################################################
    # have_cmd
    # Purpose : Test whether a command is available on PATH.
    # Args    : $1 - command name
    ###########################################################################
    function have_cmd() {
        command -v "${1}" > /dev/null 2>&1
    }

    ###########################################################################
    # recon_abspath
    # Purpose : Resolve a path to absolute form so it survives a later `cd`.
    #           Existing dirs/files are canonicalized; a not-yet-created path
    #           is rooted at $PWD (kept absolute, good enough for mkdir/cd).
    # Args    : $1 - path
    ###########################################################################
    function recon_abspath() {
        local p="${1}"
        if [[ -d "${p}" ]]; then
            (cd "${p}" > /dev/null 2>&1 && pwd)
        elif [[ -e "${p}" ]]; then
            local dir base
            dir="$(cd "$(dirname "${p}")" > /dev/null 2>&1 && pwd)"
            base="$(basename "${p}")"
            printf '%s/%s\n' "${dir}" "${base}"
        else
            case "${p}" in
                /*) printf '%s\n' "${p}" ;;
                *) printf '%s/%s\n' "$(pwd)" "${p}" ;;
            esac
        fi
    }

    ###########################################################################
    # need_file
    # Purpose : Abort the current phase unless a file exists and is non-empty.
    # Args    : $1 - path
    ###########################################################################
    function need_file() {
        if [[ ! -f "${1}" ]]; then
            LOG error "required input not found: ${1}"
            return "${RECON_ERR_INPUT}"
        fi
        if [[ ! -s "${1}" ]]; then
            LOG error "required input is empty: ${1}"
            return "${RECON_ERR_INPUT}"
        fi
        return 0
    }

    ###########################################################################
    # in_list
    # Purpose : Membership test against a comma- or space-separated list.
    # Args    : $1 - needle ; $2 - haystack
    ###########################################################################
    function in_list() {
        local needle="${1}" hay="${2}" item
        # Re-admit space to IFS: the suite runs under IFS=$'\n\t', which would
        # otherwise stop the loop below from splitting a space-separated list.
        local IFS=$' \t\n'
        hay="${hay//,/ }"
        for item in ${hay}; do
            [[ "${item}" == "${needle}" ]] && return 0
        done
        return 1
    }

    ###########################################################################
    # count_lines
    # Purpose : Count non-blank lines in a file (0 if missing).
    # Args    : $1 - path
    ###########################################################################
    function count_lines() {
        local n
        if [[ -f "${1}" ]]; then
            n="$(grep -cve '^[[:space:]]*$' "${1}" 2> /dev/null || true)"
            [[ -n "${n}" ]] || n=0
            printf '%s\n' "${n}"
        else
            printf '0\n'
        fi
    }

    ###########################################################################
    # fmt_dur
    # Purpose : Render a second count as a human-readable duration.
    # Args    : $1 - seconds
    ###########################################################################
    function fmt_dur() {
        local t="${1}"
        if [[ "${t}" -lt 60 ]]; then
            printf '%ds\n' "${t}"
        elif [[ "${t}" -lt 3600 ]]; then
            printf '%dm%02ds\n' "$((t / 60))" "$((t % 60))"
        else
            printf '%dh%02dm\n' "$((t / 3600))" "$(((t % 3600) / 60))"
        fi
    }

    #===========================================================================
    # timeout wrapper (GNU timeout, or gtimeout from Homebrew coreutils)
    #===========================================================================
    RECON_TIMEOUT_CMD=""
    if have_cmd timeout; then
        RECON_TIMEOUT_CMD="timeout"
    elif have_cmd gtimeout; then
        RECON_TIMEOUT_CMD="gtimeout"
    fi

    #===========================================================================
    # Command runners (honor --dry-run, tee to the run log)
    #===========================================================================

    ###########################################################################
    # run
    # Purpose : Log an argv command line then execute it, unless dry-run.
    # Args    : the command and its arguments
    ###########################################################################
    function run() {
        local pretty="" a
        for a in "$@"; do
            case "${a}" in
                *[![:alnum:]/._=:@,-]*) pretty="${pretty} '${a}'" ;;
                *) pretty="${pretty} ${a}" ;;
            esac
        done
        LOG debug "\$${pretty}"
        [[ "${RECON_DRY_RUN:-0}" -eq 1 ]] && return 0
        # Mirror the tool's combined stdout+stderr to a per-tool tee file, so
        # every tool's output is saved even when the caller silences the
        # terminal with `> /dev/null 2>&1` (that only redirects tee's
        # passthrough; the file still captures every line).
        if [[ -n "${RECON_TEE_DIR:-}" ]]; then
            mkdir -p "${RECON_TEE_DIR}" 2> /dev/null || true
            local label="${1}"
            [[ "${label}" == "sudo" ]] && [[ $# -ge 2 ]] && label="${2}"
            "$@" 2>&1 | tee -a "$(recon_tee_file "${label}")"
            return "${PIPESTATUS[0]}"
        fi
        "$@"
    }

    ###########################################################################
    # recon_tee_file
    # Purpose : Path of a per-tool tee file: OUTPUT/TEE/<label>.<ts>.tee
    # Args    : $1 - label (usually the tool name)
    ###########################################################################
    function recon_tee_file() {
        local label
        label="$(basename -- "${1:-cmd}")"
        printf '%s/%s.%s.tee\n' "${RECON_TEE_DIR}" "${label}" "$(date +%Y%m%d_%H%M%S)"
    }

    ###########################################################################
    # run_pipe
    # Purpose : Log a string-form shell pipeline then eval it, unless dry-run.
    # Args    : $1 - pipeline string (already quoted by the caller)
    #           $2 - optional label for the tee file (defaults to "pipe")
    ###########################################################################
    function run_pipe() {
        LOG debug "\$ ${1}"
        [[ "${RECON_DRY_RUN:-0}" -eq 1 ]] && return 0
        if [[ -n "${RECON_TEE_DIR:-}" ]]; then
            mkdir -p "${RECON_TEE_DIR}" 2> /dev/null || true
            eval "${1}" 2>&1 | tee -a "$(recon_tee_file "${2:-pipe}")"
            return "${PIPESTATUS[0]}"
        fi
        eval "${1}"
    }

    #===========================================================================
    # Privilege priming
    #---------------------------------------------------------------------------
    # nmap SYN scans, spoonmap's masscan phase and ike-scan's UDP source-port
    # binding all need raw sockets. Elevation is primed once, up front, so an
    # expired sudo credential cannot stall an unattended run hours later.
    #===========================================================================
    RECON_ELEV="unprivileged"

    function recon_set_elevation() {
        if [[ "$(id -u)" -eq 0 ]]; then
            RECON_ELEV="root"
        elif [[ "${RECON_SUDO:-1}" -eq 1 ]] && have_cmd sudo; then
            RECON_ELEV="sudo"
        else
            RECON_ELEV="unprivileged"
        fi
    }

    function recon_prime_sudo() {
        [[ "${RECON_DRY_RUN:-0}" -eq 1 ]] && return 0
        recon_set_elevation
        [[ "${RECON_ELEV}" == "sudo" ]] || return 0
        if ! sudo -n true 2> /dev/null; then
            LOG info "priming sudo now so privileged phases cannot stall on a prompt later"
            sudo -v || {
                LOG error "sudo authentication failed - re-run with --no-sudo to skip elevation"
                return "${RECON_ERR_DEPS}"
            }
        fi
        return 0
    }

    #===========================================================================
    # Signal handling
    #---------------------------------------------------------------------------
    # Walk the descendant tree deepest-first so wrapped tools (gowitness ->
    # chrome, spoonmap -> masscan/nmap) do not survive a Ctrl-C.
    #===========================================================================
    function recon_kill_tree() {
        local sig="${1}" pid="${2}" child
        if have_cmd pgrep; then
            for child in $(pgrep -P "${pid}" 2> /dev/null || true); do
                recon_kill_tree "${sig}" "${child}"
            done
        fi
        if [[ "${pid}" != "$$" ]]; then
            kill "-${sig}" "${pid}" 2> /dev/null || true
        fi
    }

    function recon_kill_children() {
        local sig="${1:-TERM}"
        if have_cmd pgrep; then
            recon_kill_tree "${sig}" "$$"
        elif have_cmd pkill; then
            pkill "-${sig}" -P "$$" > /dev/null 2>&1 || true
        fi
    }

    function recon_on_interrupt() {
        printf '\n' >&2
        LOG warn "interrupted - terminating child processes"
        trap - INT TERM
        recon_kill_children TERM
        sleep 2
        recon_kill_children KILL
        recon_print_summary
        LOG error "run aborted by user"
        exit 130
    }

    #===========================================================================
    # Phase state / resume bookkeeping
    #===========================================================================
    RECON_SUMMARY=""    # newline-separated "phase|status|duration"
    RECON_FAILED=""     # space-separated failed phase names
    RECON_STAGE_NOTE="" # a phase sets this to explain "ran but did nothing"

    function recon_record() {
        RECON_SUMMARY="${RECON_SUMMARY}${1}|${2}|${3}"$'\n'
    }

    function recon_is_done() {
        [[ "${RECON_FORCE:-0}" -eq 0 ]] && [[ -f "${RECON_STATE_DIR}/${1}.done" ]]
    }

    function recon_mark_done() {
        [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && : > "${RECON_STATE_DIR}/${1}.done"
        return 0
    }

    function recon_print_summary() {
        [[ -z "${RECON_SUMMARY}" ]] && return 0
        LOG info "================ Recon Summary ================"
        printf '  %-14s %-24s %s\n' "PHASE" "STATUS" "TIME" >&2
        printf '  %-14s %-24s %s\n' "-----" "------" "----" >&2
        local s st d
        printf '%s' "${RECON_SUMMARY}" | while IFS='|' read -r s st d; do
            [[ -z "${s}" ]] && continue
            printf '  %-14s %-24s %s\n' "${s}" "${st}" "${d}" >&2
        done
        return 0
    }

    #===========================================================================
    # Domain-review gate
    #---------------------------------------------------------------------------
    # Candidate domains discovered from the IP scope are NEVER auto-enumerated.
    # The operator reviews them, copies the in-scope ones into domains.txt and
    # re-runs with --resume.
    #===========================================================================
    RECON_AWAITING_REVIEW=0

    function recon_print_review_gate() {
        local cand="${RECON_OUTDIR}/domains-candidates.txt"
        LOG warn "REVIEW REQUIRED - candidate domains are NOT yet in scope"
        printf '\n  %s candidate apex domain(s) discovered from the IP scope.\n\n' \
            "$(count_lines "${cand}")" >&2
        printf '    candidates : %s\n' "${cand}" >&2
        printf '    provenance : %s\n' "${RECON_OUTDIR}/discovery/provenance.tsv" >&2
        printf '\n  Review, keep only what you are authorized to enumerate, then:\n\n' >&2
        printf '    $ cp %s %s\n' "${cand}" "${DOMAINS_FILE}" >&2
        printf '    $ %s --resume %s\n\n' "${RECON_SELF:-run_recon.sh}" "${RECON_ENGAGEMENT_DIR}" >&2
        return 0
    }
fi
