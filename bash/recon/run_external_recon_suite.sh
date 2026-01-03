#!/usr/bin/env bash

###############################################################################
# NAME         : run_external_recon_suite.sh
# DESCRIPTION  : Modular external reconnaissance orchestrator
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-01-03
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|--------------------------------------------
# 2026-01-03 | Adam Compton | Initial creation - modular task-based design
###############################################################################

set -uo pipefail
IFS=$'\n\t'

#===============================================================================
# Constants & Globals
#===============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
readonly COMMON_CORE_LIB="${COMMON_CORE_LIB:-/Users/pentest/Desktop/DEV/new/common_core/lib}"

# Exit codes
readonly SUCCESS=0
readonly ERR_MISSING_DEPS=1
readonly ERR_INVALID_INPUT=2
readonly ERR_TASK_FAILED=3

# Task directories
readonly TASKS_DIR="${SCRIPT_DIR}/tasks"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"

#===============================================================================
# Source Dependencies
#===============================================================================

# Source common_core utilities
if [[ -f "${COMMON_CORE_LIB}/utils/logger.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_CORE_LIB}/utils/logger.sh"
fi

if [[ -f "${COMMON_CORE_LIB}/utils/util_cmd.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_CORE_LIB}/utils/util_cmd.sh"
fi

# Source local utilities (fallback logging if common_core not available)
if [[ -f "${SCRIPT_DIR}/common_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/common_utils.sh"
fi

# Initialize logger instance
if declare -F logger_init > /dev/null 2>&1; then
    logger_init "recon" "${ENGAGEMENT_DIR:-${HOME}}/recon_$(date +%Y%m%d_%H%M%S).log" "info" "true" "true"
    LOG() { logger_log "recon" "$@"; }
else
    # Fallback logging functions
    LOG() {
        local level="${1:-info}"
        shift
        case "${level}" in
            info)  info "$*" ;;
            warn)  warn "$*" ;;
            error|fail) fail "$*" ;;
            pass)  pass "$*" ;;
            debug) debug "$*" ;;
            *) echo "[$level] $*" >&2 ;;
        esac
    }
fi

#===============================================================================
# Configuration
#===============================================================================

# Task execution control
declare -gA TASK_ENABLED=(
    [00-validate]=true
    [01-osint]=true
    [02-nmap]=true
    [03-http-scan]=true
    [04-testssl]=true
)

declare -gA TASK_REQUIRED=(
    [00-validate]=true
    [01-osint]=false
    [02-nmap]=false
    [03-http-scan]=false
    [04-testssl]=false
)

# Task execution order (array maintains order)
declare -ga TASK_ORDER=(
    "00-validate"
    "01-osint"
    "02-nmap"
    "03-http-scan"
    "04-testssl"
)

#===============================================================================
# Helper Functions
#===============================================================================

###############################################################################
# print_banner
# Display script banner
###############################################################################
print_banner() {
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════════════════╗
║            External Reconnaissance Suite v1.0.0                            ║
║            Modular Penetration Testing Reconnaissance Framework            ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
}

###############################################################################
# print_usage
# Display usage information
###############################################################################
print_usage() {
    cat << EOF

Usage: ${0##*/} [OPTIONS]

Required Environment Variables:
  ENGAGEMENT_DIR      - Base directory for engagement outputs
  TARGETS_FILE        - Path to targets file (IPs, CIDRs, FQDNs)
  DOMAINS_FILE        - Path to domains file

Optional Environment Variables:
  RECON_PARALLEL      - Enable parallel task execution (default: false)
  RECON_VERBOSE       - Enable verbose output (default: false)
  RECON_DRY_RUN       - Dry run mode, don't execute tasks (default: false)

Options:
  -h, --help          Show this help message
  -v, --version       Show version information
  -c, --config FILE   Load configuration from FILE
  -t, --task TASK     Run specific task only (e.g., 01-osint)
  -s, --skip TASK     Skip specific task
  -l, --list          List available tasks
  -d, --dry-run       Dry run mode (don't execute)

Examples:
  # Run full reconnaissance suite
  export ENGAGEMENT_DIR=/path/to/engagement
  export TARGETS_FILE=\${ENGAGEMENT_DIR}/targets.txt
  export DOMAINS_FILE=\${ENGAGEMENT_DIR}/domains.txt
  ${0##*/}

  # Run specific task only
  ${0##*/} --task 02-nmap

  # Skip specific tasks
  ${0##*/} --skip 04-testssl

EOF
}

###############################################################################
# print_version
# Display version information
###############################################################################
print_version() {
    echo "External Reconnaissance Suite ${SCRIPT_VERSION}"
}

###############################################################################
# list_tasks
# List all available tasks
###############################################################################
list_tasks() {
    LOG info "Available reconnaissance tasks:"
    echo ""
    for task in "${TASK_ORDER[@]}"; do
        local task_file="${TASKS_DIR}/${task}.sh"
        local status="[MISSING]"
        local required=""

        if [[ -f "${task_file}" ]]; then
            status="[AVAILABLE]"
        fi

        if [[ "${TASK_ENABLED[${task}]:-false}" == "true" ]]; then
            status="${status} [ENABLED]"
        else
            status="${status} [DISABLED]"
        fi

        if [[ "${TASK_REQUIRED[${task}]:-false}" == "true" ]]; then
            required=" (REQUIRED)"
        fi

        printf "  %-20s %s%s\n" "${task}" "${status}" "${required}"
    done
    echo ""
}

###############################################################################
# validate_environment
# Validate required environment variables and paths
###############################################################################
validate_environment() {
    LOG info "Validating environment..."

    local errors=0

    # Check required environment variables
    if [[ -z "${ENGAGEMENT_DIR:-}" ]]; then
        LOG error "ENGAGEMENT_DIR is not set"
        ((errors++))
    elif [[ ! -d "${ENGAGEMENT_DIR}" ]]; then
        LOG warn "ENGAGEMENT_DIR does not exist, creating: ${ENGAGEMENT_DIR}"
        mkdir -p "${ENGAGEMENT_DIR}" || {
            LOG error "Failed to create ENGAGEMENT_DIR"
            ((errors++))
        }
    fi

    if [[ -z "${TARGETS_FILE:-}" ]]; then
        LOG error "TARGETS_FILE is not set"
        ((errors++))
    fi

    if [[ -z "${DOMAINS_FILE:-}" ]]; then
        LOG warn "DOMAINS_FILE is not set (optional for some tasks)"
    fi

    # Create required directories
    local -a required_dirs=(
        "${ENGAGEMENT_DIR}/RECON"
        "${ENGAGEMENT_DIR}/OUTPUT"
        "${ENGAGEMENT_DIR}/OUTPUT/TEE"
        "${ENGAGEMENT_DIR}/LOGS"
    )

    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "${dir}" ]]; then
            LOG info "Creating directory: ${dir}"
            mkdir -p "${dir}" || {
                LOG error "Failed to create directory: ${dir}"
                ((errors++))
            }
        fi
    done

    if ((errors > 0)); then
        LOG error "Environment validation failed with ${errors} error(s)"
        return "${ERR_INVALID_INPUT}"
    fi

    LOG pass "Environment validation successful"
    return "${SUCCESS}"
}

###############################################################################
# load_task
# Load a task script
# Arguments:
#   $1 - Task name (e.g., "01-osint")
###############################################################################
load_task() {
    local task_name="${1}"
    local task_file="${TASKS_DIR}/${task_name}.sh"

    if [[ ! -f "${task_file}" ]]; then
        LOG error "Task file not found: ${task_file}"
        return 1
    fi

    LOG debug "Loading task: ${task_name}"

    # Source the task script
    # shellcheck source=/dev/null
    source "${task_file}" || {
        LOG error "Failed to source task: ${task_name}"
        return 1
    }

    # Verify task function exists
    local task_function="run_task_${task_name//-/_}"
    if ! declare -F "${task_function}" > /dev/null 2>&1; then
        LOG error "Task function not found: ${task_function}"
        return 1
    fi

    return 0
}

###############################################################################
# execute_task
# Execute a single task
# Arguments:
#   $1 - Task name (e.g., "01-osint")
###############################################################################
execute_task() {
    local task_name="${1}"
    local task_function="run_task_${task_name//-/_}"
    local task_required="${TASK_REQUIRED[${task_name}]:-false}"

    LOG info "════════════════════════════════════════════════════════════════"
    LOG info "Executing task: ${task_name}"
    LOG info "════════════════════════════════════════════════════════════════"

    # Load task
    if ! load_task "${task_name}"; then
        if [[ "${task_required}" == "true" ]]; then
            LOG error "Failed to load required task: ${task_name}"
            return "${ERR_TASK_FAILED}"
        else
            LOG warn "Failed to load optional task: ${task_name}, skipping"
            return "${SUCCESS}"
        fi
    fi

    # Execute task function
    local start_time end_time duration
    start_time=$(date +%s)

    if [[ "${RECON_DRY_RUN:-false}" == "true" ]]; then
        LOG info "[DRY RUN] Would execute: ${task_function}"
        return "${SUCCESS}"
    fi

    # Execute with error handling
    if "${task_function}"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        LOG pass "Task completed successfully: ${task_name} (${duration}s)"
        return "${SUCCESS}"
    else
        local exit_code=$?
        end_time=$(date +%s)
        duration=$((end_time - start_time))

        if [[ "${task_required}" == "true" ]]; then
            LOG error "Required task failed: ${task_name} (exit: ${exit_code}, duration: ${duration}s)"
            return "${ERR_TASK_FAILED}"
        else
            LOG warn "Optional task failed: ${task_name} (exit: ${exit_code}, duration: ${duration}s)"
            return "${SUCCESS}"
        fi
    fi
}

###############################################################################
# run_reconnaissance_suite
# Main orchestration function
###############################################################################
run_reconnaissance_suite() {
    local start_time end_time total_duration
    start_time=$(date +%s)

    print_banner
    LOG info "Starting External Reconnaissance Suite"
    LOG info "Engagement Directory: ${ENGAGEMENT_DIR}"
    LOG info "Targets File: ${TARGETS_FILE}"
    LOG info "Domains File: ${DOMAINS_FILE:-N/A}"
    echo ""

    # Validate environment
    if ! validate_environment; then
        LOG error "Environment validation failed"
        return "${ERR_INVALID_INPUT}"
    fi

    echo ""

    # Execute tasks in order
    local task_count=0
    local task_success=0
    local task_failed=0
    local task_skipped=0

    for task in "${TASK_ORDER[@]}"; do
        ((task_count++))

        # Check if task is enabled
        if [[ "${TASK_ENABLED[${task}]:-false}" != "true" ]]; then
            LOG info "Skipping disabled task: ${task}"
            ((task_skipped++))
            echo ""
            continue
        fi

        # Execute task
        if execute_task "${task}"; then
            ((task_success++))
        else
            ((task_failed++))

            # Stop if required task fails
            if [[ "${TASK_REQUIRED[${task}]:-false}" == "true" ]]; then
                LOG error "Required task failed, stopping reconnaissance suite"
                break
            fi
        fi

        echo ""
    done

    # Summary
    end_time=$(date +%s)
    total_duration=$((end_time - start_time))

    LOG info "════════════════════════════════════════════════════════════════"
    LOG info "Reconnaissance Suite Summary"
    LOG info "════════════════════════════════════════════════════════════════"
    LOG info "Total Tasks:    ${task_count}"
    LOG info "Successful:     ${task_success}"
    LOG info "Failed:         ${task_failed}"
    LOG info "Skipped:        ${task_skipped}"
    LOG info "Total Duration: ${total_duration}s"
    LOG info "════════════════════════════════════════════════════════════════"

    if ((task_failed > 0)); then
        LOG warn "Reconnaissance completed with ${task_failed} failed task(s)"
        return "${ERR_TASK_FAILED}"
    fi

    LOG pass "Reconnaissance suite completed successfully"
    return "${SUCCESS}"
}

#===============================================================================
# Main Entry Point
#===============================================================================

main() {
    # Parse command line arguments
    local specific_task=""
    local skip_tasks=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--version)
                print_version
                exit 0
                ;;
            -l|--list)
                list_tasks
                exit 0
                ;;
            -t|--task)
                specific_task="${2:-}"
                shift 2
                ;;
            -s|--skip)
                skip_tasks+=("${2:-}")
                shift 2
                ;;
            -d|--dry-run)
                export RECON_DRY_RUN=true
                shift
                ;;
            -c|--config)
                local config_file="${2:-}"
                if [[ -f "${config_file}" ]]; then
                    # shellcheck source=/dev/null
                    source "${config_file}"
                else
                    echo "Error: Config file not found: ${config_file}" >&2
                    exit "${ERR_INVALID_INPUT}"
                fi
                shift 2
                ;;
            *)
                echo "Error: Unknown option: $1" >&2
                print_usage
                exit "${ERR_INVALID_INPUT}"
                ;;
        esac
    done

    # Handle specific task execution
    if [[ -n "${specific_task}" ]]; then
        # Disable all tasks except the specified one
        for task in "${!TASK_ENABLED[@]}"; do
            TASK_ENABLED[${task}]=false
        done
        TASK_ENABLED[${specific_task}]=true
    fi

    # Handle task skipping
    for task in "${skip_tasks[@]}"; do
        TASK_ENABLED[${task}]=false
    done

    # Run reconnaissance suite
    run_reconnaissance_suite
    exit $?
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
