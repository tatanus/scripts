#!/usr/bin/env bash

# =============================================================================
# NAME        : capture_traffic.sh
# DESCRIPTION : Capture bidirectional communication between two IPs and ports.
# AUTHOR      : Adam Compton
# DATE CREATED: 2024-12-08 19:57:22
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY    | DESCRIPTION OF CHANGE
# ---------------------|--------------|----------------------------------------
# 2024-12-08 19:57:22  | Adam Compton | Initial creation.
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# Guard to prevent multiple sourcing
if [[ -z "${CAPTURETRAFFIC_SH_LOADED:-}" ]]; then
    declare -g CAPTURETRAFFIC_SH_LOADED=true

    #==============================================================================
    # Global Variables
    #==============================================================================
    SCRIPT_NAME="$(basename "$0")"

    readonly DEFAULT_CAPTURE_TIME=10  # Default capture time in seconds
    readonly DEFAULT_MAX_MESSAGES=100 # Default maximum number of messages to capture
    readonly DEFAULT_INTERFACE="any"  # Default capture interface

    ###############################################################################
    # Logger bootstrap
    ###############################################################################
    function __script_dir() {
        # Resolve script's directory portably
        local src="${BASH_SOURCE[0]:-$0}"
        local dir
        dir="$(cd -- "$(dirname -- "${src}")" > /dev/null 2>&1 && pwd -P)" || dir="."
        printf '%s\n' "${dir}"
    }

    # Try to use safe_source.sh if present
    if [[ -r "$(__script_dir)/safe_source.sh" ]]; then
        # shellcheck source=/dev/null
        . "$(__script_dir)/safe_source.sh"
    fi

    # Source logger.sh from same directory if present
    if [[ -r "$(__script_dir)/logger.sh" ]]; then
        if command -v safe_source > /dev/null 2>&1; then
            safe_source "$(__script_dir)/logger.sh" || true
        else
            # shellcheck source=/dev/null
            . "$(__script_dir)/logger.sh"
        fi
    fi

    # Fallback logging if not provided by logger.sh
    if ! declare -f info > /dev/null; then
        function info()  { printf '[* INFO  ] %s\n' "${1}"; }
    fi

    if ! declare -f warn > /dev/null; then
        function warn()  { printf '[! WARN  ] %s\n' "${1}"; }
    fi

    if ! declare -f error > /dev/null; then
        function error() { printf '[- ERROR ] %s\n' "${1}"; }
    fi

    if ! declare -f pass > /dev/null; then
        function pass()  { printf '[+ PASS  ] %s\n' "${1}"; }
    fi

    if ! declare -f fail > /dev/null; then
        function fail()  { printf '[- ERROR ] %s\n' "${1}"; }
    fi

    if ! declare -f debug > /dev/null; then
        function debug() { printf '[# DEBUG ] %s\n' "${1}"; }
    fi

    #==============================================================================
    # Validation and Argument Parsing
    #==============================================================================

    ###############################################################################
    # validate_commands
    #==================
    # Ensure all required commands are available in the system.
    #
    # Globals:
    #   None
    #
    # Arguments:
    #   $@ - List of commands to check
    #
    # Outputs:
    #   Error message to stderr if any commands are missing
    #
    # Returns:
    #   Exits script with code 1 if any command is missing
    ###############################################################################
    function validate_commands() {
        local missing=0
        for cmd in "$@"; do
            if ! command -v "${cmd}" > /dev/null 2>&1; then
                error "Missing required command: ${cmd}"
                missing=1
            fi
        done
        ((missing == 0))   || die 1 "One or more required commands are missing."
    }

    ###############################################################################
    # parse_args
    #===========
    # Parses positional and optional arguments for capture parameters.
    #
    # Globals:
    #   SCRIPT_NAME
    #   DEFAULT_CAPTURE_TIME
    #   DEFAULT_MAX_MESSAGES
    #   DEFAULT_INTERFACE
    #   src_ip, dst_ip, src_port, dst_port, capture_time, max_messages, capture_interface
    #
    # Arguments:
    #   $@ - Positional and optional flags for IPs, ports, time, messages, interface
    #
    # Outputs:
    #   Help/usage text to stdout
    #
    # Returns:
    #   Exits on invalid input or unknown arguments
    ###############################################################################
    function parse_args() {
        if [[ "$#" -lt 4 ]]; then
            echo "Usage: ${SCRIPT_NAME} <src_ip> <dst_ip> <src_port> <dst_port> [-t <seconds>] [-m <messages>] [--interface <iface>]"
            exit 1
        fi

        src_ip="${1}"
        dst_ip="${2}"
        src_port="${3}"
        dst_port="${4}"
        capture_time="${DEFAULT_CAPTURE_TIME}"
        max_messages="${DEFAULT_MAX_MESSAGES}"
        capture_interface="${DEFAULT_INTERFACE}"
        shift 4

        while [[ "$#" -gt 0 ]]; do
            case "${1}" in
                -t | --time)
                    capture_time="${2}"
                    shift 2
                    ;;
                -m | --messages)
                    max_messages="${2}"
                    shift 2
                    ;;
                --interface)
                    capture_interface="${2}"
                    shift 2
                    ;;
                --help)
                    echo "Usage: ${SCRIPT_NAME} <src_ip> <dst_ip> <src_port> <dst_port> [-t <seconds>] [-m <messages>] [--interface <iface>]"
                    exit 0
                    ;;
                *)
                    die 1 "Unknown argument: ${1}"
                    ;;
            esac
        done
    }

    #==============================================================================
    # Capture Function
    #==============================================================================

    ###############################################################################
    # capture_traffic
    #================
    # Uses tshark to capture bidirectional TCP traffic between specified endpoints.
    #
    # Globals:
    #   src_ip, dst_ip, src_port, dst_port, capture_time, max_messages, capture_interface
    #
    # Arguments:
    #   $@ - All arguments passed to parse_args()
    #
    # Outputs:
    #   Packet summary to stdout
    #
    # Returns:
    #   0 on success, 1 if capture fails or tshark is not available
    ###############################################################################
    function capture_traffic() {
        local tshark_cmd
        tshark_cmd="$(command -v tshark || true)"
        if [[ -z "${tshark_cmd}" ]]; then
            die 1 "tshark is not installed or not found in PATH."
        fi

        parse_args "$@"

        info "Capturing traffic between ${src_ip}:${src_port} and ${dst_ip}:${dst_port} on interface ${capture_interface} for ${capture_time}s or ${max_messages} messages..."

        if ! "${tshark_cmd}" -i "${capture_interface}" \
            -a "duration:${capture_time}" \
            -c "${max_messages}" \
            -Y "(ip.src==${src_ip} && ip.dst==${dst_ip} && tcp.srcport==${src_port} && tcp.dstport==${dst_port}) || (ip.src==${dst_ip} && ip.dst==${src_ip} && tcp.srcport==${dst_port} && tcp.dstport==${src_port})" \
            -T fields -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e text 2> /dev/null | awk '
            BEGIN { OFS = ""; print "Timestamp\tSource\t\tDestination\t\tPayload" }
            {
                timestamp = $1 " " $2
                src = $3 ":" $4
                dst = $5 ":" $6
                payload = ($7 == "") ? "[No payload or binary data]" : substr($0, index($0,$7))
                print "[" timestamp "]\t" src " -> " dst ":\t" payload
            }'; then
            fail "Failed to capture traffic or no packets matched."
            return 1
        fi

        pass "Traffic capture completed successfully."
    }
fi
