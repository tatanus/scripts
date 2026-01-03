#!/usr/bin/env bash
###############################################################################
# auto-mount-shares.sh - Automated Share Discovery and Mounting
#==============================
# DESCRIPTION:
#   Uses NetExec (nxc) to discover SMB/CIFS shares with READ access on target
#   hosts, then automatically mounts all discovered shares using mount-try.sh.
#
#   The script:
#     1. Scans target(s) using nxc to identify shares with READ permissions
#     2. Logs output to a dated file: nxc.shares.<username>.<date>.tee
#     3. Parses the nxc output to extract share information
#     4. Automatically mounts each discovered share
#     5. Generates a summary report of all mounted shares
#
#   Supports scanning single IPs, FQDNs, CIDR ranges, or files containing
#   multiple targets.
#————————————————————
# Usage:
#   sudo ./auto-mount-shares.sh -t <target> -u <username> -p <password> \
#                               [-d <domain>] [-m <mount_base_dir>]
#
#   Options:
#     -t  Target: IP address, FQDN, CIDR range, or file with targets (required)
#     -u  Username for authentication (required)
#     -p  Password for authentication (required)
#     -d  Domain or workgroup (optional; defaults to WORKGROUP)
#     -m  Base directory for mount points (optional; defaults to ./mounts)
#     -s  Path to mount-try.sh script (optional; auto-detected)
#     -k  Keep existing mounts (don't skip already mounted shares)
#     -v  Verbose mode (show detailed output)
#     -h  Display this help message
#
# Return Values:
#   0  – All operations completed successfully
#   1  – Missing required arguments or general failure
#   2  – Invalid input or security validation failure
#   3  – Prerequisite check failed
#   4  – No shares discovered
#————————————————————
# Requirements:
#   • bash 4.0+
#   • NetExec (nxc) - https://github.com/Pennyw0rth/NetExec
#   • mount-try.sh script (in same directory or specified with -s)
#   • cifs-utils (for mounting)
#   • Root privileges (or appropriate sudo permissions)
#
# Examples:
#   # Scan single host
#   sudo ./auto-mount-shares.sh -t 192.168.1.100 -u admin -p 'Password123'
#
#   # Scan CIDR range with domain
#   sudo ./auto-mount-shares.sh -t 192.168.1.0/24 -u jdoe -p 'secret' -d CORP
#
#   # Scan from file
#   sudo ./auto-mount-shares.sh -t targets.txt -u admin -p 'Pass123' -v
#
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# Enable extended globbing for validation
shopt -s extglob

# Script version
VERSION="1.0.0"

# Default values
DOMAIN="WORKGROUP"
MOUNT_BASE="./mounts"
MOUNT_SCRIPT=""
KEEP_EXISTING=false
VERBOSE=false

# Credentials file (will be created securely)
CREDS_FILE=""

# Output files
OUTPUT_LOG=""
SUMMARY_FILE=""

# Statistics
TOTAL_HOSTS=0
TOTAL_SHARES=0
MOUNTED_SHARES=0
FAILED_MOUNTS=0
SKIPPED_SHARES=0

# Logging with timestamps
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_info() {
    log "[*] $*"
}

log_success() {
    log "[+] $*"
}

log_error() {
    log "[-] $*" >&2
}

log_warning() {
    log "[!] $*"
}

log_verbose() {
    if [[ "${VERBOSE}" == true ]]; then
        log "[V] $*"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ -n "${CREDS_FILE}" && -f "${CREDS_FILE}" ]]; then
        log_verbose "Cleaning up credentials file..."
        shred -u "${CREDS_FILE}" 2>/dev/null || rm -f "${CREDS_FILE}"
    fi
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

print_usage() {
    cat << EOF
auto-mount-shares.sh v${VERSION} - Automated Share Discovery and Mounting

Usage:
  sudo $0 -t <target> -u <username> -p <password> \\
           [-d <domain>] [-m <mount_base_dir>] [-s <mount_script>]

Options:
  -t  Target: IP address, FQDN, CIDR range, or file with targets (required)
  -u  Username for authentication (required)
  -p  Password for authentication (required)
  -d  Domain or workgroup (optional; defaults to WORKGROUP)
  -m  Base directory for mount points (optional; defaults to ./mounts)
  -s  Path to mount-try.sh script (optional; auto-detected)
  -k  Keep existing mounts (don't skip already mounted shares)
  -v  Verbose mode (show detailed output)
  -h  Display this help message

Examples:
  # Scan single host
  sudo $0 -t 192.168.1.100 -u admin -p 'Password123'

  # Scan CIDR range with domain
  sudo $0 -t 192.168.1.0/24 -u jdoe -p 'secret' -d CORP

  # Scan from file with custom mount directory
  sudo $0 -t targets.txt -u admin -p 'Pass123' -m /mnt/shares -v

Output Files:
  - nxc.shares.<username>.<date>.tee    : Raw NetExec output
  - mount-summary.<date>.txt            : Summary of mounted shares

Requirements:
  - NetExec (nxc) installed and in PATH
  - mount-try.sh script available
  - Root/sudo privileges
  - cifs-utils package
EOF
}

# Check prerequisites
check_prerequisites() {
    local missing_cmds=()

    # Check for nxc/netexec
    if ! command -v nxc &>/dev/null && ! command -v netexec &>/dev/null; then
        missing_cmds+=("nxc/netexec")
    fi

    for cmd in mount mountpoint tee; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing_cmds+=("${cmd}")
        fi
    done

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_cmds[*]}"
        log_error "Please install NetExec: https://github.com/Pennyw0rth/NetExec"
        return 3
    fi

    # Check if running as root
    if [[ ${EUID} -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        return 3
    fi

    # Find mount-try.sh if not specified
    if [[ -z "${MOUNT_SCRIPT}" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        # Check common locations
        local search_paths=(
            "${script_dir}/mount-try.sh"
            "./mount-try.sh"
            "/usr/local/bin/mount-try.sh"
            "${HOME}/bin/mount-try.sh"
        )

        for path in "${search_paths[@]}"; do
            if [[ -f "${path}" && -x "${path}" ]]; then
                MOUNT_SCRIPT="${path}"
                log_verbose "Found mount-try.sh at: ${MOUNT_SCRIPT}"
                break
            fi
        done

        if [[ -z "${MOUNT_SCRIPT}" ]]; then
            log_error "Could not find mount-try.sh. Please specify with -s option"
            return 3
        fi
    else
        if [[ ! -f "${MOUNT_SCRIPT}" ]]; then
            log_error "Mount script not found: ${MOUNT_SCRIPT}"
            return 3
        fi
        if [[ ! -x "${MOUNT_SCRIPT}" ]]; then
            log_error "Mount script not executable: ${MOUNT_SCRIPT}"
            return 3
        fi
    fi

    log_success "Prerequisites check passed"
    log_info "Using mount script: ${MOUNT_SCRIPT}"
    return 0
}

# Validate target input
validate_target() {
    local target="$1"

    # Check for null bytes
    if [[ "${target}" == *$'\0'* ]]; then
        log_error "Invalid target: contains null bytes"
        return 2
    fi

    # If it's a file, verify it exists and is readable
    if [[ -f "${target}" ]]; then
        if [[ ! -r "${target}" ]]; then
            log_error "Target file is not readable: ${target}"
            return 2
        fi
        log_verbose "Target is a file: ${target}"
        return 0
    fi

    # Validate IP address, CIDR, or hostname
    # Basic validation - nxc will do more thorough validation
    if [[ ! "${target}" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.\-\/]*$ ]]; then
        log_error "Invalid target format: ${target}"
        return 2
    fi

    return 0
}

# Validate username
validate_username() {
    local user="$1"

    if [[ "${user}" == *$'\0'* ]]; then
        log_error "Invalid username: contains null bytes"
        return 2
    fi

    if [[ ${#user} -gt 256 ]]; then
        log_error "Invalid username: exceeds maximum length"
        return 2
    fi

    if [[ -z "${user}" ]]; then
        log_error "Username cannot be empty"
        return 2
    fi

    return 0
}

# Validate password
validate_password() {
    local pass="$1"

    if [[ "${pass}" == *$'\0'* ]]; then
        log_error "Invalid password: contains null bytes"
        return 2
    fi

    if [[ ${#pass} -gt 256 ]]; then
        log_error "Invalid password: exceeds maximum length"
        return 2
    fi

    if [[ -z "${pass}" ]]; then
        log_warning "Warning: empty password provided"
    fi

    return 0
}

# Parse NetExec output to extract shares
parse_nxc_output() {
    local output_file="$1"
    local -n shares_array=$2

    log_info "Parsing NetExec output..."

    # NetExec output format (example):
    # SMB         192.168.1.100   445    DC01      [*] Windows Server 2019
    # SMB         192.168.1.100   445    DC01      Share           Permissions     Remark
    # SMB         192.168.1.100   445    DC01      -----           -----------     ------
    # SMB         192.168.1.100   445    DC01      ADMIN$                          Remote Admin
    # SMB         192.168.1.100   445    DC01      C$                              Default share
    # SMB         192.168.1.100   445    DC01      IPC$            READ            Remote IPC
    # SMB         192.168.1.100   445    DC01      NETLOGON        READ            Logon server share
    # SMB         192.168.1.100   445    DC01      SYSVOL          READ            Logon server share

    local current_host=""
    local in_shares_section=false

    while IFS= read -r line; do
        log_verbose "Parsing line: ${line}"

        # Extract hostname/IP from each line
        if [[ "${line}" =~ ^SMB[[:space:]]+([0-9\.]+|[a-zA-Z0-9\.\-]+)[[:space:]]+445 ]]; then
            current_host="${BASH_REMATCH[1]}"
        fi

        # Detect share listings section
        if [[ "${line}" =~ Share.*Permissions.*Remark ]]; then
            in_shares_section=true
            continue
        fi

        # Skip separator lines
        if [[ "${line}" =~ ^SMB.*-----.*----- ]]; then
            continue
        fi

        # Parse share lines with READ permission
        # Format: SMB  IP  PORT  HOSTNAME  SHARENAME  PERMISSIONS  REMARK
        # Note: SHARENAME may contain spaces, so we split the line and extract fields
        if [[ "${in_shares_section}" == true && "${line}" =~ READ ]]; then
            # Remove the SMB prefix and leading whitespace
            local fields_line="${line#SMB}"
            fields_line="${fields_line#"${fields_line%%[![:space:]]*}"}"

            # Now we have: IP PORT HOSTNAME SHARENAME... READ/WRITE REMARK
            # Split into array
            read -ra fields <<< "${fields_line}"

            # Validate we have at least 5 fields (IP, PORT, HOSTNAME, SHARE, PERMISSION)
            if [[ ${#fields[@]} -ge 5 ]]; then
                local host_ip="${fields[0]}"
                # Fields 3+ until we hit READ or WRITE are the share name
                local share_name=""
                local perm_index=-1

                for ((i=3; i<${#fields[@]}; i++)); do
                    if [[ "${fields[${i}]}" == "READ" || "${fields[${i}]}" == "WRITE" ]]; then
                        perm_index=${i}
                        break
                    fi
                    if [[ -n "${share_name}" ]]; then
                        share_name="${share_name} ${fields[${i}]}"
                    else
                        share_name="${fields[${i}]}"
                    fi
                done

                # Validate we found a permission marker
                if [[ ${perm_index} -gt 3 && -n "${share_name}" ]]; then
                    # Skip administrative shares (ending with $)
                    if [[ "${share_name}" == *'$' ]]; then
                        log_verbose "Skipping administrative share: ${share_name} on ${host_ip}"
                        continue
                    fi

                    if [[ -n "${host_ip}" && -n "${share_name}" ]]; then
                        shares_array+=("${host_ip}|${share_name}")
                        log_verbose "Found share: ${share_name} on ${host_ip}"
                    fi
                fi
            fi
        fi

        # Reset section flag on empty line or new host
        if [[ -z "${line}" || "${line}" =~ ^\[.*\] ]]; then
            in_shares_section=false
        fi

    done < "${output_file}"

    log_success "Found ${#shares_array[@]} readable shares (excluding admin shares)"
}

# Run NetExec to discover shares
discover_shares() {
    local target="$1"
    local user="$2"
    local pass="$3"
    local domain="$4"

    local date_str
    date_str="$(date '+%Y%m%d-%H%M%S')"

    # Sanitize username for filename
    local safe_user="${user//[^a-zA-Z0-9]/_}"

    OUTPUT_LOG="nxc.shares.${safe_user}.${date_str}.tee"

    log_info "Starting NetExec share enumeration..."
    log_info "Target: ${target}"
    log_info "Username: ${user}"
    log_info "Domain: ${domain}"
    log_info "Output will be saved to: ${OUTPUT_LOG}"

    # Determine nxc command (could be 'nxc' or 'netexec')
    local nxc_cmd="nxc"
    if ! command -v nxc &>/dev/null; then
        nxc_cmd="netexec"
    fi

    # Build nxc command
    local nxc_command=(
        "${nxc_cmd}"
        "smb"
        "${target}"
        "-u" "${user}"
        "-p" "${pass}"
        "-d" "${domain}"
        "--shares"
        "READ"
    )

    log_info "Running: ${nxc_command[*]} | tee -a ${OUTPUT_LOG}"
    echo

    # Run nxc and capture output
    if "${nxc_command[@]}" 2>&1 | tee -a "${OUTPUT_LOG}"; then
        echo
        log_success "NetExec scan completed"
        log_info "Full output saved to: ${OUTPUT_LOG}"
        return 0
    else
        local exit_code=$?
        echo
        log_warning "NetExec completed with exit code: ${exit_code}"
        log_info "This may be normal if some hosts are unreachable"
        return 0
    fi
}

# Mount a single share
mount_share() {
    local host="$1"
    local share="$2"
    local user="$3"
    local pass="$4"
    local domain="$5"
    local mount_base="$6"

    # Create sanitized mount point name
    local safe_host="${host//./_}"
    local safe_share="${share//[^a-zA-Z0-9]/_}"
    local mount_point="${mount_base}/${safe_host}/${safe_share}"

    # Handle mount point collisions
    if [[ -e "${mount_point}" ]] && ! mountpoint -q "${mount_point}" 2>/dev/null; then
        local counter=1
        local original_mount="${mount_point}"
        while [[ -e "${mount_point}" ]] && ! mountpoint -q "${mount_point}" 2>/dev/null; do
            mount_point="${original_mount}_${counter}"
            ((counter++))
            if [[ ${counter} -gt 100 ]]; then
                log_error "Too many mount point collisions for ${original_mount}"
                ((FAILED_MOUNTS++))
                return 1
            fi
        done
        log_info "Mount point collision detected. Using: ${mount_point}"
    fi

    log_info "Mounting: //${host}/${share} -> ${mount_point}"

    # Check if already mounted
    if mountpoint -q "${mount_point}" 2>/dev/null; then
        if [[ "${KEEP_EXISTING}" == false ]]; then
            log_warning "Already mounted: ${mount_point} (skipping)"
            ((SKIPPED_SHARES++))
            return 0
        else
            log_info "Already mounted but keep_existing is set: ${mount_point}"
        fi
    fi

    # Create mount point directory
    mkdir -p "${mount_point}" || {
        log_error "Failed to create mount point: ${mount_point}"
        ((FAILED_MOUNTS++))
        return 1
    }

    # Call mount-try.sh
    local mount_output
    mount_output=$("${MOUNT_SCRIPT}" -H "${host}" -S "${share}" -u "${user}" -p "${pass}" -d "${domain}" -m "${mount_point}" 2>&1)
    local mount_exit_code=$?

    # Log output if verbose
    if [[ "${VERBOSE}" == true && -n "${mount_output}" ]]; then
        while IFS= read -r line; do
            log_verbose "${line}"
        done <<< "${mount_output}"
    fi

    if [[ ${mount_exit_code} -eq 0 ]]; then
        log_success "Successfully mounted: //${host}/${share}"
        ((MOUNTED_SHARES++))

        # Add to summary using tab delimiter (safer than pipe for share names)
        printf '%s\t%s\t%s\t%s\t%s\n' "${host}" "${share}" "${mount_point}" "SUCCESS" "$(date '+%Y-%m-%d %H:%M:%S')" >> "${SUMMARY_FILE}"
        return 0
    else
        log_error "Failed to mount: //${host}/${share}"
        ((FAILED_MOUNTS++))

        # Add to summary using tab delimiter (safer than pipe for share names)
        printf '%s\t%s\t%s\t%s\t%s\n' "${host}" "${share}" "${mount_point}" "FAILED" "$(date '+%Y-%m-%d %H:%M:%S')" >> "${SUMMARY_FILE}"

        # Clean up failed mount point if empty
        if [[ -d "${mount_point}" ]]; then
            rmdir "${mount_point}" 2>/dev/null || true
        fi
        return 1
    fi
}

# Generate summary report
generate_summary() {
    log_info "Generating summary report..."

    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "                    MOUNT SUMMARY REPORT"
    echo "════════════════════════════════════════════════════════════════"
    echo
    echo "Scan Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Target: ${TARGET}"
    echo "Username: ${USER}"
    echo "Domain: ${DOMAIN}"
    echo
    echo "────────────────────────────────────────────────────────────────"
    echo "Statistics:"
    echo "────────────────────────────────────────────────────────────────"
    echo "  Total Shares Discovered : ${TOTAL_SHARES}"
    echo "  Successfully Mounted    : ${MOUNTED_SHARES}"
    echo "  Failed to Mount         : ${FAILED_MOUNTS}"
    echo "  Skipped (Already Mounted): ${SKIPPED_SHARES}"
    echo

    if [[ -f "${SUMMARY_FILE}" ]]; then
        echo "────────────────────────────────────────────────────────────────"
        echo "Mounted Shares:"
        echo "────────────────────────────────────────────────────────────────"
        printf "%-20s %-20s %-15s\n" "HOST" "SHARE" "MOUNT POINT"
        echo "────────────────────────────────────────────────────────────────"

        while IFS=$'\t' read -r host share mount_point status timestamp; do
            # Skip header/comment lines
            if [[ "${host}" == \#* ]]; then
                continue
            fi
            if [[ "${status}" == "SUCCESS" ]]; then
                printf "%-20s %-20s %-15s\n" "${host}" "${share}" "${mount_point}"
            fi
        done < "${SUMMARY_FILE}"
        echo
    fi

    if [[ ${FAILED_MOUNTS} -gt 0 ]]; then
        echo "────────────────────────────────────────────────────────────────"
        echo "Failed Mounts:"
        echo "────────────────────────────────────────────────────────────────"
        printf "%-20s %-20s\n" "HOST" "SHARE"
        echo "────────────────────────────────────────────────────────────────"

        while IFS=$'\t' read -r host share mount_point status timestamp; do
            # Skip header/comment lines
            if [[ "${host}" == \#* ]]; then
                continue
            fi
            if [[ "${status}" == "FAILED" ]]; then
                printf "%-20s %-20s\n" "${host}" "${share}"
            fi
        done < "${SUMMARY_FILE}"
        echo
    fi

    echo "════════════════════════════════════════════════════════════════"
    echo
    echo "Full details saved to: ${SUMMARY_FILE}"
    echo "NetExec output saved to: ${OUTPUT_LOG}"
    echo
}

# Main function
main() {
    log_info "auto-mount-shares.sh v${VERSION} starting..."

    # Validate inputs
    log_info "Validating input parameters..."
    validate_target "${TARGET}"
    validate_username "${USER}"
    validate_password "${PASS}"

    # Create base mount directory
    if [[ ! -d "${MOUNT_BASE}" ]]; then
        log_info "Creating base mount directory: ${MOUNT_BASE}"
        mkdir -p "${MOUNT_BASE}" || {
            log_error "Failed to create base mount directory: ${MOUNT_BASE}"
            exit 1
        }
    fi

    # Initialize summary file
    local date_str
    date_str="$(date '+%Y%m%d-%H%M%S')"
    SUMMARY_FILE="mount-summary.${date_str}.txt"

    # Write summary header
    cat > "${SUMMARY_FILE}" << EOF
# Mount Summary Report
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Target: ${TARGET}
# Username: ${USER}
# Domain: ${DOMAIN}
# Format: HOST<TAB>SHARE<TAB>MOUNT_POINT<TAB>STATUS<TAB>TIMESTAMP
EOF

    # Discover shares using NetExec
    discover_shares "${TARGET}" "${USER}" "${PASS}" "${DOMAIN}"
    local discover_result=$?
    if [[ ${discover_result} -ne 0 ]]; then
        log_error "Share discovery failed"
        exit 1
    fi

    # Parse NetExec output
    local discovered_shares=()
    parse_nxc_output "${OUTPUT_LOG}" discovered_shares

    TOTAL_SHARES=${#discovered_shares[@]}

    if [[ ${TOTAL_SHARES} -eq 0 ]]; then
        log_warning "No shares with READ access were discovered"
        exit 4
    fi

    log_success "Discovered ${TOTAL_SHARES} shares with READ access"
    echo

    # Mount each discovered share
    log_info "Starting automatic mounting of ${TOTAL_SHARES} shares..."
    echo

    for share_info in "${discovered_shares[@]}"; do
        IFS='|' read -r host share <<< "${share_info}"

        # Validate extracted values
        if [[ -z "${host}" || -z "${share}" ]]; then
            log_warning "Skipping invalid share entry: ${share_info}"
            continue
        fi

        # Check for null bytes or newlines (security validation)
        if [[ "${host}" == *$'\0'* || "${share}" == *$'\0'* ]]; then
            log_warning "Skipping share with null bytes: ${share_info}"
            continue
        fi

        if [[ "${host}" == *$'\n'* || "${share}" == *$'\n'* ]]; then
            log_warning "Skipping share with newlines: ${share_info}"
            continue
        fi

        mount_share "${host}" "${share}" "${USER}" "${PASS}" "${DOMAIN}" "${MOUNT_BASE}"
        echo
    done

    # Generate summary
    generate_summary

    # Exit with appropriate code
    if [[ ${MOUNTED_SHARES} -eq 0 ]]; then
        log_error "No shares were successfully mounted"
        exit 1
    fi

    log_success "Completed: ${MOUNTED_SHARES}/${TOTAL_SHARES} shares mounted successfully"
    exit 0
}

# Parse command-line options
while getopts ":t:u:p:d:m:s:kvh" opt; do
    case "${opt}" in
        t) TARGET="${OPTARG}" ;;
        u) USER="${OPTARG}" ;;
        p) PASS="${OPTARG}" ;;
        d) DOMAIN="${OPTARG}" ;;
        m) MOUNT_BASE="${OPTARG}" ;;
        s) MOUNT_SCRIPT="${OPTARG}" ;;
        k) KEEP_EXISTING=true ;;
        v) VERBOSE=true ;;
        h)
            print_usage
            exit 0
            ;;
        :)
            log_error "Option -${OPTARG} requires an argument"
            print_usage
            exit 1
            ;;
        *)
            log_error "Invalid option: -${OPTARG}"
            print_usage
            exit 1
            ;;
    esac
done

# Verify required arguments
if [[ -z "${TARGET:-}" ]] || [[ -z "${USER:-}" ]] || [[ ! -v PASS ]]; then
    log_error "Missing required arguments"
    print_usage
    exit 1
fi

# Check prerequisites
check_prerequisites

# Run main function
main
