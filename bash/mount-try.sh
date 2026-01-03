#!/usr/bin/env bash
###############################################################################
# mount-try2.sh - Enhanced Secure SMB/CIFS Mount Script
#==============================
# DESCRIPTION:
#   Attempts to mount a CIFS/SMB share by iterating through a list of SMB
#   protocol versions until one succeeds. Accepts server, share, username,
#   password, and domain via command-line options. Includes common options such as:
#     • security mode (sec)
#     • client‐side ownership (mount_uid, mount_gid)
#     • permission bits (file_mode, dir_mode)
#   Upon a successful mount, prints the exact mount command that worked, shows
#   the mount details, and then runs smbcacls (using the external binary) to
#   display the share's ACLs. If all tested versions fail, it reports failure
#   and exits with a nonzero code.
#
# SECURITY ENHANCEMENTS in v2:
#   • Password passed via credentials file (not command line/process list)
#   • Input validation and sanitization for all parameters
#   • Protection against path traversal attacks
#   • Secure file permissions on credentials file (600)
#   • Automatic cleanup of credentials file via trap
#   • Additional error checking and validation
#   • Null byte injection prevention
#   • Enhanced logging with timestamps
#————————————————————
# Usage:
#   sudo ./mount-try2.sh -H <server_ip_or_hostname> -S <share_name> \
#                        -u <username> -p <password> [-d <domain>] [-m <mountpoint>]
#
#   Options:
#     -H  Hostname or IP of the SMB/CIFS server (required)
#     -S  Share name on that server (required)
#     -u  Username for authentication (required)
#     -p  Password for authentication (required)
#     -d  Domain or workgroup (optional; defaults to WORKGROUP)
#     -m  Local mount point (optional; defaults to /mnt/cifs_share)
#     -h  Display this help message
#
# Return Values:
#   0  – Mounted successfully (and exits immediately after success), or
#        already mounted (no action taken)
#   1  – Missing required arguments or all tested SMB versions failed
#   2  – Invalid input or security validation failure
#   3  – Prerequisite check failed
#————————————————————
# Requirements:
#   • bash 4.0+
#   • cifs-utils (provides the mount.cifs helper)
#   • smbcacls (from Samba client utilities)
#   • Root privileges (or appropriate sudo permissions) to perform the mount
#
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# Enable extended globbing for validation
shopt -s extglob

# Default values for optional parameters
DOMAIN="WORKGROUP"
MPOINT="/mnt/cifs_share"
SEC="ntlmssp"

# Avoid collision with readonly UID/GID
MOUNT_UID="1000"
MOUNT_GID="1000"
FILE_MODE="0644"
DIR_MODE="0755"

# Credentials file (will be created securely)
CREDS_FILE=""

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

# Cleanup function to remove credentials file
cleanup() {
    local exit_code=$?
    if [[ -n "${CREDS_FILE}" && -f "${CREDS_FILE}" ]]; then
        log_info "Cleaning up credentials file..."
        shred -u "${CREDS_FILE}" 2>/dev/null || rm -f "${CREDS_FILE}"
    fi
    exit "${exit_code}"
}

# Set trap for cleanup on EXIT
trap cleanup EXIT INT TERM

print_usage() {
    cat << 'EOF'
Usage:
  sudo $0 -H <server_ip_or_hostname> -S <share_name> \
           -u <username> -p <password> [-d <domain>] [-m <mountpoint>]

Options:
  -H  Hostname or IP of the SMB/CIFS server (required)
  -S  Share name on that server (required)
  -u  Username for authentication (required)
  -p  Password for authentication (required)
  -d  Domain or workgroup (optional; defaults to WORKGROUP)
  -m  Local mount point (optional; defaults to /mnt/cifs_share)
  -h  Display this help message

Examples:
  # Mount with specific credentials
  sudo ./mount-try2.sh -H 192.168.1.100 -S shared -u admin -p 'Pa$$w0rd'

  # Mount with domain authentication
  sudo ./mount-try2.sh -H fileserver -S documents -u jdoe -p 'secret' -d CORP

Security Notes:
  - Password is securely stored in a temporary credentials file
  - Credentials file is automatically removed on script exit
  - All inputs are validated to prevent injection attacks
EOF
}

# Check for required commands
check_prerequisites() {
    local missing_cmds=()

    for cmd in mount mountpoint smbcacls; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing_cmds+=("${cmd}")
        fi
    done

    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_cmds[*]}"
        log_error "Please install the required packages (cifs-utils, samba-client)"
        return 3
    fi

    # Check if running as root
    if [[ ${EUID} -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        return 3
    fi

    return 0
}

# Validate hostname/IP address
validate_host() {
    local host="$1"

    # Check for null bytes
    if [[ "${host}" == *$'\0'* ]]; then
        log_error "Invalid host: contains null bytes"
        return 2
    fi

    # Check length
    if [[ ${#host} -gt 253 ]]; then
        log_error "Invalid host: exceeds maximum length"
        return 2
    fi

    # Allow valid hostname or IP (basic validation)
    if [[ ! "${host}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$ ]]; then
        log_error "Invalid host format: ${host}"
        return 2
    fi

    return 0
}

# Validate share name
validate_share() {
    local share="$1"

    # Check for null bytes
    if [[ "${share}" == *$'\0'* ]]; then
        log_error "Invalid share name: contains null bytes"
        return 2
    fi

    # Check length (SMB share names are limited to 80 characters)
    if [[ ${#share} -gt 80 ]]; then
        log_error "Invalid share name: exceeds maximum length"
        return 2
    fi

    # Disallow path separators and dangerous characters
    if [[ "${share}" == *"/"* || "${share}" == *"\\"* || "${share}" == *".."* ]]; then
        log_error "Invalid share name: contains path separators or '..'"
        return 2
    fi

    # Must not be empty
    if [[ -z "${share}" ]]; then
        log_error "Share name cannot be empty"
        return 2
    fi

    return 0
}

# Validate username
validate_username() {
    local user="$1"

    # Check for null bytes
    if [[ "${user}" == *$'\0'* ]]; then
        log_error "Invalid username: contains null bytes"
        return 2
    fi

    # Check length (reasonable limit)
    if [[ ${#user} -gt 256 ]]; then
        log_error "Invalid username: exceeds maximum length"
        return 2
    fi

    # Must not be empty
    if [[ -z "${user}" ]]; then
        log_error "Username cannot be empty"
        return 2
    fi

    return 0
}

# Validate password
validate_password() {
    local pass="$1"

    # Check for null bytes
    if [[ "${pass}" == *$'\0'* ]]; then
        log_error "Invalid password: contains null bytes"
        return 2
    fi

    # Check length (reasonable limit)
    if [[ ${#pass} -gt 256 ]]; then
        log_error "Invalid password: exceeds maximum length"
        return 2
    fi

    # Allow empty password (some shares allow it)
    # But warn about it
    if [[ -z "${pass}" ]]; then
        log_warning "Warning: empty password provided"
    fi

    return 0
}

# Validate domain
validate_domain() {
    local domain="$1"

    # Check for null bytes
    if [[ "${domain}" == *$'\0'* ]]; then
        log_error "Invalid domain: contains null bytes"
        return 2
    fi

    # Check length
    if [[ ${#domain} -gt 256 ]]; then
        log_error "Invalid domain: exceeds maximum length"
        return 2
    fi

    # Allow alphanumeric, dots, hyphens, underscores (more permissive)
    # Also allow single-label domains like "WORKGROUP"
    if [[ ! "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-\._]{0,254}[a-zA-Z0-9])?$ ]]; then
        log_error "Invalid domain format: ${domain}"
        return 2
    fi

    return 0
}

# Validate and sanitize mount point
validate_mountpoint() {
    local mpoint="$1"

    # Check for null bytes
    if [[ "${mpoint}" == *$'\0'* ]]; then
        log_error "Invalid mount point: contains null bytes"
        return 2
    fi

    # Resolve to absolute path to prevent path traversal
    local abs_path
    abs_path="$(readlink -m "${mpoint}" 2>/dev/null)" || {
        log_error "Invalid mount point path: ${mpoint}"
        return 2
    }

    # Prevent mounting to sensitive system directories
    local forbidden_paths=(
        "/"
        "/bin"
        "/boot"
        "/dev"
        "/etc"
        "/lib"
        "/lib64"
        "/proc"
        "/root"
        "/sbin"
        "/sys"
        "/usr"
        "/var"
    )

    for forbidden in "${forbidden_paths[@]}"; do
        if [[ "${abs_path}" == "${forbidden}" || "${abs_path}" == "${forbidden}/"* ]]; then
            log_error "Mount point in forbidden location: ${abs_path}"
            return 2
        fi
    done

    # Check path length
    if [[ ${#abs_path} -gt 4096 ]]; then
        log_error "Mount point path too long"
        return 2
    fi

    return 0
}

# Create secure credentials file
create_credentials_file() {
    local user="$1"
    local pass="$2"
    local domain="$3"

    # Create temporary file securely
    CREDS_FILE="$(mktemp /tmp/cifs_creds.XXXXXXXXXX)" || {
        log_error "Failed to create temporary credentials file"
        return 1
    }

    # Set restrictive permissions immediately
    chmod 600 "${CREDS_FILE}" || {
        log_error "Failed to set permissions on credentials file"
        return 1
    }

    # Write credentials using printf to safely handle special characters
    {
        printf 'username=%s\n' "${user}"
        printf 'password=%s\n' "${pass}"
        printf 'domain=%s\n' "${domain}"
    } > "${CREDS_FILE}"

    log_info "Created secure credentials file at ${CREDS_FILE}"
    return 0
}

# Parse command-line options
while getopts ":H:S:u:p:d:m:h" opt; do
    case "${opt}" in
        H) SERVER_HOST="${OPTARG}" ;;
        S) SHARE_NAME="${OPTARG}" ;;
        u) USER="${OPTARG}" ;;
        p) PASS="${OPTARG}" ;;
        d) DOMAIN="${OPTARG}" ;;
        m) MPOINT="${OPTARG}" ;;
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

# Check prerequisites first
check_prerequisites

# Verify required arguments are set
if [[ -z "${SERVER_HOST:-}" ]] || [[ -z "${SHARE_NAME:-}" ]] || \
   [[ -z "${USER:-}" ]] || [[ ! -v PASS ]]; then
    log_error "Missing required arguments."
    print_usage
    exit 1
fi

# Validate all inputs
log_info "Validating input parameters..."
validate_host "${SERVER_HOST}"
validate_share "${SHARE_NAME}"
validate_username "${USER}"
validate_password "${PASS}"
validate_domain "${DOMAIN}"
validate_mountpoint "${MPOINT}"

log_success "All input parameters validated successfully"

# Construct the UNC path (//server/share)
SERVER="//${SERVER_HOST}/${SHARE_NAME}"

# Generate sanitized mount point if not explicitly provided
if [[ -z "${MPOINT:-}" || "${MPOINT}" == "/mnt/cifs_share" ]]; then
    # Sanitize server IP by replacing dots with underscores
    SAFE_SERVER="${SERVER_HOST//./_}"

    # Sanitize share name: replace non-alphanumeric with underscores
    SAFE_SHARE="${SHARE_NAME//[^a-zA-Z0-9]/_}"

    MPOINT="./${SAFE_SERVER}-${SAFE_SHARE}"

    # Handle mount point collisions by adding counter if needed
    if [[ -e "${MPOINT}" ]] && ! mountpoint -q "${MPOINT}" 2>/dev/null; then
        MPOINT_COUNTER=1
        ORIGINAL_MPOINT="${MPOINT}"
        while [[ -e "${MPOINT}" ]] && ! mountpoint -q "${MPOINT}" 2>/dev/null; do
            MPOINT="${ORIGINAL_MPOINT}_${MPOINT_COUNTER}"
            ((MPOINT_COUNTER++))
            if [[ ${MPOINT_COUNTER} -gt 100 ]]; then
                log_error "Too many mount point collisions for ${ORIGINAL_MPOINT}"
                exit 1
            fi
        done
        log_info "Mount point collision detected. Using: '${MPOINT}'"
    else
        log_info "No mount point specified. Using generated mount point: '${MPOINT}'"
    fi
fi

# Ensure the mount directory exists
if [[ ! -d "${MPOINT}" ]]; then
    log_info "Creating mount point at '${MPOINT}'..."
    mkdir -p "${MPOINT}" || {
        log_error "Failed to create directory '${MPOINT}'. Aborting."
        exit 1
    }
    # Set secure permissions on the mount point
    chmod 755 "${MPOINT}"
fi

# Check if something is already mounted at the desired mount point
if mountpoint -q "${MPOINT}"; then
    log_info "Notice: '${MPOINT}' is already a mounted filesystem. No action taken."
    exit 0
fi

# Create secure credentials file
create_credentials_file "${USER}" "${PASS}" "${DOMAIN}"

# Common CIFS options (read‐only + credentials file + security + ownership + perms)
COMMON_OPTS="ro,credentials=${CREDS_FILE},sec=${SEC},uid=${MOUNT_UID},gid=${MOUNT_GID},file_mode=${FILE_MODE},dir_mode=${DIR_MODE}"

# List of SMB versions to try (in descending order of preference)
# SMB 3.1.1 added for better security
VERSIONS=(3.1.1 3.0 2.1 2.0 1.0)

log_info "Attempting to mount '${SERVER}' to '${MPOINT}' with various SMB versions..."

for VER in "${VERSIONS[@]}"; do
    log_info "Trying with vers=${VER}..."

    # Attempt mount with proper error handling
    mount_output=$(mount -t cifs "${SERVER}" "${MPOINT}" -o "${COMMON_OPTS},vers=${VER}" 2>&1)
    mount_exit_code=$?

    # Log mount output
    if [[ -n "${mount_output}" ]]; then
        while IFS= read -r line; do
            log_info "mount output: ${line}"
        done <<< "${mount_output}"
    fi

    if [[ ${mount_exit_code} -eq 0 ]]; then
        log_success "Success: mounted with vers=${VER}."
        echo
        log_success "Working mount command (with credentials file):"
        echo "    mount -t cifs '${SERVER}' '${MPOINT}' -o 'ro,credentials=<creds_file>,sec=${SEC},uid=${MOUNT_UID},gid=${MOUNT_GID},file_mode=${FILE_MODE},dir_mode=${DIR_MODE},vers=${VER}'"
        echo

        # Display mount information
        log_info "Mount information:"
        mount | grep "${MPOINT}"
        echo

        # Retrieve ACLs using smbcacls with credentials file
        log_success "Retrieving ACLs via smbcacls:"

        # Use credentials file for smbcacls (more secure - no password on command line)
        # Note: smbcacls supports --authentication-file in newer versions
        if command smbcacls -W "${DOMAIN}" --authentication-file="${CREDS_FILE}" "${SERVER}" "" 2>&1; then
            log_success "ACLs retrieved successfully"
        else
            # Fallback: Try without ACLs if authentication-file not supported
            log_warning "Failed to retrieve ACLs (may not be supported or normal for some shares)"
        fi

        echo
        log_success "Mount operation completed successfully"
        exit 0
    else
        log_warning "Failed with vers=${VER}. Trying next version..."
        echo
    fi
done

log_error "All tested SMB versions failed (tried: ${VERSIONS[*]})."
log_error "Please check:"
log_error "  - Network connectivity to ${SERVER_HOST}"
log_error "  - Share name '${SHARE_NAME}' exists"
log_error "  - Credentials are correct"
log_error "  - Firewall allows SMB traffic (ports 445, 139)"
exit 1
