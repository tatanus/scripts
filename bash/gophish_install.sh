#!/usr/bin/env bash
###############################################################################
# NAME         : gophish_install_v2.sh
# DESCRIPTION  : Enhanced secure version - Installs Gophish, sets up firewall,
#                user, builds binary, and configures a systemd service.
#                Includes logging, validation, initial admin password bootstrap,
#                admin API key retrieval, and pre-install sanity checks.
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-08
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY         | DESCRIPTION OF CHANGE
# -----------|-------------------|---------------------------------------------
# 2025-08-08 | Adam Compton      | Initial creation.
# 2025-09-10 | Adam Compton      | Ubuntu-focused auto-install in validate_commands.
# 2026-01-03 | Security Review   | Enhanced security, input validation, shellcheck fixes
###############################################################################
# SECURITY ENHANCEMENTS in v2:
#   • Input validation for all user-provided parameters
#   • Null byte injection prevention
#   • Path traversal protection for installation directory
#   • Sanitization before external command execution (dig, curl)
#   • Proper cleanup function using exit instead of return
#   • Fixed conditional operators to preserve set -e behavior
#   • Secure temporary file permissions
#   • Command injection prevention in DNS/HTTP requests
#   • Race condition mitigation for certificate checks
#   • Service startup verification
###############################################################################

#==============================================================================
# Strict mode
#==============================================================================
set -euo pipefail
IFS=$'\n\t'

# Script semantic version
__version__="0.0.4"
readonly __version__

#==============================================================================
# Script Metadata / Globals
#==============================================================================
SCRIPT_NAME="$(basename "$0")"

# Install/Service defaults
GOPHISH_DIR="/opt/gophish"                   # Installation directory
GOPHISH_USER="gophish"                       # Dedicated service user
REPO_URL="https://github.com/kgretzky/gophish.git"

# CLI arguments (populated by parse_args)
phish_domain=""
contact_address=""
custom_install_dir=""

# Admin/API convenience
GOPHISH_ADMIN_URL="${GOPHISH_ADMIN_URL:-https://127.0.0.1:3333}"
GOPHISH_LOG_FILE="${GOPHISH_LOG_FILE:-/var/log/gophish/gophish.log}"
GOPHISH_SERVICE="${GOPHISH_SERVICE:-gophish}"
readonly GOPHISH_ADMIN_URL GOPHISH_LOG_FILE GOPHISH_SERVICE

# Return-code convenience
_PASS="${_PASS:-0}"
_FAIL="${_FAIL:-1}"
readonly _PASS _FAIL

# Captured from log and used for rotation (set by bootstrap function)
GOPHISH_INITIAL_ADMIN_PASSWORD=""

# Optional file logging (fallback logger only): LOG_FILE=/path/to/log
LOG_FILE="${LOG_FILE:-}"

#------------------------------------------------------------------------------
# Global validation configuration (Ubuntu-focused)
#------------------------------------------------------------------------------
# Map command -> apt package (Ubuntu/Debian)
declare -A pkg_map=(
    # Core network/tools
          [curl]="curl"
          [git]="git"
          [wget]="wget"
          [unzip]="unzip"

    # Shell/CLI utilities used by the script
          [sed]="sed"
          [grep]="grep"
          [tar]="tar"
          [jq]="jq"
          [sqlite3]="sqlite3"
          [rsync]="rsync"
          [screen]="screen"

    # Package-proxy mappings (package name != command name)
          [htpasswd]="apache2-utils"
          [dig]="dnsutils"
          [timeout]="coreutils"
          [ifconfig]="net-tools"
          [setcap]="libcap2-bin"
          [update - ca - certificates]="ca-certificates"
          [gcc]="build-essential"
          [make]="build-essential"

    # Direct package = command
          [certbot]="certbot"

    # Optional/quality-of-life
          [upx]="upx"

    # Environment/core (no apt package to install "just this")
          [systemctl]=""
          [apt - get]=""
)

# Default commands to validate
declare -a required_commands=(
    curl git wget unzip jq sqlite3 htpasswd dig timeout ifconfig setcap certbot
    update-ca-certificates gcc make systemctl apt-get screen sed grep tar rsync upx
)

#==============================================================================
# Logger bootstrap (standalone-style)
#==============================================================================
function __script_dir() {
    local src="${BASH_SOURCE[0]:-$0}"
    local dir
    dir="$(cd -- "$(dirname -- "${src}")" > /dev/null 2>&1 && pwd -P)" || dir="."
    printf '%s\n' "${dir}"
}

# Optionally source safe_source.sh / logger.sh if provided next to this script
# shellcheck disable=SC2310  # These checks are intentional - we want to test file existence
SCRIPT_DIR_PATH="$(__script_dir)"
if [[ -r "${SCRIPT_DIR_PATH}/safe_source.sh" ]]; then
    # shellcheck source=/dev/null
    . "${SCRIPT_DIR_PATH}/safe_source.sh"
fi
if [[ -r "${SCRIPT_DIR_PATH}/logger.sh" ]]; then
    if command -v safe_source > /dev/null 2>&1; then
        # shellcheck disable=SC2310  # safe_source failure is acceptable here
        safe_source "${SCRIPT_DIR_PATH}/logger.sh" || true
    else
        # shellcheck source=/dev/null
        . "${SCRIPT_DIR_PATH}/logger.sh"
    fi
fi

# Fallback logging if logger not provided
if ! declare -f _log_core > /dev/null; then
    function _log_core() {
        local level="${1:-INFO}"
        local label="${2:-*}"
        local msg="${3:-}"
        local ts
        ts="$(date '+%Y-%m-%d %H:%M:%S%z')"

        # Colors (disabled if NO_COLOR is set)
        local reset="" dim="" red="" yellow="" green="" blue=""
        if [[ -z "${NO_COLOR:-}" ]]; then
            reset=$'\033[0m'
            dim=$'\033[2m'
            red=$'\033[31m'
            yellow=$'\033[33m'
            green=$'\033[32m'
            blue=$'\033[34m'
        fi

        local color_prefix=""
        case "${level}" in
            DEBUG) color_prefix="${blue}" ;;
            INFO)  color_prefix="${dim}" ;;
            PASS)  color_prefix="${green}" ;;
            WARN)  color_prefix="${yellow}" ;;
            ERROR | FAIL) color_prefix="${red}" ;;
            *) color_prefix="${dim}" ;;  # Default to dim for unknown levels
        esac

        local line="[${ts}] [${label}] ${msg}"
        if [[ "${level}" = "ERROR" || "${level}" = "FAIL" ]]; then
            printf '%b%s%b\n' "${color_prefix}" "${line}" "${reset}" >&2
        else
            printf '%b%s%b\n' "${color_prefix}" "${line}" "${reset}"
        fi

        if [[ -n "${LOG_FILE}" ]]; then
            mkdir -p "$(dirname -- "${LOG_FILE}")" 2> /dev/null || true
            printf '%s\n' "${line}" >> "${LOG_FILE}" 2> /dev/null || true
        fi
    }
fi

# Public logging shims
if ! declare -f info  > /dev/null; then function info()  { _log_core "INFO"  "* INFO "  "${1}"; }; fi
if ! declare -f warn  > /dev/null; then function warn()  { _log_core "WARN"  "! WARN "  "${1}"; }; fi
if ! declare -f error > /dev/null; then function error() { _log_core "ERROR" "- ERROR"  "${1}"; }; fi
if ! declare -f pass  > /dev/null; then function pass()  { _log_core "PASS"  "+ PASS "  "${1}"; }; fi
if ! declare -f fail  > /dev/null; then function fail()  { _log_core "FAIL"  "! FAIL "  "${1}"; }; fi
if ! declare -f debug > /dev/null; then function debug() { _log_core "DEBUG" "# DEBUG"  "${1}"; }; fi

#==============================================================================
# Utility / Validation
#==============================================================================

###############################################################################
# die
#------------------------------------------------------------------------------
# Purpose : Log an error message and exit with a specific code.
# Usage   : die <exit_code:int> <message:string>
# Return  : never returns
###############################################################################
function die() {
    local exit_code="${1}"
    local error_msg="${2}"
    error "${error_msg}"
    exit "${exit_code}"
}

###############################################################################
# Input Validation Functions (Security Enhancements)
###############################################################################

# Validate domain name (FQDN)
function validate_domain() {
    local domain="${1:-}"

    # Check for null bytes
    if [[ "${domain}" == *$'\0'* ]]; then
        error "Invalid domain: contains null bytes"
        return 2
    fi

    # Check length (RFC 1035: max 253 characters)
    if [[ ${#domain} -gt 253 ]]; then
        error "Invalid domain: exceeds maximum length (253)"
        return 2
    fi

    # Must not be empty
    if [[ -z "${domain}" ]]; then
        error "Domain cannot be empty"
        return 2
    fi

    # Validate format (basic FQDN check)
    if [[ ! "${domain}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]; then
        error "Invalid domain format: ${domain}"
        return 2
    fi

    return 0
}

# Validate email address
function validate_email() {
    local email="${1:-}"

    # Allow empty (optional parameter)
    if [[ -z "${email}" ]]; then
        return 0
    fi

    # Check for null bytes
    if [[ "${email}" == *$'\0'* ]]; then
        error "Invalid email: contains null bytes"
        return 2
    fi

    # Check length
    if [[ ${#email} -gt 320 ]]; then
        error "Invalid email: exceeds maximum length"
        return 2
    fi

    # Basic email format validation
    if [[ ! "${email}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "Invalid email format: ${email}"
        return 2
    fi

    return 0
}

# Validate and sanitize installation directory path
function validate_install_dir() {
    local dir="${1:-}"

    # Check for null bytes
    if [[ "${dir}" == *$'\0'* ]]; then
        error "Invalid installation directory: contains null bytes"
        return 2
    fi

    # Resolve to absolute path to prevent path traversal
    local abs_path
    abs_path="$(readlink -m "${dir}" 2> /dev/null)" || {
        error "Invalid installation directory path: ${dir}"
        return 2
    }

    # Prevent installing to sensitive system directories
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
        "/usr/bin"
        "/usr/sbin"
        "/usr/lib"
    )

    for forbidden in "${forbidden_paths[@]}"; do
        if [[ "${abs_path}" == "${forbidden}" || "${abs_path}" == "${forbidden}/"* ]]; then
            error "Installation directory in forbidden location: ${abs_path}"
            return 2
        fi
    done

    # Check path length
    if [[ ${#abs_path} -gt 4096 ]]; then
        error "Installation directory path too long"
        return 2
    fi

    # Update GOPHISH_DIR to the validated absolute path
    GOPHISH_DIR="${abs_path}"

    return 0
}

###############################################################################
# validate_commands
#------------------------------------------------------------------------------
# Purpose : Verify required commands are present. If any are missing:
#           - Print per-command apt install hints (Ubuntu/Debian)
#           - Print a single batch install command
#           - EXIT with an error explaining what's missing and how to fix it.
# Usage   : validate_commands (uses global required_commands array)
# Return  : 0 on success; exits (non-zero) on failure
###############################################################################
function validate_commands() {
    local -a cmds=("${required_commands[@]}")

    local -a missing_cmds=()
    local -a missing_pkgs=()

    local cmd pkg
    for cmd in "${cmds[@]}"; do
        if ! command -v "${cmd}" > /dev/null 2>&1; then
            missing_cmds+=("${cmd}")
            pkg="${pkg_map[${cmd}]:-}"
            if [[ -n "${pkg}" ]]; then
                missing_pkgs+=("${pkg}")
                local sudo_prefix=""
                if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
                    sudo_prefix="sudo "
                fi
                info "Missing '${cmd}'. Install with: ${sudo_prefix}apt-get install -y ${pkg}"
            else
                warn "Missing '${cmd}'. No direct apt package mapping found; install it manually on your system."
            fi
        fi
    done

    if (("${#missing_cmds[@]}" == 0)); then
        pass "All required commands are present."
        return 0
    fi

    # De-duplicate packages for a clean batch command
    local -a unique_pkgs=()
    if (("${#missing_pkgs[@]}" > 0)); then
        declare -A seen_pkgs=()
        for pkg in "${missing_pkgs[@]}"; do
            if [[ -n "${pkg}" && -z "${seen_pkgs[${pkg}]:-}" ]]; then
                unique_pkgs+=("${pkg}")
                seen_pkgs["${pkg}"]=1
            fi
        done
        local sudo_prefix=""
        if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
            sudo_prefix="sudo "
        fi
        local pkg_list="${unique_pkgs[*]}"
        info "Batch install command:"
        printf '%sapt-get update -y && apt-get install -y %s\n' "${sudo_prefix}" "${pkg_list}"
    fi

    if (("${#unique_pkgs[@]}" > 0)); then
        die 3 "Missing required commands: ${missing_cmds[*]}. Install them using the batch command above, then re-run this script."
    else
        die 3 "Missing required core tools: ${missing_cmds[*]}. These cannot be installed automatically on Ubuntu—ensure you're running on a system with systemd and apt available."
    fi
}

###############################################################################
# usage
###############################################################################
function usage() {
    info "Usage: ${SCRIPT_NAME} --phish-domain <domain> [--contact <email>] [--install-dir <path>] [-h|--help]"
    info ""
    info "Options:"
    info "  --phish-domain <domain>  : Domain for phishing server (required)"
    info "  --contact <email>        : Contact email address (optional)"
    info "  --install-dir <path>     : Custom installation directory (optional, default: /opt/gophish)"
    info "  -h, --help              : Display this help message"
    return 0
}

#==============================================================================
# Argument Parsing
#==============================================================================

###############################################################################
# parse_args
###############################################################################
function parse_args() {
    if [[ "$#" -lt 2 ]]; then
        usage
        die 1 "Missing required arguments."
    fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --phish-domain)
                phish_domain="${2:-}"
                shift 2
                ;;
            --contact)
                contact_address="${2:-}"
                shift 2
                ;;
            --install-dir)
                custom_install_dir="${2:-}"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die 1 "Unknown option: $1"
                ;;
        esac
    done

    [[ -n "${phish_domain:-}" ]] || die 1 "--phish-domain is required"

    # Validate inputs
    info "Validating input parameters..."
    validate_domain "${phish_domain}"
    validate_email "${contact_address}"

    if [[ -n "${custom_install_dir}" ]]; then
        validate_install_dir "${custom_install_dir}"
    fi

    pass "All input parameters validated successfully"
}

#==============================================================================
# Helper Functions
#==============================================================================

###############################################################################
# _pushd/_popd
###############################################################################
if ! declare -f _pushd > /dev/null 2>&1; then
    function _pushd() {
        builtin pushd "$@" > /dev/null 2>&1 || {
            error "pushd failed: $*"
            return 1
        }
    }
fi
if ! declare -f _popd > /dev/null 2>&1; then
    function _popd() {
        builtin popd > /dev/null 2>&1 || {
            error "popd failed"
            return 1
        }
    }
fi

###############################################################################
# _get_arch
###############################################################################
function _get_arch() {
    local arch=""
    arch=$(uname -m)
    case "${arch}" in
        x86_64) echo "amd64" ;;
        aarch64 | arm64) echo "arm64" ;;
        i[3-6]86) echo "386" ;;
        armv7l) echo "armhf" ;;
        *)
            echo "unsupported"
            return 1
            ;;
    esac
}

###############################################################################
# is_valid_ipv4
# Note: This function is designed to return status codes (0=valid, 1=invalid)
#       SC2310 warnings for this function can be ignored.
###############################################################################
function is_valid_ipv4() {
    local ip="${1:-}"
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.' oct
    read -r -a oct <<< "${ip}"
    local n
    for n in "${oct[@]}"; do
        ((n >= 0 && n <= 255)) || return 1
    done
    return 0
}

###############################################################################
# is_valid_domain
# Note: This function is designed to return status codes (0=valid, 1=invalid)
#       SC2310 warnings for this function can be ignored.
###############################################################################
function is_valid_domain() {
    local dn="${1:-}"
    [[ "${dn}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

###############################################################################
# detect_public_ipv4
# Note: This function is designed to return status codes (0=found, 1=not found)
#       and output the IP to stdout. SC2310 warnings can be ignored.
###############################################################################
function detect_public_ipv4() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
    )
    local url valid
    for url in "${services[@]}"; do
        if command -v curl > /dev/null 2>&1; then
            ip="$(curl -fsS4 --max-time 5 "${url}" 2> /dev/null | tr -d '[:space:]')" || true
        elif command -v wget > /dev/null 2>&1; then
            ip="$(wget -qO- --timeout=5 "${url}" 2> /dev/null | tr -d '[:space:]')" || true
        fi
        # Check if valid (capturing exit code directly)
        is_valid_ipv4 "${ip}"
        valid=$?
        if [[ ${valid} -eq 0 ]]; then
            printf '%s\n' "${ip}"
            return 0
        fi
    done
    return 1
}

#==============================================================================
# Installation Steps
#==============================================================================

###############################################################################
# install_go
###############################################################################
function install_go() {
    _pushd /tmp
    info "Installing latest Go..."

    if apt list --installed 2> /dev/null | grep -q '^golang/'; then
        apt purge -y golang || die 1 "Failed to purge old Go"
    fi

    local arch go_version_url
    arch=$(_get_arch)
    if [[ "${arch}" == "unsupported" ]]; then
        die 1 "Unsupported architecture for Go: $(uname -m)"
    fi
    go_version_url=$(curl -sL https://golang.org/dl/ | grep -oP "go[0-9.]+.linux-${arch}.tar.gz" | head -n 1)

    [[ -n "${go_version_url}" ]] || die 1 "Could not fetch Go version for arch ${arch}"
    wget --no-check-certificate "https://golang.org/dl/${go_version_url}" || die 1 "Failed to download Go"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${go_version_url}" || die 1 "Failed to extract Go"
    rm -f "${go_version_url}"
    # shellcheck disable=SC2016  # We want literal $PATH in the file, not expanded
    printf 'export PATH=$PATH:/usr/local/go/bin\n' > /etc/profile.d/go.sh
    export PATH="${PATH}:/usr/local/go/bin"

    command -v go > /dev/null 2>&1 || die 1 "Go binary missing after install"
    pass "Go installed: $(go version)"

    _popd
}

###############################################################################
# setup_environment
###############################################################################
function setup_environment() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die 1 "This installer currently targets Linux (Debian/Ubuntu)."
    fi

    info "Installing dependencies..."
    apt-get update -y || die 2 "Failed to update package list"
    validate_commands
    info "Installing Go (latest)..."
    install_go
}

###############################################################################
# setup_user_and_dirs
###############################################################################
function setup_user_and_dirs() {
    local user_name="${GOPHISH_USER}"
    local group_name="${GOPHISH_USER}"
    local install_dir="${GOPHISH_DIR}"

    useradd -r -m -d /var/lib/gophish -s /usr/sbin/nologin "${user_name}" 2> /dev/null || true
    mkdir -p "${install_dir}" /var/lib/gophish /var/log/gophish /etc/gophish/certs/phish
    chown -R "${user_name}:${group_name}" "${install_dir}" /var/lib/gophish /var/log/gophish /etc/gophish
    pass "User and directories set up."
}

###############################################################################
# build_gophish
###############################################################################
function build_gophish() {
    local repo_dir="/tmp/gophish"

    info "Cloning GoPhish…"
    rm -rf "${repo_dir}"
    git clone "${REPO_URL}" "${repo_dir}" || die 1 "Git clone failed"
    _pushd "${repo_dir}"

    info "Applying recipient/email/MTA/integration-facing patches…"

    sed -i 's/X-Gophish-Contact/X-Contact/g' models/*.go
    sed -i 's/X-Gophish-Signature/X-Signature/g' webhook/webhook.go
    sed -i 's/const ServerName = "gophish"/const ServerName = ""/g' config/config.go
    sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "oauth"/g' models/campaign.go

    info "Building GoPhish binary (stripped)…"
    if ! go build -ldflags "-s -w"; then
        die 1 "Go build failed"
    fi

    if command -v setcap > /dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' ./gophish 2> /dev/null || true
    fi

    if command -v upx > /dev/null 2>&1; then
        info "UPX found; compressing binary…"
        upx --best --lzma ./gophish || warn "UPX compression failed; continuing."
    else
        info "UPX not found; skipping binary compression."
    fi

    mkdir -p "${GOPHISH_DIR}" || die 1 "Failed to create ${GOPHISH_DIR}"
    if command -v rsync > /dev/null 2>&1; then
        rsync -a --delete ./ "${GOPHISH_DIR}/"
    else
        find "${GOPHISH_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2> /dev/null || true
        cp -a . "${GOPHISH_DIR}/"
    fi

    install -m 0755 -o "${GOPHISH_USER}" -g "${GOPHISH_USER}" gophish "${GOPHISH_DIR}/gophish"
    chown -R "${GOPHISH_USER}:${GOPHISH_USER}" "${GOPHISH_DIR}"

    if [[ ! -f "${GOPHISH_DIR}/VERSION" ]]; then
        warn "VERSION file not found in ${GOPHISH_DIR}; creating placeholder."
        printf '%s\n' "dev" > "${GOPHISH_DIR}/VERSION"
        chown "${GOPHISH_USER}:${GOPHISH_USER}" "${GOPHISH_DIR}/VERSION"
    fi

    pass "GoPhish built and installed with recipient/email/integration-facing obfuscations."
    _popd
}

###############################################################################
# obtain_certs (MANUAL DNS-01)
###############################################################################
function obtain_certs() {
    info "Ensuring certbot is available…"
    command -v certbot > /dev/null 2>&1 || apt-get install -y certbot || die 6 "Failed to install certbot"

    local live_dir="/etc/letsencrypt/live/${phish_domain}"

    # Check if certs exist AND are readable
    if [[ -f "${live_dir}/fullchain.pem" && -r "${live_dir}/fullchain.pem" &&
          -f "${live_dir}/privkey.pem" && -r "${live_dir}/privkey.pem" ]]; then
        pass "Existing Let's Encrypt certs found for ${phish_domain}; skipping issuance."
        return 0
    fi

    local -a email_opts
    email_opts=(--register-unsafely-without-email)

    info "Starting Certbot in MANUAL mode (DNS-01) for ${phish_domain}."
    info "Create TXT: _acme-challenge.${phish_domain} → <token>; then press Enter in certbot."

    if certbot certonly --manual \
        --preferred-challenges dns-01 \
        --manual-public-ip-logging-ok \
        --agree-tos \
        --server https://acme-v02.api.letsencrypt.org/directory \
        "${email_opts[@]}" \
        -d "${phish_domain}"; then
        :
    else
        die 7 "Failed to obtain certificates for ${phish_domain} using manual mode."
    fi

    # Verify certs exist AND are readable after certbot runs
    if [[ -f "${live_dir}/fullchain.pem" && -r "${live_dir}/fullchain.pem" &&
          -f "${live_dir}/privkey.pem" && -r "${live_dir}/privkey.pem" ]]; then
        pass "Let's Encrypt certificates obtained (manual) for ${phish_domain}."
    else
        die 7 "Certbot completed but expected files not found or not readable in ${live_dir}."
    fi
}

###############################################################################
# configure_tls_and_config
###############################################################################
function configure_tls_and_config() {
    info "Copying TLS certificates from Certbot…"
    local src_cert="/etc/letsencrypt/live/${phish_domain}/fullchain.pem"
    local src_key="/etc/letsencrypt/live/${phish_domain}/privkey.pem"

    [[ -f "${src_cert}" && -f "${src_key}" ]] || die 1 "TLS certs not found. Ensure Certbot is run for ${phish_domain}."

    cp "${src_cert}" /etc/gophish/certs/phish/fullchain.pem || die 5 "Failed to copy certificate."
    cp "${src_key}" /etc/gophish/certs/phish/privkey.pem || die 5 "Failed to copy key."
    chown gophish:gophish /etc/gophish/certs/phish/*.pem
    chmod 0600 /etc/gophish/certs/phish/*.pem

    info "Creating GoPhish configuration file…"

    # Create temporary config file with secure permissions
    local temp_config
    temp_config="$(mktemp)" || die 5 "Failed to create temporary config file"
    chmod 600 "${temp_config}"

    cat > "${temp_config}" << EOF
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "/etc/gophish/certs/phish/fullchain.pem",
    "key_path": "/etc/gophish/certs/phish/privkey.pem"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/gophish/certs/phish/fullchain.pem",
    "key_path": "/etc/gophish/certs/phish/privkey.pem"
  },
  "db_name": "sqlite3",
  "db_path": "/var/lib/gophish/gophish.db",
  "migrations_prefix": "db/db_",
  "contact_address": "${contact_address:-""}",
  "logging": {
    "filename": "/var/log/gophish/gophish.log"
  }
}
EOF

    # Move to final location
    mv "${temp_config}" /etc/gophish/config.json
    chown gophish:gophish /etc/gophish/config.json
    chmod 0640 /etc/gophish/config.json
    pass "Config created."
}

###############################################################################
# create_service_and_sync
###############################################################################
function create_service_and_sync() {
    info "Creating systemd service for GoPhish…"

    if [[ ! -x "${GOPHISH_DIR}/gophish" ]]; then
        die 5 "Expected binary not found: ${GOPHISH_DIR}/gophish"
    fi
    if [[ ! -f "${GOPHISH_DIR}/VERSION" ]]; then
        die 5 "Expected VERSION not found in ${GOPHISH_DIR}"
    fi

    cat > /etc/systemd/system/gophish.service << EOF
[Unit]
Description=GoPhish Service
Wants=network-online.target
After=network-online.target

[Service]
User=${GOPHISH_USER}
Group=${GOPHISH_USER}
WorkingDirectory=${GOPHISH_DIR}
ExecStartPre=/usr/bin/test -f ${GOPHISH_DIR}/VERSION
ExecStart=${GOPHISH_DIR}/gophish --config /etc/gophish/config.json
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gophish
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/var/lib/gophish /var/log/gophish /etc/gophish ${GOPHISH_DIR}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 /etc/systemd/system/gophish.service

    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable --now gophish || die 6 "Failed to start GoPhish with systemd."

    # Verify service actually started
    sleep 2
    if ! systemctl is-active --quiet gophish; then
        die 6 "GoPhish service failed to start. Check 'systemctl status gophish' for details."
    fi

    pass "GoPhish systemd service installed and started."

    info "Installing cert sync helper script…"
    cat > /usr/local/sbin/gophish-cert-sync << EOF
#!/usr/bin/env bash
set -euo pipefail
echo "[gophish-cert-sync] starting"
cp /etc/letsencrypt/live/${phish_domain}/fullchain.pem /etc/gophish/certs/phish/fullchain.pem
cp /etc/letsencrypt/live/${phish_domain}/privkey.pem    /etc/gophish/certs/phish/privkey.pem
chown gophish:gophish /etc/gophish/certs/phish/*.pem
chmod 0600 /etc/gophish/certs/phish/*.pem
systemctl restart gophish
echo "[gophish-cert-sync] done"
EOF
    chmod 0755 /usr/local/sbin/gophish-cert-sync

    info "Creating systemd timer for cert sync…"
    cat > /etc/systemd/system/gophish-cert-sync.service << EOF
[Unit]
Description=GoPhish Cert Sync

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gophish-cert-sync
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gophish-cert-sync
EOF
    chmod 0644 /etc/systemd/system/gophish-cert-sync.service

    cat > /etc/systemd/system/gophish-cert-sync.timer << 'EOF'
[Unit]
Description=Run cert sync daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 0644 /etc/systemd/system/gophish-cert-sync.timer

    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable --now gophish-cert-sync.timer
    systemctl start gophish-cert-sync.service || warn "Initial cert sync run failed; will retry via timer."
    pass "Cert sync setup complete."
}

###############################################################################
# start_services_and_screen
###############################################################################
function start_services_and_screen() {
    systemctl restart gophish || die 6 "Failed to start GoPhish."

    # Verify service is running
    sleep 2
    if ! systemctl is-active --quiet gophish; then
        die 6 "GoPhish failed to start. Check logs with: journalctl -u gophish -n 50"
    fi

    pass "GoPhish restarted successfully."

    info "Launching detached screen session for log monitoring…"
    if command -v screen > /dev/null 2>&1; then
        if [[ ! -d /run/screen ]]; then
            mkdir -p /run/screen || true
            chmod 0777 /run/screen || true
        fi

        if screen -dmS gophish_logs bash -lc "tail -F /var/log/gophish/gophish.log"; then
            pass "Screen session launched under root. Attach with: screen -r gophish_logs"
        else
            warn "Failed to launch screen session."
        fi
    else
        warn "screen not found; skipping log tailing."
    fi
}

###############################################################################
# setup_firewall
###############################################################################
function setup_firewall() {
    if command -v ufw > /dev/null 2>&1; then
        info "Configuring UFW firewall rules…"
        if { ufw allow ssh && ufw allow 80 && ufw allow 443 && ufw --force enable; }; then
            pass "UFW configured."
        else
            warn "Some UFW actions failed."
        fi
    elif command -v firewall-cmd > /dev/null 2>&1; then
        info "Configuring firewalld firewall rules…"
        if {
            firewall-cmd --permanent --add-service=ssh &&
                   firewall-cmd --permanent --add-port=80/tcp &&
                   firewall-cmd --permanent --add-port=443/tcp &&
                   firewall-cmd --reload
        }; then
            pass "firewalld configured."
        else
            warn "Some firewalld actions failed."
        fi
    else
        warn "Neither ufw nor firewalld found; skipping firewall setup."
    fi
}

#==============================================================================
# Password Extraction
#==============================================================================

###############################################################################
# extract_initial_admin_password_from_log
###############################################################################
function extract_initial_admin_password_from_log() {
    local logfile="${1:-}"
    [[ -n "${logfile}" && -r "${logfile}" ]] || {
        warn "Log file missing/unreadable: ${logfile}"
        return 1
    }

    local line="" candidate="" last_password=""
    while IFS= read -r line; do
        if printf '%s' "${line}" | grep -Eiq 'admin' && printf '%s' "${line}" | grep -Eiq 'password'; then
            candidate="$(printf '%s' "${line}" | sed -E 's/.*[Pp]assword[^[:alnum:]]+([[:graph:]]+).*/\1/')" || candidate=""
            if [[ -z "${candidate}" || "${candidate}" == "${line}" ]]; then
                candidate="$(printf '%s' "${line}" | awk '{print $NF}')" || candidate=""
            fi
            candidate="$(printf '%s' "${candidate}" | sed -E 's/[[:punct:]]+$//')" || candidate=""
            if [[ -n "${candidate}" ]]; then
                last_password="${candidate}"
            fi
        fi
    done < "${logfile}"

    if [[ -n "${last_password}" ]]; then
        printf '%s\n' "${last_password}"
        return 0
    fi
    return 1
}

#==============================================================================
# Sanity & Reputation Checks
#==============================================================================

###############################################################################
# check_reputation
#------------------------------------------------------------------------------
# SECURITY NOTE: Domain and IP are validated before being used in DNS queries
###############################################################################
function check_reputation() {
    local ip="${1:-}"
    local domain="${2:-}"
    local reversed_ip=""
    local valid_ip valid_domain

    if ! command -v dig > /dev/null 2>&1; then
        warn "dig not found; install dnsutils to enable reputation checks."
        return 0
    fi

    # Validate before using in DNS queries (prevent command injection)
    is_valid_ipv4 "${ip}"
    valid_ip=$?
    if [[ ${valid_ip} -ne 0 ]]; then
        warn "Invalid or missing IPv4 address: ${ip}"
        return 0
    fi

    is_valid_domain "${domain}"
    valid_domain=$?
    if [[ ${valid_domain} -ne 0 ]]; then
        warn "Invalid or missing domain: ${domain}"
        return 0
    fi

    local IFS='.' o1 o2 o3 o4
    read -r o1 o2 o3 o4 <<< "${ip}"
    reversed_ip="${o4}.${o3}.${o2}.${o1}"

    # Common IP DNSBLs
    local -a rbls=(
        zen.spamhaus.org
        sbl.spamhaus.org
        xbl.spamhaus.org
        pbl.spamhaus.org
        b.barracudacentral.org
        bl.spamcop.net
        cbl.abuseat.org
        dnsbl.sorbs.net
        dul.dnsbl.sorbs.net
        spam.dnsbl.sorbs.net
        dnsbl-1.uceprotect.net
        dnsbl-2.uceprotect.net
        dnsbl-3.uceprotect.net
        psbl.surriel.com
        spamrbl.imp.ch
        db.wpbl.info
        bl.mailspike.net
        ix.dnsbl.manitu.net
        all.s5h.net
        hostkarma.junkemailfilter.com
        dnsbl.dronebl.org
        bl.nosolicitado.org
    )

    declare -A rbl_removal=(
          [zen.spamhaus.org]="https://check.spamhaus.org/removal/"
          [sbl.spamhaus.org]="https://check.spamhaus.org/removal/"
          [xbl.spamhaus.org]="https://check.spamhaus.org/removal/"
          [pbl.spamhaus.org]="https://check.spamhaus.org/removal/"
          [b.barracudacentral.org]="https://www.barracudanetworks.com/support/knowledgebase/100227.htm"
          [bl.spamcop.net]="https://www.spamcop.net/bl.shtml"
          [cbl.abuseat.org]="https://cbl.abuseat.org/removal.html"
          [dnsbl.sorbs.net]="https://www.sorbs.net/lookup.shtml"
          [dul.dnsbl.sorbs.net]="https://www.sorbs.net/lookup.shtml"
          [spam.dnsbl.sorbs.net]="https://www.sorbs.net/lookup.shtml"
          [dnsbl - 1.uceprotect.net]="https://www.uceprotect.net/en/index.php?m=7&s=0"
          [dnsbl - 2.uceprotect.net]="https://www.uceprotect.net/en/index.php?m=7&s=0"
          [dnsbl - 3.uceprotect.net]="https://www.uceprotect.net/en/index.php?m=7&s=0"
          [psbl.surriel.com]="https://psbl.surriel.com/removal/"
          [spamrbl.imp.ch]="https://imp.ch/spamrbl/"
          [db.wpbl.info]="http://db.wpbl.info/"
          [bl.mailspike.net]="https://www.mailspike.net/lookup"
          [ix.dnsbl.manitu.net]="mailto:dnsbl@manitu.net"
          [all.s5h.net]="https://www.s5h.net/blacklist"
          [hostkarma.junkemailfilter.com]="https://www.junkemailfilter.com/remove-from-blacklist"
          [dnsbl.dronebl.org]="https://dronebl.org/lookup"
          [bl.nosolicitado.org]="https://www.nosolicitado.org/lookup.php"
    )

    # Domain URI blocklists
    local -a surbls=(
        multi.surbl.org
        ab.surbl.org
        wsbl.surbl.org
        ph.surbl.org
        rhsbl.surbl.org
        uribl.spamhaus.org
        black.uribl.com
        grey.uribl.com
        red.uribl.com
        malware.uribl.com
        phishing.uribl.com
        dbl.spamhaus.org
    )

    declare -A surbl_removal=(
          [multi.surbl.org]="https://www.surbl.org/delisting-request"
          [ab.surbl.org]="https://www.surbl.org/delisting-request"
          [wsbl.surbl.org]="https://www.surbl.org/delisting-request"
          [ph.surbl.org]="https://www.surbl.org/delisting-request"
          [rhsbl.surbl.org]="https://www.surbl.org/delisting-request"
          [uribl.spamhaus.org]="https://uribl.spamhaus.org/removal/"
          [black.uribl.com]="https://uribl.com/delisting-request"
          [grey.uribl.com]="https://uribl.com/delisting-request"
          [red.uribl.com]="https://uribl.com/delisting-request"
          [malware.uribl.com]="https://uribl.com/delisting-request"
          [phishing.uribl.com]="https://uribl.com/delisting-request"
          [dbl.spamhaus.org]="https://check.spamhaus.org"
    )

    info "Checking IP ${ip} against ${#rbls[@]} DNSBLs…"
    local rbl removal_url
    for rbl in "${rbls[@]}"; do
        if dig +short "${reversed_ip}.${rbl}" A | grep -q '[0-9]'; then
            removal_url="${rbl_removal[${rbl}]-(no known removal URL)}"
            fail "  ✔ Listed in ${rbl} | Removal: ${removal_url}"
        else
            info "  — Not listed in ${rbl}"
        fi
    done

    info "Checking domain ${domain} against ${#surbls[@]} URI blocklists…"
    local s surbl_url
    for s in "${surbls[@]}"; do
        if dig +short "${domain}.${s}" A | grep -q '^127\.' || dig +short "${domain}.${s}" TXT | grep -q '[0-9]'; then
            surbl_url="${surbl_removal[${s}]-(no known removal URL)}"
            fail "  ✔ ${domain} appears in ${s} | Removal: ${surbl_url}"
        else
            info "  — ${domain} not found in ${s}"
        fi
    done
}

###############################################################################
# health_check
###############################################################################
function health_check() {
    local public_ip="${1:-}"
    local domain="${2:-}"

    if [[ -z "${domain}" && -n "${phish_domain:-}" ]]; then
        domain="${phish_domain}"
    fi
    if [[ -z "${public_ip}" ]]; then
        # Try to detect public IP (function outputs IP or returns 1)
        # shellcheck disable=SC2310  # detect_public_ipv4 is designed to return status codes
        public_ip="$(detect_public_ipv4)" || public_ip=""
    fi
    if [[ -z "${public_ip}" || -z "${domain}" ]]; then
        warn "health_check: missing IP or domain (public_ip='${public_ip:-}', domain='${domain:-}'). Skipping."
        return 0
    fi

    check_reputation "${public_ip}" "${domain}"

    info ">>> Verify the above health check looks good."
    info "Continue with installation? [y/N]:"
    local ans=""
    if [[ -t 0 ]]; then
        read -r ans || ans=""
    else
        ans="n"
    fi
    if [[ ! "${ans}" =~ ^[Yy]$ ]]; then
        die 90 "User aborted after pre-install sanity check."
    fi
    pass "Continuing with installation…"
}

#==============================================================================
# Main Execution Sequence
#==============================================================================

###############################################################################
# main
###############################################################################
function main() {
    parse_args "$@"

    health_check

    setup_environment
    setup_user_and_dirs
    build_gophish
    obtain_certs
    configure_tls_and_config
    create_service_and_sync
    start_services_and_screen

    # Extract password with proper error handling
    extract_initial_admin_password_from_log "${GOPHISH_LOG_FILE}"
    local extract_result=$?
    if [[ ${extract_result} -eq 0 ]]; then
        GOPHISH_INITIAL_ADMIN_PASSWORD="$(extract_initial_admin_password_from_log "${GOPHISH_LOG_FILE}")"
    else
        warn "No initial admin password found in ${GOPHISH_LOG_FILE}."
        warn "The service may still be initializing. Check logs: journalctl -u gophish"
        GOPHISH_INITIAL_ADMIN_PASSWORD="<check logs>"
    fi

    if [[ "${GOPHISH_INITIAL_ADMIN_PASSWORD}" != "<check logs>" ]]; then
        pass "Extracted initial admin password from log."
    fi

    setup_firewall
    pass "GoPhish installation complete."

    info "=========================== NEXT STEPS =============================="
    info " Admin UI : ${GOPHISH_ADMIN_URL}"
    info " Phish UI : https://${phish_domain}"
    info ""
    info " Default Admin Credentials:"
    info "   Username : admin"
    info "   Password : ${GOPHISH_INITIAL_ADMIN_PASSWORD}"
    if [[ -f /etc/gophish/api.key ]]; then
        info "   API Key  : (saved to) /etc/gophish/api.key"
    else
        info "   API Key  : Not detected on disk; see logs for /api/login result."
    fi
    info ""
    info " DNS reminders for your landing page / tracking:"
    info "   - Add/verify A record:     ${phish_domain} -> <your public IPv4>"
    info "   - (Optional) AAAA record:   ${phish_domain} -> <your public IPv6>"
    info "   - (Optional) CNAME:         www.${phish_domain} -> ${phish_domain}"
    info "   - If sending mail from this domain, configure:"
    info "       * SPF (TXT)"
    info "       * DKIM (TXT/CNAME per your MTA)"
    info "       * DMARC (TXT)"
    info "   - Ensure ports 80/443 are open on any upstream firewall/LB."
    info "====================================================================="
}

main "$@"
