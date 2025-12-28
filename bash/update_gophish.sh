#!/usr/bin/env bash

###############################################################################
# NAME         : gophish_change_domain.sh
# DESCRIPTION  : Updates the phishing domain for an existing GoPhish installation.
#                Replaces TLS certs and updates the cert sync script.
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-08
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-08 | Adam Compton | Initial creation using custom template
###############################################################################

set -uo pipefail
IFS=$'\n\t'

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
# Global Variables
#==============================================================================
SCRIPT_NAME="$(basename "$0")"
CERT_DST_DIR="/etc/gophish/certs/phish"
CONFIG_FILE="/etc/gophish/config.json"
CERT_SYNC_SCRIPT="/usr/local/sbin/gophish-cert-sync"
GOPHISH_SERVICE="gophish"

#==============================================================================
# Utility Functions
#==============================================================================
# die: log error and exit with provided code
function die() {
    local exit_code="${1}"
    local error_msg="${2}"
    error "${error_msg}"
    exit "${exit_code}"
}

#==============================================================================
# Validate Certs
#==============================================================================
function validate_certs() {
    local domain="${1}"
    local src_dir="/etc/letsencrypt/live/${domain}"

    if [[ ! -f "${src_dir}/fullchain.pem" ]] || [[ ! -f "${src_dir}/privkey.pem" ]]; then
        die 1 "TLS certificates for '${domain}' not found at '${src_dir}'"
    fi
    pass "TLS certs validated for ${domain}"
}

#==============================================================================
# Copy Certificates
#==============================================================================
function copy_certs() {
    local domain="${1}"
    local src_dir="/etc/letsencrypt/live/${domain}"

    cp "${src_dir}/fullchain.pem" "${CERT_DST_DIR}/fullchain.pem" || die 2 "Failed to copy fullchain.pem"
    cp "${src_dir}/privkey.pem" "${CERT_DST_DIR}/privkey.pem" || die 2 "Failed to copy privkey.pem"
    chown gophish:gophish "${CERT_DST_DIR}/fullchain.pem" "${CERT_DST_DIR}/privkey.pem"
    chmod 0600 "${CERT_DST_DIR}/fullchain.pem" "${CERT_DST_DIR}/privkey.pem"
    pass "Certificates copied and permissions set"
}

#==============================================================================
# Update Cert Sync Script
#==============================================================================
function update_cert_sync_script() {
    local domain="${1}"
    if [[ -f "${CERT_SYNC_SCRIPT}" ]]; then
        sed -i "s|/etc/letsencrypt/live/[^/]*/|/etc/letsencrypt/live/${domain}/|g" "${CERT_SYNC_SCRIPT}" \
            || warn "Could not update domain in cert sync script"
        pass "Updated domain in cert sync script"
    else
        warn "Cert sync script not found: ${CERT_SYNC_SCRIPT}"
    fi
}

#==============================================================================
# Restart GoPhish
#==============================================================================
function restart_gophish_service() {
    systemctl restart "${GOPHISH_SERVICE}" || die 3 "Failed to restart GoPhish service"
    pass "GoPhish service restarted"
}

#==============================================================================
# Main Function
#==============================================================================
function main() {
    if [[ "$#" -ne 1 ]]; then
        echo "Usage: ${SCRIPT_NAME} <new-phish-domain>"
        die 1 "Invalid number of arguments"
    fi

    local new_domain="${1}"
    info "Changing GoPhish phishing domain to: ${new_domain}"

    validate_certs "${new_domain}"
    copy_certs "${new_domain}"
    update_cert_sync_script "${new_domain}"
    restart_gophish_service

    pass "Phishing domain successfully changed to: ${new_domain}"
}

main "$@"
