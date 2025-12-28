#!/usr/bin/env bash

###############################################################################
# NAME         : update-mail-domain.sh
# DESCRIPTION  : Update an existing Postfix/OpenDKIM mail server installation
#                to a new base domain (SPF, DKIM, DMARC, MTA-STS, TLS-RPT,
#                aliases, and certificates).
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-07
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-07 | Adam Compton | Initial creation.
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

function die() {
    local code="$1" msg="$2"
    error "${msg}"
    exit "${code}"
}

function validate_commands() {
    local missing=0 cmd
    for cmd in "$@"; do
        if ! command -v "${cmd}" &> /dev/null; then
            error "Required command not found: ${cmd}"
            missing=1
        fi
    done
    ((missing == 0))   || die 1 "One or more required commands are missing."
}

#==============================================================================
# 1) Gather old and new domain info
#==============================================================================
function gather_info() {
    info "Gathering domain and network information"

    # 1) Auto-detect OLD_DOMAIN from Postfix
    OLD_DOMAIN=$(postconf -h myorigin 2> /dev/null || true)
    if [[ -n "${OLD_DOMAIN}" ]]; then
        info "Detected current mail domain: ${OLD_DOMAIN}"
    else
        read -rp "Current mail domain (old, e.g. example.com): " OLD_DOMAIN
    fi

    # 2) Prompt for NEW_DOMAIN and NEW_FQDN
    read -rp "New mail domain (new, e.g. newdomain.com): " NEW_DOMAIN
    read -rp "New mail hostname (FQDN, e.g. mail.${NEW_DOMAIN}): " NEW_FQDN

    # 3) Try to auto-detect PUBLIC_IP via multiple methods
    PUBLIC_IP=""

    # 3a) dig + OpenDNS
    if command -v dig &> /dev/null; then
        PUBLIC_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2> /dev/null || true)
    fi

    # 3b) curl to ipify
    if [[ -z "${PUBLIC_IP}" ]] && command -v curl &> /dev/null; then
        PUBLIC_IP=$(curl -s https://api.ipify.org || true)
    fi

    # 3c) wget to ipify
    if [[ -z "${PUBLIC_IP}" ]] && command -v wget &> /dev/null; then
        PUBLIC_IP=$(wget -qO- https://api.ipify.org || true)
    fi

    # 3d) ip route (best-effort if behind NAT this will give local IP)
    if [[ -z "${PUBLIC_IP}" ]] && command -v ip &> /dev/null; then
        PUBLIC_IP=$(ip route get 1.1.1.1 2> /dev/null \
            | awk '/src/ { for(i=1;i<=NF;i++) if ($i=="src") print $(i+1) }' \
            | head -n1 || true)
    fi

    # 3e) Prompt if still empty
    if [[ -n "${PUBLIC_IP}" ]]; then
        info "Detected public IP: ${PUBLIC_IP}"
    else
        read -rp "Server public IP for SPF/PTR (unchanged): " PUBLIC_IP
    fi

    # 4) Validation
    for var in OLD_DOMAIN NEW_DOMAIN NEW_FQDN PUBLIC_IP; do
        [[ -n "${!var}" ]] || die 2 "${var} cannot be empty"
    done

    pass "Domain and IP info gathered"
}

#==============================================================================
# 2) Backup existing configs
#==============================================================================
function backup_configs() {
    info "Backing up existing configuration files"
    local files=(
        /etc/postfix/main.cf
        /etc/opendkim.conf
        /etc/aliases
        /var/www/mta-sts/mta-sts.txt
    )
    for f in "${files[@]}"; do
        if [[ -f "${f}" ]]; then
            cp "${f}" "${f}.bak" || die 3 "Failed to backup ${f}"
            pass "Backed up ${f} → ${f}.bak"
        fi
    done
}

#==============================================================================
# 3) Update Postfix main.cf
#==============================================================================
function update_postfix_config() {
    info "Updating Postfix configuration (main.cf)"
    sed -i \
        -e "s/^myhostname = .*/myhostname = ${NEW_FQDN}/" \
        -e "s/^myorigin = .*/myorigin = ${NEW_DOMAIN}/" \
        /etc/postfix/main.cf || die 4 "Postfix config update failed"
    pass "Postfix main.cf updated"
}

#==============================================================================
# 4) Obtain new TLS certificates via DNS-01
#==============================================================================
function obtain_certs() {
    info "Requesting new TLS certificate for ${NEW_FQDN}"
    certbot certonly --manual --preferred-challenges dns-01 \
        --manual-public-ip-logging-ok --agree-tos \
        --register-unsafely-without-email \
        --server https://acme-v02.api.letsencrypt.org/directory \
        -d "${NEW_FQDN}" \
        || die 5 "Certbot issuance failed for ${NEW_FQDN}"

    CERT_DIR="/etc/letsencrypt/live/${NEW_FQDN}"
    [[ -d "${CERT_DIR}" ]] || die 6 "Certificate directory ${CERT_DIR} not found"
    pass "Certificate obtained at ${CERT_DIR}"
}

#==============================================================================
# 5) Generate new DKIM key
#==============================================================================
function generate_dkim_key() {
    info "Generating new DKIM key for ${NEW_DOMAIN}"
    DKIM_DIR="/etc/opendkim/keys/${NEW_DOMAIN}"
    mkdir -p "${DKIM_DIR}" || die 7 "Failed to create DKIM directory"
    opendkim-genkey -s default -d "${NEW_DOMAIN}" -D "${DKIM_DIR}" \
        || die 8 "DKIM key generation failed"
    chown -R opendkim:opendkim "${DKIM_DIR}" || die 9 "DKIM key ownership failed"

    local pub
    pub=$(sed -n 's/^.*p=\(.*\)";/\1/p' "${DKIM_DIR}/default.txt") || die 10 "Failed extracting DKIM public key"
    cat << EOF

Add this DKIM TXT record for ${NEW_DOMAIN}:

Host:   default._domainkey.${NEW_DOMAIN}
Value:  "v=DKIM1; k=rsa; p=${pub}"
EOF
    read -rp "Press ENTER once DKIM DNS record is live: " _
    pass "DKIM key ready"
}

#==============================================================================
# 6) Update OpenDKIM configuration and tables
#==============================================================================
function update_opendkim() {
    info "Updating OpenDKIM configuration"
    sed -i \
        -e "s#^Domain.*#Domain                  ${NEW_DOMAIN}#" \
        -e "s#^KeyFile.*#KeyFile                 ${DKIM_DIR}/default.private#" \
        /etc/opendkim.conf || die 11 "Failed updating /etc/opendkim.conf"

    cat > /etc/opendkim/key.table << EOF
default._domainkey.${NEW_DOMAIN} ${NEW_DOMAIN}:default:${DKIM_DIR}/default.private
EOF

    cat > /etc/opendkim/signing.table << EOF
*@${NEW_DOMAIN} default._domainkey.${NEW_DOMAIN}
EOF

    pass "OpenDKIM configuration updated"
}

#==============================================================================
# 7) Update mail aliases
#==============================================================================
function update_aliases() {
    info "Updating mail aliases"
    grep -q '^postmaster:' /etc/aliases \
        || echo "postmaster:    postmaster@${NEW_DOMAIN}" >> /etc/aliases
    grep -q '^tlsrpt:' /etc/aliases \
        || echo "tlsrpt:       postmaster@${NEW_DOMAIN}" >> /etc/aliases

    newaliases || die 12 "newaliases command failed"
    pass "Aliases updated"
}

#==============================================================================
# 8) Update MTA-STS policy
#==============================================================================
function update_mta_sts() {
    info "Updating MTA-STS policy"
    local mta_dir="/var/www/mta-sts"
    mkdir -p "${mta_dir}" || die 13 "Failed to create ${mta_dir}"

    cat > "${mta_dir}/mta-sts.txt" << EOF
version: STSv1
mode: enforce
mx: ${NEW_FQDN}
timeout: 86400
EOF

    pass "MTA-STS policy written to ${mta_dir}/mta-sts.txt"
}

#==============================================================================
# 9) Prompt for DNS updates
#==============================================================================
function prompt_dns_update() {
    cat << EOF

--- DNS Update Required for ${NEW_DOMAIN} ---
• A record:    ${NEW_FQDN} → ${PUBLIC_IP}
• MX record:   ${NEW_DOMAIN} → ${NEW_FQDN}
• SPF (TXT @): "v=spf1 mx a ip4:${PUBLIC_IP} -all"
• DKIM (TXT):  default._domainkey.${NEW_DOMAIN} (see above)
• DMARC (TXT _dmarc): "v=DMARC1; p=quarantine; rua=mailto:postmaster@${NEW_DOMAIN}; pct=100; fo=1"
• MTA-STS (TXT _mta-sts): "v=STSv1; id=${NEW_DOMAIN}-$(date -u +%Y%m%dT%H%M%SZ)"
• TLS-RPT (TXT _smtp._tls): "v=TLSRPTv1; rua=mailto:tlsrpt@${NEW_DOMAIN}"

Press ENTER when DNS changes have propagated.
EOF
    read -r
    pass "DNS update acknowledged"
}

#==============================================================================
# 10) Reload services
#==============================================================================
function reload_services() {
    info "Reloading Postfix and OpenDKIM"
    for svc in postfix opendkim; do
        systemctl reload "${svc}" \
            || die 14 "Failed reloading ${svc}"
    done
    pass "Services reloaded"
}

#==============================================================================
# MAIN
#==============================================================================
function main() {
    validate_commands sed certbot opendkim-genkey newaliases systemctl
    gather_info
    backup_configs
    update_postfix_config
    obtain_certs
    generate_dkim_key
    update_opendkim
    update_aliases
    update_mta_sts
    prompt_dns_update
    reload_services
    pass "Domain update complete!"
}

main "$@"
