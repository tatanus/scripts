#!/usr/bin/env bash

###############################################################################
# NAME         : setup-mail-server.sh
# DESCRIPTION  : Secure, robust one-shot installer for a send-only Postfix +
#                OpenDKIM mail server on Ubuntu, complete with Let's Encrypt
#                SSL, SPF, DKIM & DMARC. Structured with functions, colorized
#                logging, error handling, and inline documentation.
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-07
###############################################################################
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-07 | Adam Compton | Initial creation with robust error handling
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
        error "$2"
                            exit "$1"
}

function validate_commands() {
    local missing=0
    for cmd in "$@"; do
        command -v "${cmd}" &> /dev/null || {
            error "Required command not found: ${cmd}"
            missing=1
        }
    done
    ((missing == 0)) || die 1 "One or more required commands are missing."
}

#==============================================================================
# 0) Ensure sendmail wrapper
#==============================================================================
function check_sendmail() {
    if ! command -v sendmail &> /dev/null; then
        info "sendmail not found; installing bsd-mailx..."
        if apt-get update && apt-get install -y bsd-mailx; then
            :
        else
            die 1 "Failed installing bsd-mailx"
        fi
        pass "bsd-mailx installed"
    fi
}

#==============================================================================
# 1) Gather info
#==============================================================================
function gather_info() {
    info "Gathering config values"
    read -rp "Enter domain (e.g. example.com): " DOMAIN
    read -rp "Enter mail FQDN (e.g. mail.${DOMAIN}): " FQDN
    read -rp "Enter contact email (for certs): " CONTACT_EMAIL

    # Try to auto-detect PUBLIC_IP via multiple methods
    PUBLIC_IP=""

    # a) dig + OpenDNS
    if command -v dig &> /dev/null; then
        PUBLIC_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2> /dev/null || true)
    fi

    # b) curl to ipify
    if [[ -z "${PUBLIC_IP}" ]] && command -v curl &> /dev/null; then
        PUBLIC_IP=$(curl -s https://api.ipify.org || true)
    fi

    # c) wget to ipify
    if [[ -z "${PUBLIC_IP}" ]] && command -v wget &> /dev/null; then
        PUBLIC_IP=$(wget -qO- https://api.ipify.org || true)
    fi

    # d) ip route (best-effort if behind NAT this will give local IP)
    if [[ -z "${PUBLIC_IP}" ]] && command -v ip &> /dev/null; then
        PUBLIC_IP=$(ip route get 1.1.1.1 2> /dev/null \
            | awk '/src/ { for(i=1;i<=NF;i++) if ($i=="src") print $(i+1) }' \
            | head -n1 || true)
    fi

    # e) Prompt if still empty
    if [[ -n "${PUBLIC_IP}" ]]; then
        info "Detected public IP: ${PUBLIC_IP}"
    else
        read -rp "Server public IP for SPF/PTR (unchanged): " PUBLIC_IP
    fi

    HOSTNAME="${FQDN%%.*}"
    for v in DOMAIN FQDN CONTACT_EMAIL PUBLIC_IP HOSTNAME; do
        [[ -n "${!v}" ]] || die 1 "${v} cannot be empty"
    done
    pass "Config gathered"
}

#==============================================================================
# 2) Prompt DNS setup
#==============================================================================
function prompt_dns_update() {
    cat << EOF

==> Update DNS records:

• A:      ${HOSTNAME} → ${PUBLIC_IP} (TTL 3600)
• PTR:    ${PUBLIC_IP} → ${FQDN} (via ISP)
• MX:     ${DOMAIN} → ${FQDN} (prio 10, TTL 3600)
• SPF:    TXT @    "v=spf1 mx a ip4:${PUBLIC_IP} -all"
• DKIM:   TXT default._domainkey.${DOMAIN} → printed later
• DMARC:  TXT _dmarc.${DOMAIN} →
          "v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOMAIN}; pct=100; fo=1"
• MTA-STS: TXT _mta-sts.${DOMAIN} → "v=STSv1; id=20250807T000000Z"
• TLS-RPT: TXT _smtp._tls.${DOMAIN}→ "v=TLSRPTv1; rua=mailto:tlsrpt@${DOMAIN}"

Press ENTER when done.
EOF
    read -r
    pass "DNS setup acknowledged"
}

#==============================================================================
# 3) System prep
#==============================================================================
function system_prep() {
    info "Updating system..."
    if apt-get update && apt-get upgrade -y; then
        :
    else
        die 2 "Update failed"
    fi
    info "Setting hostname..."
    hostnamectl set-hostname "${FQDN}" || die 3
    echo "${FQDN}" > /etc/hostname
    grep -q "${FQDN}" /etc/hosts || echo "${PUBLIC_IP} ${FQDN} ${HOSTNAME}" >> /etc/hosts
    pass "System ready"
}

#==============================================================================
# 4) Obtain certs (DNS-01)
#==============================================================================
function obtain_certs() {
    info "Installing certbot..."
    apt-get install -y certbot || die 6
    info "Requesting certs via DNS-01..."
    certbot certonly --manual --preferred-challenges dns-01 \
        --manual-public-ip-logging-ok --agree-tos \
        --register-unsafely-without-email \
        --server https://acme-v02.api.letsencrypt.org/directory \
        -d "${FQDN}" || die 7
    CERT_DIR="/etc/letsencrypt/live/${FQDN}"
    [[ -d "${CERT_DIR}" ]] || die 8
    info "Configuring renewal hook"
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-mail << 'HOOK'
#!/usr/bin/env bash
systemctl reload postfix opendkim
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-mail
    pass "Certs ready"
}

#==============================================================================
# 5) MTA-STS policy
#==============================================================================
function setup_mta_sts() {
    MTA_STS_DIR="/var/www/mta-sts"
    mkdir -p "${MTA_STS_DIR}"
    cat > "${MTA_STS_DIR}/mta-sts.txt" << EOF
version: STSv1
mode: enforce
mx: ${FQDN}
timeout: 86400
EOF
    pass "MTA-STS policy created at ${MTA_STS_DIR}/mta-sts.txt"
}

#==============================================================================
# 6) OpenDKIM
#==============================================================================
function setup_opendkim() {
    info "Installing OpenDKIM..."
    apt-get install -y opendkim opendkim-tools || die 9
    DKIM_DIR="/etc/opendkim/keys/${DOMAIN}"
    if mkdir -p "${DKIM_DIR}" && opendkim-genkey -s default -d "${DOMAIN}" -D "${DKIM_DIR}"; then
        :
    else
        die 11
    fi
    chown -R opendkim:opendkim "${DKIM_DIR}"
    printf 'Host: default._domainkey.%s
Value: "%s"
' "${DOMAIN}" "$(sed -z 's/["\n]//g; s/.*p=\([^[:space:]]*\).*/\1/p; d' "${DKIM_DIR}/default.txt")"
    read -rp "Press ENTER once DKIM TXT is live" _
    cat > /etc/opendkim.conf << EOF
Syslog
UMask                  002
Domain                 ${DOMAIN}
KeyFile                ${DKIM_DIR}/default.private
Selector               default
Socket                 inet:12345@localhost
KeyTable               refile:/etc/opendkim/key.table
SigningTable           refile:/etc/opendkim/signing.table
TrustedHosts           /etc/opendkim/trusted.hosts
EOF
    cat > /etc/opendkim/key.table << EOF
default._domainkey.${DOMAIN} ${DOMAIN}:default:${DKIM_DIR}/default.private
EOF
    cat > /etc/opendkim/signing.table << EOF
*@${DOMAIN} default._domainkey.${DOMAIN}
EOF
    cat > /etc/opendkim/trusted.hosts << EOF
127.0.0.1
localhost
${FQDN}
EOF
    systemctl enable --now opendkim
    pass "OpenDKIM running"
}

#==============================================================================
# 7) Postfix & Throttling & Aliases
#==============================================================================
function setup_postfix() {
    info "Installing Postfix & deps..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules mailutils || die 12
    postconf -e "myhostname=${FQDN}"
    postconf -e "myorigin=${DOMAIN}"
    postconf -e "inet_interfaces=loopback-only"
    postconf -e "inet_protocols=ipv4"
    postconf -e "smtp_tls_security_level=encrypt"
    postconf -e "smtp_tls_mandatory_protocols=TLSv1.2"
    postconf -e "smtp_tls_cert_file=${CERT_DIR}/fullchain.pem"
    postconf -e "smtp_tls_key_file=${CERT_DIR}/privkey.pem"
    postconf -e "smtp_tls_CAfile=${CERT_DIR}/chain.pem"
    postconf -e "smtpd_tls_security_level=may"
    postconf -e "smtpd_tls_cert_file=${CERT_DIR}/fullchain.pem"
    postconf -e "smtpd_tls_key_file=${CERT_DIR}/privkey.pem"
    postconf -e "smtpd_tls_CAfile=${CERT_DIR}/chain.pem"
    postconf -e "milter_default_action=accept"
    postconf -e "milter_protocol=6"
    postconf -e "smtpd_milters=inet:localhost:12345"
    postconf -e "non_smtpd_milters=inet:localhost:12345"
    # polite throttling
    postconf -e "anvil_rate_delay=1s"
    # header checks
    echo '/^Received-SPF:/ IGNORE' > /etc/postfix/header_checks
    postconf -e "header_checks=regexp:/etc/postfix/header_checks"
    postmap /etc/postfix/header_checks || die 13
    # mail aliases for postmaster & tlsrpt
    grep -q '^postmaster:' /etc/aliases || echo "postmaster:    postmaster@${DOMAIN}" >> /etc/aliases
    grep -q '^tlsrpt:' /etc/aliases    || echo "tlsrpt:       postmaster@${DOMAIN}" >> /etc/aliases
    newaliases || die 14 "newaliases failed"
    systemctl restart postfix
    pass "Postfix running with aliases"
}

#==============================================================================
# 8) ARC header placeholder
#==============================================================================
function setup_arc() {
    info "ARC generation requires additional milter (e.g., OpenARC)."
    info "Please install/configure OpenARC or similar for ARC support."
}

#==============================================================================
# 9) Final instructions
#==============================================================================
function final_instructions() {
    cat << EOF

Setup complete! Next:
1) Verify SPF/DKIM/DMARC via external testers.
2) Check MTA-STS: https://${DOMAIN}/.well-known/mta-sts.txt
3) Check TLS-RPT aggregate;
   look for TXT _smtp._tls.${DOMAIN}
4) Monitor DMARC reports in Postmaster inbox.
5) For ARC, install OpenARC and configure milter.

Gophish:
• SMTP: 127.0.0.1:25 (no TLS/auth)
• Use your domain as envelope; web landing domain can differ.

Happy sending!
EOF
    pass "Done"
}

#==============================================================================
# 10) check reputation
#===============================================================================
###############################################################################
# check_reputation
#  - Takes two args: an IPv4 address, and a domain name.
#  - Queries a list of well-known RBLs for the IP.
#  - Queries a list of URI blocklists for the domain.
# Globals:
#  - none
# Arguments:
#  - $1: IPv4 address to check
#  - $2: Domain name to check
# Returns:
#  - Prints findings to stdout (you can redirect or parse as needed).
###############################################################################
function check_reputation() {
    local ip="$1"
    local domain="$2"
    local reversed_ip
    local rbls=(
        zen.spamhaus.org
        sbl.spamhaus.org
        xbl.spamhaus.org
        pbl.spamhaus.org
        b.barracudacentral.org
        bl.spamcop.net
        cbl.abuseat.org
        dnsbl.sorbs.net
        dnsbl-1.uceprotect.net
        dnsbl-2.uceprotect.net
        dnsbl-3.uceprotect.net
        psbl.surriel.com
        spamrbl.imp.ch
        db.wpbl.info
        bl.mailspike.net
        ix.dnsbl.manitu.net
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
               [dnsbl - 1.uceprotect.net]="mailto:uceprotect@uceprotect.net"
               [dnsbl - 2.uceprotect.net]="mailto:uceprotect@uceprotect.net"
               [dnsbl - 3.uceprotect.net]="mailto:uceprotect@uceprotect.net"
               [psbl.surriel.com]="https://psbl.surriel.com/removal/"
               [spamrbl.imp.ch]="https://imp.ch/spamrbl/"
               [db.wpbl.info]="http://db.wpbl.info/?ADDR=${ip}"
               [bl.mailspike.net]="https://www.mailspike.net/lookup"
               [ix.dnsbl.manitu.net]="mailto:dnsbl@manitu.net"
    )

    local surbls=(
        multi.surbl.org
        ab.surbl.org
        wsbl.surbl.org
        ph.surbl.org
        rhsbl.surbl.org
        uribl.spamhaus.org
        black.uribl.com
        malware.uribl.com
        phishing.uribl.com
    )
    declare -A surbl_removal=(
               [multi.surbl.org]="https://www.surbl.org/delisting-request"
               [ab.surbl.org]="https://www.surbl.org/delisting-request"
               [wsbl.surbl.org]="https://www.surbl.org/delisting-request"
               [ph.surbl.org]="https://www.surbl.org/delisting-request"
               [rhsbl.surbl.org]="https://www.surbl.org/delisting-request"
               [uribl.spamhaus.org]="https://uribl.spamhaus.org/removal/"
               [black.uribl.com]="https://uribl.com/delisting-request"
               [malware.uribl.com]="https://uribl.com/delisting-request"
               [phishing.uribl.com]="https://uribl.com/delisting-request"
    )

    info "Checking IP ${ip} against ${#rbls[@]} RBLs…"
    IFS='.' read -r o1 o2 o3 o4 <<< "${ip}"
    reversed_ip="${o4}.${o3}.${o2}.${o1}"

    for rbl in "${rbls[@]}"; do
        if dig +short "${reversed_ip}.${rbl}" A | grep -q '[0-9]'; then
            printf "  ✔ Listed in %s\n    → Removal: %s\n" \
                "${rbl}" "${rbl_removal[${rbl}]}"
        else
            printf "  — Not listed in %s\n" "${rbl}"
        fi
    done

    echo
    info "Checking domain ${domain} against ${#surbls[@]} URI blocklists…"
    for surbl in "${surbls[@]}"; do
        if dig +short "${domain}.${surbl}" TXT | grep -q '[0-9]'; then
            printf "  ✔ %s appears in %s\n    → Removal: %s\n" \
                "${domain}" "${surbl}" "${surbl_removal[${surbl}]}"
        else
            printf "  — %s not found in %s\n" "${domain}" "${surbl}"
        fi
    done
}

#==============================================================================
# 11) Health-check script
#===============================================================================
function health_check() {
    info "Running health checks"
    echo -n "Checking rDNS... "
    rdns=$(dig +short -x "${PUBLIC_IP}")
    echo "${rdns}"
    echo -n "Checking public RBLs... "
    for rbl in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do
        echo -n "${rbl}..."
        dig +short "${PUBLIC_IP}"."${rbl}"
    done
    echo "DMARC summary:"
    # assumes reports in /var/mail/postmaster
    grep -c "policy_evaluated" /var/mail/postmaster || echo "No reports found"
    pass "Health checks done"

    check_reputation "${PUBLIC_IP}" "${DOMAIN}"
}

#==============================================================================
# MAIN
#==============================================================================
function main() {
    validate_commands apt-get hostnamectl certbot opendkim-genkey postconf dig
    check_sendmail
    gather_info
    prompt_dns_update
    system_prep
    obtain_certs
    setup_mta_sts
    setup_opendkim
    setup_postfix
    setup_arc
    final_instructions
    health_check
}

main "$@"
