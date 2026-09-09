#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154
# Rationale: RECON_* globals and the LOG front-end come from
# run_recon.sh / recon_lib.sh (SC2154); DISC_* and RECON_AWAITING_REVIEW are
# set here and read by the orchestrator and sibling functions (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : discovery_lib.sh
# DESCRIPTION  : Derive candidate DNS domains from an IP scope when no
#                domains.txt is supplied. Techniques: scope, rdns, tls, ike,
#                http, smtp, smb-ldap, whois. Every finding is written with
#                provenance; results are reduced to registrable apexes and
#                left for operator review (never auto-enumerated).
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation - ported from recon_new.sh
# =============================================================================

if [[ -z "${DISCOVERY_LIB_LOADED:-}" ]]; then
    DISCOVERY_LIB_LOADED=1

    # Hosting / CDN / ISP apexes that reverse-DNS and whois routinely reveal
    # but which are almost never the client's registrable domain.
    DISC_PROVIDER_DENYLIST="amazonaws.com cloudfront.net akamai.net akamaitechnologies.com \
azure.com azurewebsites.net cloudflare.com cloudflare.net googleusercontent.com \
1e100.net comcast.net rr.com level3.net cogentco.com he.net gtt.net \
digitalocean.com linode.com googlehosted.com outlook.com microsoft.com \
office365.com fastly.net incapsula.com sucuri.net"

    ###########################################################################
    # disc_emit
    # Purpose : Append a cleaned "<name>\t<technique>\t<evidence>" row.
    # Args    : reads TAB-delimited "name[\tevidence]" rows on stdin;
    #           $1 technique label ; writes to ${DISC_PROV}
    ###########################################################################
    function disc_emit() {
        local src="${1}"
        awk -F'\t' -v src="${src}" '
            NF >= 1 {
                name = $1; ev = (NF >= 2 ? $2 : "")
                gsub(/^[ \t"'"'"']+|[ \t"'"'"'.]+$/, "", name)
                name = tolower(name)
                sub(/^\*\./, "", name)
                sub(/\.$/, "", name)
                if (name ~ /^[a-z0-9][a-z0-9._-]*\.[a-z0-9-][a-z0-9-]+$/ && name !~ /\.\./) {
                    print name "\t" src "\t" ev
                }
            }' >> "${DISC_PROV}"
    }

    ###########################################################################
    # disc_scope : hostnames already present in targets.txt.
    ###########################################################################
    function disc_scope() {
        [[ -s "${DISC_HOSTS}" ]] || return 0
        LOG info "discovery[scope]: $(count_lines "${DISC_HOSTS}") hostname(s) in scope"
        awk 'NF { print $0 "\tin targets.txt" }' "${DISC_HOSTS}" | disc_emit "scope"
    }

    ###########################################################################
    # disc_rdns : PTR records for each IP (dnsx if present, else dig).
    ###########################################################################
    function disc_rdns() {
        [[ -s "${DISC_IPS}" ]] || return 0
        LOG info "discovery[rdns]: reverse lookups over $(count_lines "${DISC_IPS}") IP(s)"
        if have_cmd dnsx; then
            dnsx -ptr -resp-only -silent -t "${RECON_THREADS:-50}" -l "${DISC_IPS}" 2> /dev/null |
                awk 'NF { print $0 "\tPTR" }' | disc_emit "rdns"
        elif have_cmd dig; then
            local ip name
            while IFS= read -r ip; do
                [[ -n "${ip}" ]] || continue
                name="$(dig +short -x "${ip}" 2> /dev/null | head -n 1)"
                [[ -n "${name}" ]] && printf '%s\tPTR\n' "${name}" | disc_emit "rdns"
            done < "${DISC_IPS}"
        fi
    }

    ###########################################################################
    # disc_tls : certificate CN + SANs (tlsx if present, else openssl).
    ###########################################################################
    function disc_tls() {
        [[ -s "${DISC_IPS}" ]] || return 0
        local ports="${RECON_TLS_PORTS:-443,8443,993,995,465,636}"
        local IFS=$' \t\n'
        LOG info "discovery[tls]: certificate names on ports ${ports}"
        if have_cmd tlsx; then
            tlsx -l "${DISC_IPS}" -p "${ports}" -san -cn -resp-only -silent \
                -c "${RECON_THREADS:-50}" 2> /dev/null |
                awk 'NF { print $0 "\tcert" }' | disc_emit "tls"
            return 0
        fi
        have_cmd openssl || return 0
        local ip port
        while IFS= read -r ip; do
            [[ -n "${ip}" ]] || continue
            for port in ${ports//,/ }; do
                printf 'Q\n' | ${RECON_TIMEOUT_CMD:+${RECON_TIMEOUT_CMD} 8} \
                    openssl s_client -connect "${ip}:${port}" -servername "${ip}" 2> /dev/null |
                    openssl x509 -noout -text 2> /dev/null |
                    grep -oiE 'DNS:[a-z0-9.*-]+' | sed 's/^DNS://I' |
                    awk 'NF { print $0 "\tcert" }' | disc_emit "tls"
            done
        done < "${DISC_IPS}"
    }

    ###########################################################################
    # disc_ike : IKE aggressive-mode ID_FQDN payloads (needs ike-scan + root).
    ###########################################################################
    function disc_ike() {
        have_cmd ike-scan || {
            LOG debug "discovery[ike]: ike-scan not installed, skipping"
            return 0
        }
        [[ -s "${DISC_IPS}" ]] || return 0
        LOG info "discovery[ike]: aggressive-mode ID probing"
        local runner=()
        [[ "${RECON_ELEV}" == "sudo" ]] && runner=(sudo)
        ${runner[@]+"${runner[@]}"} ike-scan -A -M --id=recon -f "${DISC_IPS}" 2> /dev/null |
            grep -oiE 'ID_(FQDN|USER_FQDN)=[a-z0-9.@_-]+' |
            sed -E 's/^ID_[A-Z_]+=//I; s/^[^@]*@//' |
            awk 'NF { print $0 "\tIKE ID" }' | disc_emit "ike" || true
    }

    ###########################################################################
    # disc_http : Location redirects / CSP / body hostnames (httpx else curl).
    ###########################################################################
    function disc_http() {
        [[ -s "${DISC_IPS}" ]] || return 0
        local ports="${RECON_WEB_PORTS:-80,443,8080,8443}"
        LOG info "discovery[http]: redirect/CSP hostnames on ports ${ports}"
        if have_cmd httpx; then
            httpx -l "${DISC_IPS}" -p "${ports}" -location -silent \
                -threads "${RECON_THREADS:-50}" 2> /dev/null |
                grep -oiE 'https?://[a-z0-9.-]+' | sed -E 's#^https?://##I' |
                awk 'NF { print $0 "\tHTTP redirect" }' | disc_emit "http"
        fi
    }

    ###########################################################################
    # disc_smtp : MTA 220 greetings (built-in nc/bash grabber).
    ###########################################################################
    function disc_smtp() {
        [[ -s "${DISC_IPS}" ]] || return 0
        local ports="${RECON_SMTP_PORTS:-25,587,2525}"
        local IFS=$' \t\n'
        LOG info "discovery[smtp]: MTA banners on ports ${ports}"
        have_cmd nc || return 0
        local ip port banner
        while IFS= read -r ip; do
            [[ -n "${ip}" ]] || continue
            for port in ${ports//,/ }; do
                banner="$(${RECON_TIMEOUT_CMD:+${RECON_TIMEOUT_CMD} 6} \
                    nc -w 5 "${ip}" "${port}" 2> /dev/null < /dev/null | head -n 1)"
                printf '%s\n' "${banner}" |
                    grep -oiE '220[ -][a-z0-9.-]+\.[a-z]{2,}' |
                    sed -E 's/^220[ -]//' |
                    awk 'NF { print $0 "\tSMTP 220" }' | disc_emit "smtp"
            done
        done < "${DISC_IPS}"
    }

    ###########################################################################
    # disc_smb_ldap : SMB OS discovery + LDAP RootDSE naming contexts (nmap).
    ###########################################################################
    function disc_smb_ldap() {
        have_cmd nmap || return 0
        [[ -s "${DISC_IPS}" ]] || return 0
        LOG info "discovery[smb-ldap]: SMB/LDAP domain names via nmap NSE"
        local xml="${DISC_DIR}/smb-ldap.xml"
        run nmap -Pn -n -p 139,445,389,636 \
            --script "smb-os-discovery,ldap-rootdse" \
            -iL "${DISC_IPS}" -oX "${xml}" > /dev/null 2>&1 || true
        [[ -f "${xml}" ]] || return 0
        grep -oiE '(Domain|dnsHostName|defaultNamingContext)[^a-z0-9]+[a-z0-9.,=-]+' "${xml}" 2> /dev/null |
            grep -oiE '[a-z0-9-]+\.[a-z0-9.-]+\.[a-z]{2,}' |
            awk 'NF { print $0 "\tSMB/LDAP" }' | disc_emit "smb-ldap" || true
    }

    ###########################################################################
    # disc_whois : registry org / netname / contact email domains (per /24).
    ###########################################################################
    function disc_whois() {
        have_cmd whois || return 0
        [[ -s "${DISC_IPS}" ]] || return 0
        LOG info "discovery[whois]: registry data (cap ${RECON_WHOIS_MAX:-64} queries)"
        local seen="" n=0 ip net
        while IFS= read -r ip; do
            [[ "${n}" -ge "${RECON_WHOIS_MAX:-64}" ]] && break
            net="${ip%.*}"
            in_list "${net}" "${seen}" && continue
            seen="${seen} ${net}"
            n=$((n + 1))
            whois "${ip}" 2> /dev/null |
                grep -oiE '[a-z0-9][a-z0-9-]*\.[a-z]{2,}' |
                awk 'NF { print $0 "\twhois" }' | disc_emit "whois"
        done < "${DISC_IPS}"
    }

    ###########################################################################
    # disc_normalize
    # Purpose : Reduce provenance rows to registrable apexes, drop provider
    #           domains, and write candidates + observed FQDNs.
    ###########################################################################
    function disc_normalize() {
        local keep_providers="${RECON_KEEP_PROVIDERS:-0}"
        sort -u "${DISC_PROV}" -o "${DISC_PROV}"
        cut -f1 "${DISC_PROV}" | sort -u > "${RECON_OUTDIR}/observed-fqdns.txt"

        python3 - "${DISC_PROV}" "${RECON_OUTDIR}/domains-candidates.txt" \
            "${keep_providers}" "${DISC_PROVIDER_DENYLIST}" << 'PY'
import sys

prov, out, keep_providers, denylist = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
deny = set(denylist.split())
# Second-level public suffixes that need three labels for the registrable apex.
multi = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
         "org.au", "co.nz", "co.za", "com.br", "com.mx"}

def apex(name):
    parts = name.split(".")
    if len(parts) < 2:
        return None
    last2 = ".".join(parts[-2:])
    if last2 in multi and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2

cands = set()
with open(prov, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        name = line.split("\t", 1)[0].strip().lower()
        a = apex(name)
        if not a:
            continue
        if keep_providers != "1" and a in deny:
            continue
        cands.add(a)

with open(out, "w") as fh:
    fh.write("".join(c + "\n" for c in sorted(cands)))
print(len(cands))
PY
    }

    ###########################################################################
    # discovery_run
    # Purpose : Orchestrate the enabled techniques and raise the review gate.
    # Args    : $1 techniques CSV ("" = all)  $2 skip CSV
    ###########################################################################
    function discovery_run() {
        local only="${1:-}" skip="${2:-}"
        local IFS=$' \t\n' # split the space-separated technique list
        local all="scope rdns tls ike http smtp smb-ldap whois"
        DISC_DIR="${RECON_OUTDIR}/discovery"
        DISC_PROV="${DISC_DIR}/provenance.tsv"
        DISC_IPS="${DISC_DIR}/scope-ips.txt"
        DISC_HOSTS="${DISC_DIR}/scope-hosts.txt"
        mkdir -p "${DISC_DIR}"
        : > "${DISC_PROV}"

        local stats
        stats="$(scope_expand "${TARGETS_FILE}" "${RECON_MAX_HOSTS:-8192}" \
            "${DISC_IPS}" "${DISC_HOSTS}" 2> /dev/null)" || {
            LOG error "could not expand ${TARGETS_FILE}"
            return "${RECON_ERR_INPUT}"
        }
        LOG info "discovery: expanded scope to ${stats%% *} IP(s)"

        # Discovery techniques send live traffic; honor --dry-run by listing
        # the techniques that would run rather than probing the scope.
        if [[ "${RECON_DRY_RUN:-0}" -eq 1 ]]; then
            LOG info "dry-run: would run discovery techniques: ${all}"
            return 0
        fi

        local t
        for t in ${all}; do
            [[ -n "${only}" ]] && { in_list "${t}" "${only}" || continue; }
            [[ -n "${skip}" ]] && { in_list "${t}" "${skip}" && continue; }
            local fn="disc_${t//-/_}"
            declare -F "${fn}" > /dev/null 2>&1 && "${fn}"
        done

        local n
        n="$(disc_normalize)"
        LOG pass "discovery: ${n} candidate apex domain(s) written for review"
        if [[ "${n}" -gt 0 ]]; then
            RECON_AWAITING_REVIEW=1
        fi
        return 0
    }
fi
