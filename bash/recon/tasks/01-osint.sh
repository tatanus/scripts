#!/usr/bin/env bash

###############################################################################
# TASK: 01-osint
# DESCRIPTION: OSINT reconnaissance using subfinder, dnsx, asnmap, cdncheck
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_01_osint
# Main task function
###############################################################################
run_task_01_osint() {
    LOG info "Starting OSINT reconnaissance"

    local targets_file="${EXPANDED_TARGETS_FILE:-${TARGETS_FILE}}"
    local domains_file="${VALIDATED_DOMAINS_FILE:-${DOMAINS_FILE}}"
    local recon_dir="${ENGAGEMENT_DIR}/RECON"
    local tee_dir="${ENGAGEMENT_DIR}/OUTPUT/TEE"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Create subdirectory for OSINT outputs
    local osint_dir="${recon_dir}/osint_${timestamp}"
    mkdir -p "${osint_dir}"

    LOG info "OSINT output directory: ${osint_dir}"

    #===========================================================================
    # Subdomain Enumeration with Subfinder
    #===========================================================================
    if command -v subfinder > /dev/null 2>&1 && [[ -f "${domains_file}" ]]; then
        LOG info "Running subfinder for subdomain discovery..."

        local subfinder_out="${osint_dir}/subfinder.json"
        local subfinder_tee="${tee_dir}/subfinder_${timestamp}.tee"

        subfinder -dL "${domains_file}" \
            -all \
            -recursive \
            -v \
            -oJ \
            -o "${subfinder_out}" \
            2>&1 | tee -a "${subfinder_tee}"

        if [[ -s "${subfinder_out}" ]]; then
            local subdomain_count
            subdomain_count=$(jq -s 'length' "${subfinder_out}")
            LOG pass "Subfinder found ${subdomain_count} subdomains"

            # Extract subdomains to text file for other tools
            jq -r '.host // .domain // empty' "${subfinder_out}" \
                | sort -u > "${osint_dir}/subdomains.txt"
        else
            LOG warn "Subfinder did not produce output"
        fi
    else
        LOG info "Skipping subfinder (not installed or no domains file)"
    fi

    #===========================================================================
    # DNS Resolution with DNSx
    #===========================================================================
    if command -v dnsx > /dev/null 2>&1; then
        LOG info "Running dnsx for DNS resolution..."

        # Prepare input file (subdomains if available, otherwise targets)
        local dnsx_input="${osint_dir}/subdomains.txt"
        if [[ ! -s "${dnsx_input}" ]]; then
            dnsx_input="${targets_file}"
        fi

        local dnsx_out="${osint_dir}/dnsx.json"
        local dnsx_tee="${tee_dir}/dnsx_${timestamp}.tee"

        dnsx -l "${dnsx_input}" \
            -a -aaaa -cname -mx -ns -txt -srv -ptr \
            -cdn \
            -asn \
            -resp \
            -json \
            -o "${dnsx_out}" \
            2>&1 | tee -a "${dnsx_tee}"

        if [[ -s "${dnsx_out}" ]]; then
            local resolved_count
            resolved_count=$(jq -s 'length' "${dnsx_out}")
            LOG pass "DNSx resolved ${resolved_count} records"
        else
            LOG warn "DNSx did not produce output"
        fi
    else
        LOG info "Skipping dnsx (not installed)"
    fi

    #===========================================================================
    # ASN Mapping with ASNMap
    #===========================================================================
    if command -v asnmap > /dev/null 2>&1; then
        LOG info "Running asnmap for ASN discovery..."

        local asnmap_out="${osint_dir}/asnmap.json"
        local asnmap_tee="${tee_dir}/asnmap_${timestamp}.tee"

        asnmap -l "${targets_file}" \
            -v \
            -json \
            -o "${asnmap_out}" \
            2>&1 | tee -a "${asnmap_tee}"

        if [[ -s "${asnmap_out}" ]]; then
            LOG pass "ASNMap output saved"
        else
            LOG warn "ASNMap did not produce output"
        fi
    else
        LOG info "Skipping asnmap (not installed)"
    fi

    #===========================================================================
    # CDN Detection with CDNCheck
    #===========================================================================
    if command -v cdncheck > /dev/null 2>&1; then
        LOG info "Running cdncheck for CDN detection..."

        local cdncheck_out="${osint_dir}/cdncheck.jsonl"
        local cdncheck_tee="${tee_dir}/cdncheck_${timestamp}.tee"

        cdncheck -l "${targets_file}" \
            -resp \
            -json \
            -o "${cdncheck_out}" \
            2>&1 | tee -a "${cdncheck_tee}"

        if [[ -s "${cdncheck_out}" ]]; then
            LOG pass "CDNCheck output saved"
        else
            LOG warn "CDNCheck did not produce output"
        fi
    else
        LOG info "Skipping cdncheck (not installed)"
    fi

    #===========================================================================
    # Microsoft 365 / Azure AD Reconnaissance (if M365 script exists)
    #===========================================================================
    local m365_script="${SCRIPT_DIR}/m365_recon_NG.sh"
    if [[ -f "${m365_script}" ]] && [[ -f "${domains_file}" ]]; then
        LOG info "Running Microsoft 365 reconnaissance..."

        local m365_out="${osint_dir}/m365_recon.json"

        # Run M365 recon for each domain
        while IFS= read -r domain || [[ -n "$domain" ]]; do
            domain=$(echo "$domain" | xargs)
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue

            LOG info "M365 recon for domain: ${domain}"

            if bash "${m365_script}" "${domain}" "${m365_out}.${domain}" 2>&1 | tee -a "${tee_dir}/m365_${domain}_${timestamp}.tee"; then
                LOG pass "M365 recon completed for ${domain}"
            else
                LOG warn "M365 recon failed for ${domain}"
            fi
        done < "${domains_file}"
    else
        LOG info "Skipping M365 reconnaissance (script not found or no domains)"
    fi

    #===========================================================================
    # Certificate Transparency (crt.sh)
    #===========================================================================
    if [[ -f "${domains_file}" ]]; then
        LOG info "Querying certificate transparency logs..."

        local crtsh_out="${osint_dir}/crtsh.json"

        while IFS= read -r domain || [[ -n "$domain" ]]; do
            domain=$(echo "$domain" | xargs)
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue

            LOG info "Querying crt.sh for: ${domain}"

            curl -sS --connect-timeout 10 --max-time 30 \
                "https://crt.sh/?q=${domain}&output=json" \
                2>/dev/null >> "${crtsh_out}.${domain}" || {
                LOG warn "crt.sh query failed for ${domain}"
            }
        done < "${domains_file}"

        # Combine all crt.sh results
        if compgen -G "${crtsh_out}.*" > /dev/null; then
            jq -s 'add' "${crtsh_out}".* > "${crtsh_out}" 2>/dev/null || true
            rm -f "${crtsh_out}".*
            LOG pass "Certificate transparency data collected"
        fi
    fi

    #===========================================================================
    # Generate Summary
    #===========================================================================
    local summary_file="${osint_dir}/summary.txt"

    {
        echo "OSINT Reconnaissance Summary"
        echo "Generated: $(date)"
        echo "Target file: ${targets_file}"
        echo "Domains file: ${domains_file:-N/A}"
        echo ""
        echo "Outputs:"
        find "${osint_dir}" -type f -exec echo "  - {}" \;
    } > "${summary_file}"

    LOG pass "OSINT reconnaissance completed"
    LOG info "Results saved to: ${osint_dir}"
    LOG info "Summary: ${summary_file}"

    return 0
}
