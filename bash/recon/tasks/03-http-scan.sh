#!/usr/bin/env bash

###############################################################################
# TASK: 03-http-scan
# DESCRIPTION: HTTP/HTTPS reconnaissance with httpx and nuclei
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_03_http_scan
# Main task function
###############################################################################
run_task_03_http_scan() {
    LOG info "Starting HTTP/HTTPS reconnaissance"

    local targets_file="${EXPANDED_TARGETS_FILE:-${TARGETS_FILE}}"
    local recon_dir="${ENGAGEMENT_DIR}/RECON"
    local tee_dir="${ENGAGEMENT_DIR}/OUTPUT/TEE"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Create subdirectory for HTTP scan outputs
    local http_dir="${recon_dir}/http_scan_${timestamp}"
    mkdir -p "${http_dir}"

    LOG info "HTTP scan output directory: ${http_dir}"

    #===========================================================================
    # HTTPx - HTTP/HTTPS Service Probing
    #===========================================================================
    if command -v httpx > /dev/null 2>&1; then
        LOG info "Running httpx for HTTP/HTTPS service discovery..."

        # Prepare input (use nmap web services if available, otherwise targets)
        local httpx_input="${NMAP_WEB_SERVICES:-${targets_file}}"

        # Common web ports
        local web_ports="80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017"

        local httpx_out="${http_dir}/httpx.json"
        local httpx_tee="${tee_dir}/httpx_${timestamp}.tee"
        local httpx_urls="${http_dir}/live_urls.txt"

        httpx -l "${httpx_input}" \
            -p "${web_ports}" \
            -silent \
            -follow-redirects \
            -random-agent \
            -status-code \
            -title \
            -tech-detect \
            -method \
            -ip \
            -cname \
            -cdn \
            -probe \
            -timeout 10 \
            -retries 2 \
            -threads 50 \
            -json \
            -o "${httpx_out}" \
            2>&1 | tee -a "${httpx_tee}"

        if [[ -s "${httpx_out}" ]]; then
            # Extract live URLs
            jq -r '.url // empty' "${httpx_out}" | sort -u > "${httpx_urls}"

            local url_count
            url_count=$(wc -l < "${httpx_urls}")
            LOG pass "HTTPx found ${url_count} live web services"

            export HTTPX_LIVE_URLS="${httpx_urls}"

            # Extract interesting findings
            local interesting="${http_dir}/httpx_interesting.txt"
            {
                echo "=== HTTP/HTTPS Interesting Findings ==="
                echo ""

                # 4xx/5xx errors
                echo "--- Error Responses (4xx/5xx) ---"
                jq -r 'select(.status_code >= 400) | "\(.url) - \(.status_code) - \(.title // "N/A")"' "${httpx_out}" 2>/dev/null || echo "None"
                echo ""

                # Default credentials pages
                echo "--- Potential Login Pages ---"
                jq -r 'select(.title | test("login|sign in|admin|dashboard"; "i")) | "\(.url) - \(.title)"' "${httpx_out}" 2>/dev/null || echo "None"
                echo ""

                # Technologies detected
                echo "--- Technologies Detected ---"
                jq -r 'select(.technologies) | "\(.url): \(.technologies | join(", "))"' "${httpx_out}" 2>/dev/null || echo "None"
                echo ""

                # CDN detection
                echo "--- CDN Protected Services ---"
                jq -r 'select(.cdn == true) | "\(.url) - CDN detected"' "${httpx_out}" 2>/dev/null || echo "None"
            } > "${interesting}"

            LOG info "Interesting findings saved to: ${interesting}"
        else
            LOG warn "HTTPx did not find any live services"
        fi
    else
        LOG warn "HTTPx not installed, skipping HTTP probing"
    fi

    #===========================================================================
    # Nuclei - Vulnerability Scanning
    #===========================================================================
    if command -v nuclei > /dev/null 2>&1 && [[ -f "${HTTPX_LIVE_URLS:-}" ]]; then
        LOG info "Running Nuclei vulnerability scans..."

        # Define scan categories
        local -a nuclei_scans=(
            "cves:CVE Detection"
            "vulnerabilities:Known Vulnerabilities"
            "exposures:Sensitive Exposures"
            "misconfigurations:Misconfigurations"
            "default-logins:Default Credentials"
            "exposed-panels:Exposed Panels"
            "takeovers:Subdomain Takeovers"
            "technologies:Technology Detection"
        )

        # Run each scan category
        for scan in "${nuclei_scans[@]}"; do
            local tag="${scan%%:*}"
            local desc="${scan#*:}"

            LOG info "Nuclei scan: ${desc} (${tag})"

            local nuclei_out="${http_dir}/nuclei_${tag}.txt"
            local nuclei_json="${http_dir}/nuclei_${tag}.json"
            local nuclei_tee="${tee_dir}/nuclei_${tag}_${timestamp}.tee"

            nuclei -l "${HTTPX_LIVE_URLS}" \
                -tags "${tag}" \
                -severity critical,high,medium,low,info \
                -rate-limit 150 \
                -bulk-size 50 \
                -timeout 10 \
                -retries 2 \
                -stats \
                -silent \
                -nc \
                -o "${nuclei_out}" \
                -json-export "${nuclei_json}" \
                2>&1 | tee -a "${nuclei_tee}"

            if [[ -s "${nuclei_out}" ]]; then
                local finding_count
                finding_count=$(wc -l < "${nuclei_out}")
                LOG pass "Nuclei ${tag}: ${finding_count} findings"
            else
                LOG info "Nuclei ${tag}: No findings"
            fi
        done

        # Combine all nuclei findings
        local all_findings="${http_dir}/nuclei_all_findings.txt"
        local all_json="${http_dir}/nuclei_all_findings.json"

        cat "${http_dir}"/nuclei_*.txt > "${all_findings}" 2>/dev/null || true
        jq -s 'add // []' "${http_dir}"/nuclei_*.json > "${all_json}" 2>/dev/null || true

        if [[ -s "${all_findings}" ]]; then
            local total_findings
            total_findings=$(wc -l < "${all_findings}")
            LOG pass "Total Nuclei findings: ${total_findings}"

            # Generate severity summary
            local severity_summary="${http_dir}/nuclei_severity_summary.txt"
            {
                echo "=== Nuclei Severity Summary ==="
                echo ""
                jq -r '.severity' "${all_json}" 2>/dev/null | sort | uniq -c | sort -rn || echo "Error generating summary"
            } > "${severity_summary}"

            LOG info "Severity summary: ${severity_summary}"
        fi
    else
        LOG info "Skipping Nuclei (not installed or no live URLs)"
    fi

    #===========================================================================
    # Screenshot Capture (if aquatone/gowitness available)
    #===========================================================================
    if command -v gowitness > /dev/null 2>&1 && [[ -f "${HTTPX_LIVE_URLS:-}" ]]; then
        LOG info "Capturing screenshots with gowitness..."

        local screenshot_dir="${http_dir}/screenshots"
        mkdir -p "${screenshot_dir}"

        gowitness file \
            --source "${HTTPX_LIVE_URLS}" \
            --destination "${screenshot_dir}" \
            --timeout 15 \
            --threads 10 \
            2>&1 | tee -a "${tee_dir}/gowitness_${timestamp}.tee"

        if [[ -n "$(ls -A "${screenshot_dir}" 2>/dev/null)" ]]; then
            LOG pass "Screenshots captured to: ${screenshot_dir}"
        else
            LOG warn "Screenshot capture did not produce outputs"
        fi
    else
        LOG info "Skipping screenshot capture (gowitness not installed or no URLs)"
    fi

    #===========================================================================
    # Web Technology Fingerprinting (if whatweb available)
    #===========================================================================
    if command -v whatweb > /dev/null 2>&1 && [[ -f "${HTTPX_LIVE_URLS:-}" ]]; then
        LOG info "Running WhatWeb for technology fingerprinting..."

        local whatweb_out="${http_dir}/whatweb.json"
        local whatweb_tee="${tee_dir}/whatweb_${timestamp}.tee"

        whatweb \
            --input-file="${HTTPX_LIVE_URLS}" \
            --log-json="${whatweb_out}" \
            --max-threads=50 \
            --wait=1 \
            --open-timeout=10 \
            --read-timeout=15 \
            2>&1 | tee -a "${whatweb_tee}"

        if [[ -s "${whatweb_out}" ]]; then
            LOG pass "WhatWeb fingerprinting completed"
        else
            LOG warn "WhatWeb did not produce output"
        fi
    else
        LOG info "Skipping WhatWeb (not installed or no URLs)"
    fi

    #===========================================================================
    # Generate Summary Report
    #===========================================================================
    local summary_file="${http_dir}/summary.txt"

    {
        echo "HTTP/HTTPS Reconnaissance Summary"
        echo "Generated: $(date)"
        echo ""

        if [[ -f "${HTTPX_LIVE_URLS}" ]]; then
            echo "Live Web Services: $(wc -l < "${HTTPX_LIVE_URLS}")"
        fi

        if [[ -f "${http_dir}/nuclei_all_findings.txt" ]]; then
            echo "Total Nuclei Findings: $(wc -l < "${http_dir}/nuclei_all_findings.txt")"
        fi

        echo ""
        echo "Outputs:"
        find "${http_dir}" -type f -name "*.json" -o -name "*.txt" | while read -r file; do
            echo "  - ${file}"
        done
    } > "${summary_file}"

    LOG pass "HTTP/HTTPS reconnaissance completed"
    LOG info "Results saved to: ${http_dir}"
    LOG info "Summary: ${summary_file}"

    return 0
}
