#!/usr/bin/env bash

###############################################################################
# TASK: 04-testssl
# DESCRIPTION: SSL/TLS security testing with testssl.sh
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_04_testssl
# Main task function
###############################################################################
run_task_04_testssl() {
    LOG info "Starting SSL/TLS security testing"

    local recon_dir="${ENGAGEMENT_DIR}/RECON"
    local tee_dir="${ENGAGEMENT_DIR}/OUTPUT/TEE"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Create subdirectory for testssl outputs
    local testssl_dir="${recon_dir}/testssl_${timestamp}"
    mkdir -p "${testssl_dir}"

    LOG info "TestSSL output directory: ${testssl_dir}"

    # Check if testssl.sh is available
    local testssl_cmd=""
    if command -v testssl.sh > /dev/null 2>&1; then
        testssl_cmd="testssl.sh"
    elif command -v testssl > /dev/null 2>&1; then
        testssl_cmd="testssl"
    elif [[ -x "/usr/local/bin/testssl.sh" ]]; then
        testssl_cmd="/usr/local/bin/testssl.sh"
    elif [[ -x "${HOME}/tools/testssl.sh/testssl.sh" ]]; then
        testssl_cmd="${HOME}/tools/testssl.sh/testssl.sh"
    else
        LOG error "testssl.sh not found in PATH or common locations"
        LOG info "Install with: git clone --depth 1 https://github.com/drwetter/testssl.sh.git"
        return 1
    fi

    LOG info "Using testssl command: ${testssl_cmd}"

    #===========================================================================
    # Prepare Target List
    #===========================================================================
    local targets_file=""

    # Prefer httpx URLs with HTTPS
    if [[ -f "${HTTPX_LIVE_URLS:-}" ]]; then
        targets_file="${testssl_dir}/https_targets.txt"
        grep '^https://' "${HTTPX_LIVE_URLS}" > "${targets_file}" || true
    fi

    # Fallback to nmap web services
    if [[ ! -s "${targets_file}" ]] && [[ -f "${NMAP_WEB_SERVICES:-}" ]]; then
        targets_file="${testssl_dir}/https_targets.txt"
        grep '^https://' "${NMAP_WEB_SERVICES}" > "${targets_file}" || true
    fi

    # Last resort: scan expanded targets on port 443
    if [[ ! -s "${targets_file}" ]]; then
        targets_file="${EXPANDED_TARGETS_FILE:-${TARGETS_FILE}}"
        LOG warn "No HTTPS services identified, will test all targets on port 443"
    fi

    if [[ ! -f "${targets_file}" ]]; then
        LOG error "No targets file available for SSL/TLS testing"
        return 1
    fi

    local target_count
    target_count=$(wc -l < "${targets_file}")
    LOG info "Testing ${target_count} targets for SSL/TLS vulnerabilities"

    #===========================================================================
    # Run testssl.sh on Each Target
    #===========================================================================
    local success_count=0
    local fail_count=0
    local skip_count=0

    # Create results directory
    local results_dir="${testssl_dir}/results"
    mkdir -p "${results_dir}"

    while IFS= read -r target || [[ -n "${target}" ]]; do
        target=$(echo "${target}" | xargs)
        [[ -z "${target}" || "${target}" =~ ^# ]] && continue

        # Extract host and port from URL if needed
        local test_target="${target}"
        if [[ "${target}" =~ ^https?:// ]]; then
            # Extract host:port from URL
            test_target=$(echo "${target}" | sed -E 's|https?://([^/]+).*|\1|')
        fi

        # Add default port if not specified
        if [[ ! "${test_target}" =~ :[0-9]+$ ]]; then
            test_target="${test_target}:443"
        fi

        LOG info "Testing: ${test_target}"

        # Sanitize filename
        local safe_name
        safe_name=$(echo "${test_target}" | sed 's/[^a-zA-Z0-9._-]/_/g')

        local output_base="${results_dir}/${safe_name}"
        local output_txt="${output_base}.txt"
        local output_json="${output_base}.json"
        local output_html="${output_base}.html"
        local test_tee="${tee_dir}/testssl_${safe_name}_${timestamp}.tee"

        # Run testssl.sh with comprehensive checks
        if timeout 600 "${testssl_cmd}" \
            --parallel \
            --fast \
            --warnings batch \
            --openssl-timeout 10 \
            --hints \
            --severity MEDIUM \
            --file "${output_txt}" \
            --jsonfile "${output_json}" \
            --htmlfile "${output_html}" \
            "${test_target}" \
            2>&1 | tee -a "${test_tee}"; then

            ((success_count++))
            LOG pass "TestSSL completed for ${test_target}"

            # Check for critical findings
            if [[ -f "${output_json}" ]]; then
                local critical_findings
                critical_findings=$(jq -r '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' "${output_json}" 2>/dev/null || echo "0")

                if [[ "${critical_findings}" -gt 0 ]]; then
                    LOG warn "${test_target}: ${critical_findings} critical/high severity findings"
                fi
            fi
        else
            local exit_code=$?
            ((fail_count++))

            if [[ ${exit_code} -eq 124 ]]; then
                LOG warn "TestSSL timed out for ${test_target}"
            else
                LOG warn "TestSSL failed for ${test_target} (exit code: ${exit_code})"
            fi
        fi

        # Rate limiting to avoid overwhelming targets
        sleep 2

    done < "${targets_file}"

    #===========================================================================
    # Aggregate Results
    #===========================================================================
    LOG info "Aggregating SSL/TLS test results..."

    local aggregate_json="${testssl_dir}/aggregate_results.json"
    local aggregate_summary="${testssl_dir}/aggregate_summary.txt"

    # Combine all JSON results
    if compgen -G "${results_dir}/*.json" > /dev/null 2>&1; then
        jq -s 'add // []' "${results_dir}"/*.json > "${aggregate_json}" 2>/dev/null || {
            LOG warn "Failed to aggregate JSON results"
        }
    fi

    # Generate summary report
    {
        echo "=========================================="
        echo "SSL/TLS Security Testing Summary"
        echo "=========================================="
        echo "Generated: $(date)"
        echo ""
        echo "Targets Tested: ${target_count}"
        echo "Successful: ${success_count}"
        echo "Failed: ${fail_count}"
        echo "Skipped: ${skip_count}"
        echo ""

        if [[ -f "${aggregate_json}" ]]; then
            echo "=== Severity Distribution ==="
            jq -r '.[] | select(.severity) | .severity' "${aggregate_json}" 2>/dev/null \
                | sort | uniq -c | sort -rn || echo "Error processing results"
            echo ""

            echo "=== Critical Vulnerabilities ==="
            jq -r '.[] | select(.severity == "CRITICAL") | "\(.id): \(.finding)"' "${aggregate_json}" 2>/dev/null \
                || echo "None found"
            echo ""

            echo "=== High Severity Findings ==="
            jq -r '.[] | select(.severity == "HIGH") | "\(.id): \(.finding)"' "${aggregate_json}" 2>/dev/null \
                || echo "None found"
            echo ""

            echo "=== Weak Ciphers Detected ==="
            jq -r '.[] | select(.id | test("cipher")) | select(.severity == "HIGH" or .severity == "CRITICAL") | "\(.ip): \(.finding)"' "${aggregate_json}" 2>/dev/null \
                || echo "None found"
            echo ""

            echo "=== Certificate Issues ==="
            jq -r '.[] | select(.id | test("cert")) | select(.severity != "OK" and .severity != "INFO") | "\(.ip): \(.finding)"' "${aggregate_json}" 2>/dev/null \
                || echo "None found"
            echo ""

            echo "=== Protocol Vulnerabilities ==="
            jq -r '.[] | select(.id | test("heartbleed|ccs|ticketbleed|robot|breach|crime|poodle")) | "\(.ip): \(.id) - \(.finding)"' "${aggregate_json}" 2>/dev/null \
                || echo "None found"
        fi

    } > "${aggregate_summary}"

    LOG info "Aggregate summary: ${aggregate_summary}"

    # Display summary to user
    if [[ -f "${aggregate_summary}" ]]; then
        echo ""
        cat "${aggregate_summary}"
        echo ""
    fi

    #===========================================================================
    # Extract Vulnerable Hosts
    #===========================================================================
    local vulnerable_hosts="${testssl_dir}/vulnerable_hosts.txt"

    if [[ -f "${aggregate_json}" ]]; then
        jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH") | .ip' "${aggregate_json}" 2>/dev/null \
            | sort -u > "${vulnerable_hosts}" || true

        if [[ -s "${vulnerable_hosts}" ]]; then
            local vuln_count
            vuln_count=$(wc -l < "${vulnerable_hosts}")
            LOG warn "Found ${vuln_count} hosts with critical/high severity SSL/TLS issues"
            export TESTSSL_VULNERABLE_HOSTS="${vulnerable_hosts}"
        fi
    fi

    #===========================================================================
    # Final Summary
    #===========================================================================
    LOG pass "SSL/TLS security testing completed"
    LOG info "Results saved to: ${testssl_dir}"
    LOG info "Summary report: ${aggregate_summary}"

    if [[ ${fail_count} -gt 0 ]]; then
        LOG warn "${fail_count} targets failed SSL/TLS testing"
    fi

    return 0
}
