#!/usr/bin/env bash

###############################################################################
# TASK: 02-nmap
# DESCRIPTION: Network mapping and port scanning with Nmap
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_02_nmap
# Main task function
###############################################################################
run_task_02_nmap() {
    LOG info "Starting Nmap reconnaissance"

    local targets_file="${EXPANDED_TARGETS_FILE:-${TARGETS_FILE}}"
    local recon_dir="${ENGAGEMENT_DIR}/RECON"
    local tee_dir="${ENGAGEMENT_DIR}/OUTPUT/TEE"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Create subdirectory for Nmap outputs
    local nmap_dir="${recon_dir}/nmap_${timestamp}"
    mkdir -p "${nmap_dir}"

    LOG info "Nmap output directory: ${nmap_dir}"

    # Verify nmap is installed
    if ! command -v nmap > /dev/null 2>&1; then
        LOG error "Nmap is not installed"
        return 1
    fi

    #===========================================================================
    # Quick Host Discovery Scan
    #===========================================================================
    LOG info "Running host discovery scan..."

    local discovery_out="${nmap_dir}/01_discovery"
    local discovery_tee="${tee_dir}/nmap_discovery_${timestamp}.tee"

    nmap -sn \
        -PE -PP -PM \
        -PS21,22,23,25,80,113,443,31339 \
        -PA80,113,443 \
        -iL "${targets_file}" \
        -oA "${discovery_out}" \
        --stats-every 30s \
        2>&1 | tee -a "${discovery_tee}"

    if [[ -f "${discovery_out}.gnmap" ]]; then
        # Extract live hosts
        local live_hosts="${nmap_dir}/live_hosts.txt"
        awk '/Status: Up/ {print $2}' "${discovery_out}.gnmap" | sort -u > "${live_hosts}"

        local live_count
        live_count=$(wc -l < "${live_hosts}")
        LOG pass "Host discovery found ${live_count} live hosts"

        export NMAP_LIVE_HOSTS="${live_hosts}"
    else
        LOG warn "Host discovery did not complete successfully"
        export NMAP_LIVE_HOSTS="${targets_file}"
    fi

    #===========================================================================
    # Top Ports Scan (Fast)
    #===========================================================================
    LOG info "Running top 1000 ports scan..."

    local top_ports_out="${nmap_dir}/02_top_ports"
    local top_ports_tee="${tee_dir}/nmap_top_ports_${timestamp}.tee"

    nmap -Pn \
        --top-ports 1000 \
        -sV \
        --version-intensity 5 \
        -iL "${NMAP_LIVE_HOSTS}" \
        -oA "${top_ports_out}" \
        --stats-every 30s \
        2>&1 | tee -a "${top_ports_tee}"

    if [[ -f "${top_ports_out}.xml" ]]; then
        LOG pass "Top ports scan completed"
    else
        LOG warn "Top ports scan did not complete successfully"
    fi

    #===========================================================================
    # Full TCP Scan (if enabled via config)
    #===========================================================================
    if [[ "${NMAP_FULL_TCP_SCAN:-false}" == "true" ]]; then
        LOG info "Running full TCP port scan (this may take a while)..."

        local full_tcp_out="${nmap_dir}/03_full_tcp"
        local full_tcp_tee="${tee_dir}/nmap_full_tcp_${timestamp}.tee"

        nmap -Pn \
            -p- \
            -sS \
            -T4 \
            -iL "${NMAP_LIVE_HOSTS}" \
            -oA "${full_tcp_out}" \
            --stats-every 30s \
            2>&1 | tee -a "${full_tcp_tee}"

        if [[ -f "${full_tcp_out}.xml" ]]; then
            LOG pass "Full TCP scan completed"
        else
            LOG warn "Full TCP scan did not complete successfully"
        fi
    else
        LOG info "Skipping full TCP scan (not enabled)"
    fi

    #===========================================================================
    # UDP Scan on Common Ports
    #===========================================================================
    if [[ "${NMAP_UDP_SCAN:-false}" == "true" ]]; then
        LOG info "Running UDP port scan on common ports..."

        local udp_out="${nmap_dir}/04_udp_common"
        local udp_tee="${tee_dir}/nmap_udp_${timestamp}.tee"

        # Common UDP ports
        local udp_ports="53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"

        nmap -Pn \
            -sU \
            -p "${udp_ports}" \
            --version-intensity 0 \
            -iL "${NMAP_LIVE_HOSTS}" \
            -oA "${udp_out}" \
            --stats-every 30s \
            2>&1 | tee -a "${udp_tee}"

        if [[ -f "${udp_out}.xml" ]]; then
            LOG pass "UDP scan completed"
        else
            LOG warn "UDP scan did not complete successfully"
        fi
    else
        LOG info "Skipping UDP scan (not enabled)"
    fi

    #===========================================================================
    # Service and OS Detection Scan
    #===========================================================================
    LOG info "Running service and OS detection scan..."

    local service_os_out="${nmap_dir}/05_service_os_detection"
    local service_os_tee="${tee_dir}/nmap_service_os_${timestamp}.tee"

    nmap -Pn \
        -sV \
        -O \
        --osscan-guess \
        --version-all \
        -iL "${NMAP_LIVE_HOSTS}" \
        -oA "${service_os_out}" \
        --stats-every 30s \
        2>&1 | tee -a "${service_os_tee}"

    if [[ -f "${service_os_out}.xml" ]]; then
        LOG pass "Service and OS detection completed"
    else
        LOG warn "Service and OS detection did not complete successfully"
    fi

    #===========================================================================
    # NSE Vulnerability Scan (if enabled)
    #===========================================================================
    if [[ "${NMAP_VULN_SCAN:-false}" == "true" ]]; then
        LOG info "Running NSE vulnerability scan..."

        local vuln_out="${nmap_dir}/06_nse_vuln"
        local vuln_tee="${tee_dir}/nmap_vuln_${timestamp}.tee"

        nmap -Pn \
            -sV \
            --script vuln,safe,default \
            --script-timeout 10m \
            -iL "${NMAP_LIVE_HOSTS}" \
            -oA "${vuln_out}" \
            --stats-every 30s \
            2>&1 | tee -a "${vuln_tee}"

        if [[ -f "${vuln_out}.xml" ]]; then
            LOG pass "NSE vulnerability scan completed"
        else
            LOG warn "NSE vulnerability scan did not complete successfully"
        fi
    else
        LOG info "Skipping NSE vulnerability scan (not enabled)"
    fi

    #===========================================================================
    # Extract Open Ports for Other Tools
    #===========================================================================
    LOG info "Extracting open ports for follow-up tasks..."

    # Extract hosts with open ports
    local open_ports_file="${nmap_dir}/hosts_with_open_ports.txt"

    if [[ -f "${top_ports_out}.gnmap" ]]; then
        awk '/Ports:/ {print $2}' "${top_ports_out}.gnmap" | sort -u > "${open_ports_file}"
        export NMAP_HOSTS_WITH_OPEN_PORTS="${open_ports_file}"

        local hosts_with_ports
        hosts_with_ports=$(wc -l < "${open_ports_file}")
        LOG pass "Found ${hosts_with_ports} hosts with open ports"
    fi

    # Extract web service URLs (HTTP/HTTPS)
    local web_services_file="${nmap_dir}/web_services.txt"
    if [[ -f "${top_ports_out}.gnmap" ]]; then
        # Extract HTTP services
        grep -oP '\d+/open/tcp//http//' "${top_ports_out}.gnmap" 2>/dev/null | while read -r line; do
            local ip port
            ip=$(echo "${line}" | awk '{print $2}')
            port=$(echo "${line}" | grep -oP '\d+(?=/open)')
            echo "http://${ip}:${port}"
        done > "${web_services_file}"

        # Extract HTTPS services
        grep -oP '\d+/open/tcp//https//' "${top_ports_out}.gnmap" 2>/dev/null | while read -r line; do
            local ip port
            ip=$(echo "${line}" | awk '{print $2}')
            port=$(echo "${line}" | grep -oP '\d+(?=/open)')
            echo "https://${ip}:${port}"
        done >> "${web_services_file}"

        if [[ -s "${web_services_file}" ]]; then
            sort -u "${web_services_file}" -o "${web_services_file}"
            export NMAP_WEB_SERVICES="${web_services_file}"

            local web_count
            web_count=$(wc -l < "${web_services_file}")
            LOG pass "Identified ${web_count} web services"
        fi
    fi

    #===========================================================================
    # Generate Summary Report
    #===========================================================================
    local summary_file="${nmap_dir}/summary.txt"

    {
        echo "Nmap Reconnaissance Summary"
        echo "Generated: $(date)"
        echo "Target file: ${targets_file}"
        echo ""

        if [[ -f "${NMAP_LIVE_HOSTS}" ]]; then
            echo "Live Hosts: $(wc -l < "${NMAP_LIVE_HOSTS}")"
        fi

        if [[ -f "${NMAP_HOSTS_WITH_OPEN_PORTS}" ]]; then
            echo "Hosts with Open Ports: $(wc -l < "${NMAP_HOSTS_WITH_OPEN_PORTS}")"
        fi

        if [[ -f "${NMAP_WEB_SERVICES}" ]]; then
            echo "Web Services: $(wc -l < "${NMAP_WEB_SERVICES}")"
        fi

        echo ""
        echo "Scan Outputs:"
        find "${nmap_dir}" -name "*.xml" -exec echo "  - {}" \;
    } > "${summary_file}"

    LOG pass "Nmap reconnaissance completed"
    LOG info "Results saved to: ${nmap_dir}"
    LOG info "Summary: ${summary_file}"

    return 0
}
