#!/usr/bin/env bash

###############################################################################
# TASK: 00-validate
# DESCRIPTION: Validate input files and expand CIDR ranges
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# cidr_to_ips
# Expand a CIDR range into individual IP addresses
###############################################################################
cidr_to_ips() {
    local cidr=$1

    # Prefer ipcalc if available
    if command -v ipcalc > /dev/null 2>&1; then
        local network broadcast
        network=$(ipcalc -n "$cidr" | awk '/Network:/ {print $2}' | cut -d'/' -f1)
        broadcast=$(ipcalc -b "$cidr" | awk '/Broadcast:/ {print $2}')
        [[ -n "$network" && -n "$broadcast" ]] || return 1

        IFS=. read -r n1 n2 n3 n4 <<< "$network"
        IFS=. read -r b1 b2 b3 b4 <<< "$broadcast"

        for ((i1 = n1; i1 <= b1; i1++)); do
            for ((i2 = n2; i2 <= b2; i2++)); do
                for ((i3 = n3; i3 <= b3; i3++)); do
                    for ((i4 = n4; i4 <= b4; i4++)); do
                        echo "$i1.$i2.$i3.$i4"
                    done
                done
            done
        done
        return 0
    fi

    # Fallback: use nmap if present
    if command -v nmap > /dev/null 2>&1; then
        nmap -sL -n "$cidr" 2> /dev/null \
            | awk '/Nmap scan report/{print $NF}' \
            | sed 's/[()]//g'
        return 0
    fi

    # Pure Bash fallback
    local ip mask
    IFS=/ read -r ip mask <<< "$cidr"
    IFS=. read -r o1 o2 o3 o4 <<< "$ip"

    local ip_int=$(((o1 << 24) + (o2 << 16) + (o3 << 8) + o4))
    local mask_int=$((0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF))
    local network_int=$((ip_int & mask_int))
    local num_hosts=$((1 << (32 - mask)))

    for ((i = 0; i < num_hosts; i++)); do
        local addr=$((network_int + i))
        printf "%d.%d.%d.%d\n" \
            $(((addr >> 24) & 255)) \
            $(((addr >> 16) & 255)) \
            $(((addr >> 8) & 255)) \
            $((addr & 255))
    done
}

###############################################################################
# expand_targets_to_file
# Expand targets (IPs, CIDRs, FQDNs) and output to file
###############################################################################
expand_targets_to_file() {
    local source_file=$1
    local destination_file=$2
    local tmpfile

    if [[ -z "$source_file" || -z "$destination_file" ]]; then
        LOG error "expand_targets_to_file: source and destination required"
        return 1
    fi

    if [[ ! -f "$source_file" ]]; then
        LOG error "Source file not found: $source_file"
        return 1
    fi

    tmpfile=$(mktemp) || {
        LOG error "Failed to create temp file"
        return 1
    }

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | xargs)
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        # Check if CIDR
        if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
            cidr_to_ips "$line" >> "$tmpfile"
        elif [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$line" >> "$tmpfile"
        else
            # Assume FQDN
            echo "$line" >> "$tmpfile"
        fi
    done < "$source_file"

    sort -u "$tmpfile" > "$destination_file"
    rm -f "$tmpfile"

    return 0
}

###############################################################################
# run_task_00_validate
# Main task function
###############################################################################
run_task_00_validate() {
    LOG info "Starting input validation and expansion"

    local targets_file="${TARGETS_FILE}"
    local domains_file="${DOMAINS_FILE:-}"
    local recon_dir="${ENGAGEMENT_DIR}/RECON"
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"

    # Validate targets file
    if [[ ! -f "${targets_file}" ]]; then
        LOG error "Targets file not found: ${targets_file}"
        return 1
    fi

    # Create expanded targets file
    local expanded_targets="${recon_dir}/targets_expanded_${timestamp}.txt"
    LOG info "Expanding targets from: ${targets_file}"
    LOG info "Output: ${expanded_targets}"

    if ! expand_targets_to_file "${targets_file}" "${expanded_targets}"; then
        LOG error "Failed to expand targets"
        return 1
    fi

    local target_count
    target_count=$(wc -l < "${expanded_targets}")
    LOG pass "Expanded ${target_count} targets"

    # Export expanded targets for other tasks
    export EXPANDED_TARGETS_FILE="${expanded_targets}"

    # Validate domains file (if provided)
    if [[ -n "${domains_file}" ]]; then
        if [[ ! -f "${domains_file}" ]]; then
            LOG warn "Domains file specified but not found: ${domains_file}"
        else
            local domain_count
            domain_count=$(grep -v '^#' "${domains_file}" | grep -v '^[[:space:]]*$' | wc -l)
            LOG pass "Validated ${domain_count} domains"
            export VALIDATED_DOMAINS_FILE="${domains_file}"
        fi
    fi

    # Validate required tools
    LOG info "Validating required tools..."

    local -a required_tools=(
        "curl"
        "jq"
        "nmap"
    )

    local -a optional_tools=(
        "subfinder"
        "httpx"
        "nuclei"
        "testssl.sh"
        "dnsx"
        "asnmap"
    )

    local missing_required=()
    local missing_optional=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            missing_required+=("${tool}")
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            missing_optional+=("${tool}")
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        LOG error "Missing required tools: ${missing_required[*]}"
        return 1
    fi

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        LOG warn "Missing optional tools: ${missing_optional[*]}"
        LOG warn "Some features may be unavailable"
    fi

    LOG pass "Tool validation complete"
    LOG pass "Input validation task completed successfully"

    return 0
}
