#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: SPOONMAP_DIR / SPOONMAP_OUT_DIR / TARGETS_FILE / EXCLUDES_FILE /
# PORTS_DIR / LIVE_HOSTS_FILE / IPPORTS_FILE / TEE_DIR and the LOG /
# internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 04-spoonmap
# DESCRIPTION: Run TrustedSec spoonmap (https://github.com/trustedsec/spoonmap)
#              against targets.txt. spoonmap reads config.json from its own
#              install directory, so we (re)generate that file from the
#              engagement inputs, run the scan, then parse the nmap/masscan
#              results into the shared hosts.txt and ipports.txt consumed by
#              later tasks.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

# Default internal port set (mirrors pentest_setup's spoonmap.config.json).
readonly SPOONMAP_PORTS='"21","22","23","25","53","80","111","135","139","389","443","445","1433","3306","3389","5432","5900","5985","5986","8000","8080","8443","8888"'

###############################################################################
# _write_spoonmap_config
# Regenerate <spoonmap>/config.json pointing at the engagement inputs/outputs.
###############################################################################
function _write_spoonmap_config() {
    local cfg="${SPOONMAP_DIR}/config.json"
    local excl=""
    [[ -s "${EXCLUDES_FILE}" ]] && excl="${EXCLUDES_FILE}"

    cat > "${cfg}" << EOF
{
    "scan_type" : "Custom Port Scan",
    "dest_ports" : [${SPOONMAP_DEST_PORTS:-${SPOONMAP_PORTS}}],
    "banner_scan" : "True",
    "target_scan" : "Internal",
    "max_rate" : "${SPOONMAP_MAX_RATE:-2000}",
    "target_file" : "${TARGETS_FILE}",
    "exclusions_file" : "${excl}",
    "output_path" : "${SPOONMAP_OUT_DIR}/"
}
EOF
    LOG info "Wrote spoonmap config: ${cfg}"
}

###############################################################################
# _parse_scan_results
# Parse open ip:port pairs from any nmap .gnmap / .xml under the spoonmap
# output tree (and PORTS_DIR), writing IPPORTS_FILE + LIVE_HOSTS_FILE.
###############################################################################
function _parse_scan_results() {
    local tmp
    tmp="$(mktemp)"

    local f
    # Greppable nmap output.
    while IFS= read -r f; do
        # Host: <ip> () Ports: 80/open/tcp//http, 443/open/tcp//https
        awk '
            /Ports:/ {
                ip = $2
                n = split($0, parts, "Ports:")
                m = split(parts[2], ports, ",")
                for (i = 1; i <= m; i++) {
                    if (ports[i] ~ /open/) {
                        split(ports[i], f, "/")
                        gsub(/[[:space:]]/, "", f[1])
                        if (f[1] != "") print ip ":" f[1]
                    }
                }
            }
        ' "${f}" >> "${tmp}" 2> /dev/null || true
    done < <(find "${SPOONMAP_OUT_DIR}" "${PORTS_DIR}" -type f -name '*.gnmap' 2> /dev/null)

    # Nmap XML output.
    while IFS= read -r f; do
        awk '
            /<address addr=/ {
                if (match($0, /addr="[^"]+"/)) {
                    a = substr($0, RSTART+6, RLENGTH-7)
                    if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip = a
                }
            }
            /<port / {
                if (match($0, /portid="[0-9]+"/)) {
                    port = substr($0, RSTART+8, RLENGTH-9)
                }
            }
            /state state="open"/ {
                if (ip != "" && port != "") print ip ":" port
            }
        ' "${f}" >> "${tmp}" 2> /dev/null || true
    done < <(find "${SPOONMAP_OUT_DIR}" "${PORTS_DIR}" -type f -name '*.xml' 2> /dev/null)

    mkdir -p "$(dirname "${IPPORTS_FILE}")" "$(dirname "${LIVE_HOSTS_FILE}")"
    sort -u "${tmp}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$' > "${IPPORTS_FILE}" || true
    cut -d: -f1 "${IPPORTS_FILE}" | sort -u > "${LIVE_HOSTS_FILE}" || true
    rm -f "${tmp}"
}

###############################################################################
# run_task_04_spoonmap
###############################################################################
function run_task_04_spoonmap() {
    local spoonmap_py="${SPOONMAP_DIR}/spoonmap.py"

    if internal::is_dry_run; then
        LOG info "[DRY RUN] would write ${SPOONMAP_DIR}/config.json (targets: ${TARGETS_FILE})"
        LOG info "[DRY RUN] would run: (cd ${SPOONMAP_DIR} && python3 spoonmap.py)"
        LOG info "[DRY RUN] would parse results from ${SPOONMAP_OUT_DIR} -> ${IPPORTS_FILE}"
        return 0
    fi

    if [[ ! -f "${spoonmap_py}" ]]; then
        LOG error "spoonmap not found at ${spoonmap_py} (install via pentest_setup)"
        return 1
    fi
    internal::require_cmd python3 || return 1

    mkdir -p "${SPOONMAP_OUT_DIR}"
    _write_spoonmap_config

    local tee_log
    tee_log="${TEE_DIR}/spoonmap_$(date +%Y%m%d_%H%M%S).tee"
    LOG info "Running spoonmap (output -> ${SPOONMAP_OUT_DIR})"
    # spoonmap resolves relative paths against its own directory.
    (cd "${SPOONMAP_DIR}" && python3 spoonmap.py) 2>&1 | tee -a "${tee_log}" || {
        LOG warn "spoonmap exited non-zero; attempting to parse any partial results"
    }

    _parse_scan_results

    local hosts ports
    hosts="$(wc -l < "${LIVE_HOSTS_FILE}" 2> /dev/null | tr -d ' ')"
    ports="$(wc -l < "${IPPORTS_FILE}" 2> /dev/null | tr -d ' ')"
    if [[ "${ports:-0}" -eq 0 ]]; then
        LOG warn "No open ip:port pairs parsed from ${SPOONMAP_OUT_DIR}"
        return 0
    fi
    LOG pass "spoonmap results: ${hosts} host(s), ${ports} ip:port(s)"
    LOG info "  hosts    -> ${LIVE_HOSTS_FILE}"
    LOG info "  ipports  -> ${IPPORTS_FILE}"
    return 0
}
