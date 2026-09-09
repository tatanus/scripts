#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 04-portscan.sh
# DESCRIPTION  : Phase 4 - port and service discovery over the authorized scan
#                scope (targets.txt only). Default engine is nmap (host
#                discovery, top ports, service detection, optional full-TCP /
#                UDP / NSE). Optional engine is spoonmap (masscan-driven) when
#                RECON_ENGINE=spoonmap and its repo is available.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_portscan
###############################################################################
function run_phase_portscan() {
    need_file "${TARGETS_FILE}" || return "${RECON_ERR_INPUT}"
    case "${RECON_ENGINE:-nmap}" in
        spoonmap) portscan_spoonmap ;;
        naabu) portscan_naabu ;;
        nmap | *) portscan_nmap ;;
    esac
}

###############################################################################
# portscan_naabu
# Purpose : Fast port sweep with naabu, handing the open ports straight to
#           nmap -sV (via -nmap-cli) so service detection only touches ports
#           that are actually open. Produces the same nmap XML the web phase
#           consumes. CONNECT scan when unprivileged; SYN needs root.
###############################################################################
function portscan_naabu() {
    have_cmd naabu || {
        LOG error "naabu not installed and engine=naabu"
        return "${RECON_ERR_DEPS}"
    }
    have_cmd nmap || {
        LOG error "the naabu engine needs nmap for service detection"
        return "${RECON_ERR_DEPS}"
    }
    local d="${RECON_OUTDIR}/04-portscan"
    local xmldir="${d}/nmap_xml"
    mkdir -p "${xmldir}"

    local -a stype=()
    [[ "$(id -u)" -ne 0 ]] && stype=(-s c) # CONNECT scan without root

    LOG info "naabu: fast top-${NAABU_TOP_PORTS:-1000} sweep -> nmap -sV"
    run naabu -l "${TARGETS_FILE}" -top-ports "${NAABU_TOP_PORTS:-1000}" \
        -rate "${NAABU_RATE:-1000}" -silent ${stype[@]+"${stype[@]}"} \
        -o "${d}/naabu.txt" \
        -nmap-cli "nmap -sV -oX ${xmldir}/top-ports.xml" \
        > /dev/null 2>&1 || LOG warn "naabu returned non-zero"

    local live="${d}/live-hosts.txt"
    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && [[ -f "${d}/naabu.txt" ]]; then
        cut -d: -f1 "${d}/naabu.txt" | sort -u > "${live}" || true
    fi
    [[ -s "${live}" ]] || cp "${RECON_EXPANDED_TARGETS:-${TARGETS_FILE}}" "${live}" 2> /dev/null || true
    export RECON_NMAP_LIVE_HOSTS="${live}"
    export RECON_NMAP_XMLDIR="${xmldir}"
    LOG pass "$(count_lines "${live}") host(s) with open ports"

    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && [[ -f "${xmldir}/top-ports.xml" ]]; then
        local websvc="${d}/web-services.txt"
        scope_web_urls_from_nmap "${xmldir}" "${websvc}" "${TARGETS_FILE}" \
            "${GW_ALL_PORTS:-0}" "${d}/out-of-scope-ports.txt" "${GW_TRUST:-0}" \
            > /dev/null 2>&1 || true
        export RECON_WEB_SERVICES="${websvc}"
        LOG pass "$(count_lines "${websvc}") web service URL(s) derived from naabu/nmap"
    fi
    return 0
}

###############################################################################
# portscan_nmap
# Purpose : Run the nmap scan sequence and export live hosts / web services /
#           the XML directory the web phase derives probe targets from.
###############################################################################
function portscan_nmap() {
    have_cmd nmap || {
        LOG error "nmap not installed and engine=nmap"
        return "${RECON_ERR_DEPS}"
    }
    local d="${RECON_OUTDIR}/04-portscan"
    local xmldir="${d}/nmap_xml"
    mkdir -p "${xmldir}"

    recon_set_elevation
    local timing="${NMAP_TIMING:-4}"

    # 1. Host discovery.
    LOG info "nmap: host discovery"
    local live="${d}/live-hosts.txt"
    run nmap -sn -n -T"${timing}" -iL "${TARGETS_FILE}" -oX "${xmldir}/discovery.xml" \
        > /dev/null 2>&1 || true
    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && [[ -f "${xmldir}/discovery.xml" ]]; then
        grep -oE 'addr="[0-9.]+"' "${xmldir}/discovery.xml" | sed -E 's/addr="([^"]+)"/\1/' |
            sort -u > "${live}" || true
    fi
    [[ -s "${live}" ]] || cp "${RECON_EXPANDED_TARGETS:-${TARGETS_FILE}}" "${live}" 2> /dev/null || true
    export RECON_NMAP_LIVE_HOSTS="${live}"
    LOG pass "$(count_lines "${live}") live host(s)"

    # 2. Top-ports + service detection (SYN when elevated, else connect scan).
    local scan_type="-sT"
    [[ "${RECON_ELEV}" != "unprivileged" ]] && scan_type="-sS"
    LOG info "nmap: top-1000 ports + service detection (${scan_type})"
    run nmap -Pn -n -T"${timing}" "${scan_type}" -sV --top-ports 1000 \
        -iL "${live}" -oA "${d}/top-ports" -oX "${xmldir}/top-ports.xml" \
        > /dev/null 2>&1 || LOG warn "nmap top-ports returned non-zero"

    # 3. Optional full TCP.
    if [[ "${NMAP_FULL_TCP:-0}" -eq 1 ]]; then
        LOG info "nmap: full TCP port scan (1-65535)"
        run nmap -Pn -n -T"${timing}" "${scan_type}" -p- \
            -iL "${live}" -oA "${d}/full-tcp" -oX "${xmldir}/full-tcp.xml" \
            > /dev/null 2>&1 || LOG warn "nmap full-TCP returned non-zero"
    fi

    # 4. Optional UDP (top ports).
    if [[ "${NMAP_UDP:-0}" -eq 1 ]] && [[ "${RECON_ELEV}" != "unprivileged" ]]; then
        LOG info "nmap: UDP top-100 ports"
        run nmap -Pn -n -T"${timing}" -sU --top-ports 100 \
            -iL "${live}" -oA "${d}/udp" > /dev/null 2>&1 || LOG warn "nmap UDP returned non-zero"
    fi

    # 5. Web services for downstream phases.
    if [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && [[ -f "${xmldir}/top-ports.xml" ]]; then
        local websvc="${d}/web-services.txt"
        scope_web_urls_from_nmap "${xmldir}" "${websvc}" "${TARGETS_FILE}" \
            "${GW_ALL_PORTS:-0}" "${d}/out-of-scope-ports.txt" "${GW_TRUST:-0}" \
            > /dev/null 2>&1 || true
        export RECON_WEB_SERVICES="${websvc}"
        export RECON_NMAP_XMLDIR="${xmldir}"
        LOG pass "$(count_lines "${websvc}") web service URL(s) derived from nmap"
    fi
    return 0
}

###############################################################################
# portscan_spoonmap
# Purpose : Drive spoonmap in its own repo (masscan needs raw sockets). It is
#           interactive unless RECON_SPOONMAP_ARGS is supplied.
###############################################################################
function portscan_spoonmap() {
    local script="" repo=""
    local base="${RECON_SPOONMAP_PATH:-}"
    base="${base%/}"
    if [[ -f "${base}" ]]; then
        script="${base}"
    elif [[ -f "${base}/spoonmap.py" ]]; then
        script="${base}/spoonmap.py"
    elif have_cmd spoonmap.py; then
        script="$(command -v spoonmap.py)"
    fi
    if [[ -z "${script}" ]]; then
        LOG error "spoonmap.py not found - set RECON_SPOONMAP_PATH or use --engine nmap"
        return "${RECON_ERR_DEPS}"
    fi
    repo="$(cd -- "$(dirname "${script}")" && pwd)"
    LOG info "spoonmap: ${script} (runs in ${repo})"

    recon_set_elevation
    local runner=()
    [[ "${RECON_ELEV}" == "sudo" ]] && runner=(sudo)

    if [[ ! -t 0 ]] && [[ -z "${RECON_SPOONMAP_ARGS:-}" ]] && [[ "${RECON_DRY_RUN:-0}" -eq 0 ]]; then
        LOG warn "spoonmap is interactive but stdin is not a TTY - skipping"
        LOG warn "re-run this phase from a terminal, or set RECON_SPOONMAP_ARGS"
        RECON_STAGE_NOTE="skipped (needs a TTY)"
        return 0
    fi

    local py
    py="$(command -v python3)"
    local -a args=()
    local IFS=$' \t\n' # split RECON_SPOONMAP_ARGS on spaces
    # shellcheck disable=SC2206
    [[ -n "${RECON_SPOONMAP_ARGS:-}" ]] && args=(${RECON_SPOONMAP_ARGS})
    (
        cd "${repo}" || exit 1
        run ${runner[@]+"${runner[@]}"} "${py}" "${script}" ${args[@]+"${args[@]}"}
    ) || LOG warn "spoonmap returned non-zero"

    # Hand back ownership of anything spoonmap wrote as root.
    if [[ ${#runner[@]} -gt 0 ]] && [[ "${RECON_DRY_RUN:-0}" -eq 0 ]] && [[ -O "${repo}" ]]; then
        sudo chown -R "$(id -u):$(id -g)" "${repo}" 2> /dev/null ||
            LOG warn "could not reclaim ownership of ${repo}"
    fi

    # Point the web phase at spoonmap's nmap XML if present.
    if [[ -d "${repo}/nmap_results" ]]; then
        export RECON_NMAP_XMLDIR="${repo}/nmap_results"
        LOG info "spoonmap nmap XML: ${repo}/nmap_results"
    fi
    return 0
}
