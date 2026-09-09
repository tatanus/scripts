#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: RECON_* globals, TARGETS_FILE/DOMAINS_FILE and the LOG
# front-end are established by run_recon.sh and lib/*.sh across the source
# chain (SC2154); values exported here are consumed by later phases (SC2034).
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : 05-web.sh
# DESCRIPTION  : Phase 5 - web surface capture and fingerprinting. Screenshots
#                open web ports with gowitness v3 (one probe per derived
#                scheme://ip:port so filtered ports do not stall workers),
#                builds urls.txt from gowitness output, then fingerprints with
#                httpx and whatweb.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation
# =============================================================================

###############################################################################
# run_phase_web
###############################################################################
function run_phase_web() {
    local d="${RECON_OUTDIR}/05-web"
    mkdir -p "${d}"
    local gw_targets="${d}/gowitness-targets.txt"
    local urls="${RECON_OUTDIR}/urls.txt"

    # Prefer the exact web-service list derived from nmap in phase 04.
    if [[ -n "${RECON_WEB_SERVICES:-}" ]] && [[ -s "${RECON_WEB_SERVICES}" ]]; then
        cp "${RECON_WEB_SERVICES}" "${gw_targets}"
    elif [[ -n "${RECON_NMAP_XMLDIR:-}" ]] && [[ -d "${RECON_NMAP_XMLDIR}" ]]; then
        scope_web_urls_from_nmap "${RECON_NMAP_XMLDIR}" "${gw_targets}" "${TARGETS_FILE}" \
            "${GW_ALL_PORTS:-0}" "${d}/out-of-scope-ports.txt" "${GW_TRUST:-0}" > /dev/null 2>&1 || true
    fi

    # gowitness screenshots.
    if have_cmd gowitness; then
        if [[ -s "${gw_targets}" ]]; then
            LOG info "gowitness: $(count_lines "${gw_targets}") derived web target(s)"
            (
                cd "${d}" && run gowitness scan file -f "${gw_targets}" \
                    --threads "${GW_THREADS:-40}" --timeout "${GW_TIMEOUT:-10}" \
                    --delay "${GW_DELAY:-2}" --log-scan-errors \
                    --write-db --write-csv --write-jsonl --write-stdout
            ) || LOG warn "gowitness returned non-zero"
        else
            LOG warn "no derived web targets - run the portscan phase first for a narrowed list"
            LOG warn "falling back to expanded scope with a large port list (slow)"
            # gowitness cannot expand CIDRs, so hand it one address per line.
            local expanded="${d}/expanded-scope.txt"
            if [[ -n "${RECON_EXPANDED_TARGETS:-}" ]] && [[ -s "${RECON_EXPANDED_TARGETS}" ]]; then
                cp "${RECON_EXPANDED_TARGETS}" "${expanded}"
            elif [[ -s "${RECON_OUTDIR}/targets-expanded.txt" ]]; then
                cp "${RECON_OUTDIR}/targets-expanded.txt" "${expanded}"
            else
                scope_expand "${TARGETS_FILE}" "${RECON_MAX_HOSTS:-8192}" \
                    "${d}/.ips" "${d}/.names" > /dev/null 2>&1 || true
                cat "${d}/.ips" "${d}/.names" 2> /dev/null | sed -e '/^$/d' |
                    sort -u > "${expanded}"
                rm -f "${d}/.ips" "${d}/.names"
            fi
            if [[ ! -s "${expanded}" ]]; then
                LOG warn "no usable targets to screenshot - skipping gowitness"
            else
                LOG info "gowitness: $(count_lines "${expanded}") address(es) x large port list"
                (
                    cd "${d}" && run gowitness scan file -f "${expanded}" \
                        --threads "${GW_THREADS:-40}" --timeout "${GW_TIMEOUT:-10}" \
                        --delay "${GW_DELAY:-2}" --write-db --write-csv --write-jsonl --ports-large
                ) || LOG warn "gowitness returned non-zero"
            fi
        fi
    else
        LOG info "gowitness not installed - skipping screenshots"
    fi

    # Build urls.txt from gowitness output.
    web_build_urls "${d}" "${urls}"

    # urlfinder: passive historical URL discovery for the in-scope domains,
    # merged in to broaden httpx/nuclei coverage beyond the screenshotted set.
    if have_cmd urlfinder && [[ -n "${DOMAINS_FILE:-}" ]] && [[ -s "${DOMAINS_FILE}" ]]; then
        LOG info "urlfinder: passive URL discovery"
        run_pipe "urlfinder -list $(printf '%q' "${DOMAINS_FILE}") -silent \
            >> $(printf '%q' "${d}/urlfinder.txt") 2>/dev/null || true"
        if [[ -s "${d}/urlfinder.txt" ]]; then
            cat "${d}/urlfinder.txt" >> "${urls}" 2> /dev/null || true
            [[ -s "${urls}" ]] && sort -u -o "${urls}" "${urls}"
        fi
    fi

    # httpx fingerprint.
    if have_cmd httpx && [[ -s "${urls}" ]]; then
        LOG info "httpx: fingerprinting $(count_lines "${urls}") URL(s)"
        run_pipe "cat $(printf '%q' "${urls}") \
            | httpx -title -status-code -web-server -vhost -threads ${RECON_THREADS:-50} \
              -o $(printf '%q' "${d}/httpx.out")" || LOG warn "httpx returned non-zero"
        export RECON_LIVE_URLS="${urls}"
    fi

    # whatweb fingerprint.
    if have_cmd whatweb && [[ -s "${urls}" ]]; then
        LOG info "whatweb: technology fingerprinting"
        run_pipe "whatweb -i $(printf '%q' "${urls}") --log-brief=$(printf '%q' "${d}/whatweb.txt") \
            --no-errors >/dev/null 2>&1" || LOG warn "whatweb returned non-zero"
    fi

    if [[ -s "${urls}" ]]; then
        LOG pass "$(count_lines "${urls}") live URL(s) -> ${urls}"
    else
        LOG warn "no live web URLs found; phase 06 web templates will be skipped"
    fi
    return 0
}

###############################################################################
# web_build_urls
# Purpose : Extract a deduplicated URL list from gowitness jsonl/csv output.
# Args    : $1 gowitness dir ; $2 out file
###############################################################################
function web_build_urls() {
    local d="${1}" out="${2}"
    local jsonl csv
    jsonl="$(find "${d}" -maxdepth 2 -type f -name '*.jsonl' 2> /dev/null | head -n 1)"
    csv="$(find "${d}" -maxdepth 2 -type f -name '*.csv' 2> /dev/null | head -n 1)"
    : > "${out}"

    if [[ -n "${jsonl}" ]] && [[ -s "${jsonl}" ]]; then
        if have_cmd jq; then
            jq -r '.url // .URL // empty' "${jsonl}" 2> /dev/null >> "${out}" || true
        fi
        [[ -s "${out}" ]] || grep -ohE 'https?://[^"'"'"' ,]+' "${jsonl}" >> "${out}" 2> /dev/null || true
    fi

    if [[ ! -s "${out}" ]] && [[ -n "${csv}" ]] && [[ -s "${csv}" ]]; then
        python3 - "${csv}" >> "${out}" << 'PY' || true
import csv, sys
with open(sys.argv[1], newline="", encoding="utf-8", errors="replace") as fh:
    reader = csv.reader(fh)
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        sys.exit(0)
    idx = next((i for i, h in enumerate(header)
                if h in ("url", "finalurl", "final_url", "final url")), None)
    if idx is None:
        sys.exit(0)
    for row in reader:
        if len(row) > idx and row[idx].strip().startswith(("http://", "https://")):
            print(row[idx].strip())
PY
    fi

    if [[ -s "${out}" ]]; then
        sort -u -o "${out}" "${out}"
    else
        rm -f "${out}"
    fi
}
