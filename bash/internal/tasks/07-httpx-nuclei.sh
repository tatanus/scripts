#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: WEB_IPPORTS_FILE / IPPORTS_FILE / WEB_OUT_DIR / TEE_DIR and the
# LOG / internal::* helpers come from internal_lib.sh.

###############################################################################
# TASK: 07-httpx-nuclei
# DESCRIPTION: Probe the web ip:ports with ProjectDiscovery httpx to confirm
#              live HTTP(S) services, then run nuclei against the confirmed
#              URLs. Consumes web_ipports.txt from the gowitness task, falling
#              back to the full ip:port list if that file is absent.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_07_httpx_nuclei
###############################################################################
function run_task_07_httpx_nuclei() {
    # Prefer gowitness-confirmed web services; fall back to all ip:ports.
    local input="${WEB_IPPORTS_FILE}"
    [[ -s "${input}" ]] || input="${IPPORTS_FILE}"

    if [[ ! -s "${input}" ]]; then
        LOG warn "No ip:ports available for web triage; skipping httpx/nuclei"
        return 0
    fi

    mkdir -p "${WEB_OUT_DIR}" "${TEE_DIR}"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local httpx_out="${WEB_OUT_DIR}/httpx_${ts}.txt"
    local nuclei_out="${WEB_OUT_DIR}/nuclei_${ts}.txt"
    local httpx_tee="${TEE_DIR}/httpx_${ts}.tee"
    local nuclei_tee="${TEE_DIR}/nuclei_${ts}.tee"

    # ---- httpx --------------------------------------------------------------
    if internal::optional_cmd httpx "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"; then
        if internal::is_dry_run; then
            LOG info "[DRY RUN] would run: httpx -l ${input} -o ${httpx_out}"
        else
            LOG info "Probing $(wc -l < "${input}" | tr -d ' ') target(s) with httpx"
            httpx -l "${input}" -silent -o "${httpx_out}" 2>&1 | tee -a "${httpx_tee}" || {
                LOG warn "httpx returned non-zero"
            }
        fi
    else
        # No httpx: synthesise candidate URLs so nuclei still has input.
        LOG warn "httpx unavailable; generating candidate URLs directly"
        if ! internal::is_dry_run; then
            local ipport
            : > "${httpx_out}"
            while IFS= read -r ipport; do
                [[ -z "${ipport}" ]] && continue
                printf 'http://%s\nhttps://%s\n' "${ipport}" "${ipport}" >> "${httpx_out}"
            done < "${input}"
        fi
    fi

    local n_urls=0
    [[ -f "${httpx_out}" ]] && n_urls="$(wc -l < "${httpx_out}" | tr -d ' ')"
    LOG info "Live web URLs: ${n_urls} -> ${httpx_out}"

    # ---- nuclei -------------------------------------------------------------
    if [[ "${n_urls}" -eq 0 && "${INTERNAL_DRY_RUN}" != "true" ]]; then
        LOG warn "No URLs to scan with nuclei"
        return 0
    fi

    if internal::optional_cmd nuclei "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; then
        if internal::is_dry_run; then
            LOG info "[DRY RUN] would run: nuclei -l ${httpx_out} -o ${nuclei_out}"
        else
            LOG info "Running nuclei against ${n_urls} URL(s)"
            nuclei -l "${httpx_out}" -o "${nuclei_out}" 2>&1 | tee -a "${nuclei_tee}" || {
                LOG warn "nuclei returned non-zero"
            }
            local findings
            findings="$(wc -l < "${nuclei_out}" 2> /dev/null | tr -d ' ')"
            LOG pass "nuclei findings: ${findings:-0} -> ${nuclei_out}"
        fi
    fi

    return 0
}
