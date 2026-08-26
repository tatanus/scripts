#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: IPPORTS_FILE / WEB_URLS_FILE / WEB_IPPORTS_FILE /
# GOWITNESS_OUT_DIR / TEE_DIR and the LOG / internal::* helpers come from
# internal_lib.sh.

###############################################################################
# TASK: 06-gowitness
# DESCRIPTION: Screenshot every discovered ip:port (both http and https) with
#              gowitness, then record the ip:port pairs that actually responded
#              (a screenshot was produced) into web_ipports.txt for the
#              httpx/nuclei task. Falls back to forwarding all ip:ports if
#              gowitness output cannot be correlated.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# _build_url_list
# Expand ip:port pairs into http:// and https:// URLs.
###############################################################################
function _build_url_list() {
    mkdir -p "$(dirname "${WEB_URLS_FILE}")"
    : > "${WEB_URLS_FILE}"
    local ipport
    while IFS= read -r ipport; do
        [[ -z "${ipport}" ]] && continue
        printf 'http://%s\n' "${ipport}" >> "${WEB_URLS_FILE}"
        printf 'https://%s\n' "${ipport}" >> "${WEB_URLS_FILE}"
    done < "${IPPORTS_FILE}"
}

###############################################################################
# _run_gowitness
# Run whichever gowitness CLI generation is installed (v3 subcommands first,
# then legacy v2). Returns 0 if a variant ran.
###############################################################################
function _run_gowitness() {
    local tee_log="${1}"
    # v3: gowitness scan file -f urls.txt --screenshot-path <dir>
    if gowitness scan file --help > /dev/null 2>&1; then
        gowitness scan file -f "${WEB_URLS_FILE}" --screenshot-path "${GOWITNESS_OUT_DIR}" \
            2>&1 | tee -a "${tee_log}"
        return 0
    fi
    # v2: gowitness file -f urls.txt -P <dir>
    if gowitness file --help > /dev/null 2>&1; then
        gowitness file -f "${WEB_URLS_FILE}" -P "${GOWITNESS_OUT_DIR}" \
            2>&1 | tee -a "${tee_log}"
        return 0
    fi
    LOG warn "Unrecognised gowitness CLI; skipping screenshots"
    return 1
}

###############################################################################
# _correlate_successes
# For each candidate ip:port, mark it successful if a produced screenshot file
# references both the ip and the port. Writes WEB_IPPORTS_FILE.
###############################################################################
function _correlate_successes() {
    local -a shots=()
    local s
    while IFS= read -r s; do
        [[ -n "${s}" ]] && shots+=("$(basename "${s}")")
    done < <(find "${GOWITNESS_OUT_DIR}" -type f \
        \( -iname '*.png' -o -iname '*.jpeg' -o -iname '*.jpg' \) 2> /dev/null)

    mkdir -p "$(dirname "${WEB_IPPORTS_FILE}")"
    : > "${WEB_IPPORTS_FILE}"

    if ((${#shots[@]} == 0)); then
        LOG warn "No gowitness screenshots found; forwarding all ip:ports to web triage"
        cp -f "${IPPORTS_FILE}" "${WEB_IPPORTS_FILE}"
        return 0
    fi

    local ipport ip port name hit
    while IFS= read -r ipport; do
        [[ -z "${ipport}" ]] && continue
        ip="${ipport%%:*}"
        port="${ipport##*:}"
        hit=""
        for name in "${shots[@]}"; do
            if [[ "${name}" == *"${ip}"* && "${name}" == *"${port}"* ]]; then
                hit=1
                break
            fi
        done
        [[ -n "${hit}" ]] && printf '%s\n' "${ipport}" >> "${WEB_IPPORTS_FILE}"
    done < "${IPPORTS_FILE}"

    sort -u -o "${WEB_IPPORTS_FILE}" "${WEB_IPPORTS_FILE}"
}

###############################################################################
# run_task_06_gowitness
###############################################################################
function run_task_06_gowitness() {
    if [[ ! -s "${IPPORTS_FILE}" ]]; then
        LOG warn "No ip:ports from spoonmap; skipping gowitness"
        return 0
    fi
    internal::optional_cmd gowitness "go install github.com/sensepost/gowitness@latest" || return 0

    mkdir -p "${GOWITNESS_OUT_DIR}" "${TEE_DIR}"
    _build_url_list

    local tee_log
    tee_log="${TEE_DIR}/gowitness_$(date +%Y%m%d_%H%M%S).tee"
    if internal::is_dry_run; then
        LOG info "[DRY RUN] would screenshot $(wc -l < "${WEB_URLS_FILE}" | tr -d ' ') URL(s) with gowitness"
        cp -f "${IPPORTS_FILE}" "${WEB_IPPORTS_FILE}"
        return 0
    fi

    LOG info "Running gowitness against $(wc -l < "${WEB_URLS_FILE}" | tr -d ' ') URL(s)"
    _run_gowitness "${tee_log}" || true
    _correlate_successes

    local n
    n="$(wc -l < "${WEB_IPPORTS_FILE}" | tr -d ' ')"
    LOG pass "Responsive web ip:ports: ${n} -> ${WEB_IPPORTS_FILE}"
    LOG info "Screenshots: ${GOWITNESS_OUT_DIR}"
    return 0
}
