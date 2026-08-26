#!/usr/bin/env bash
# shellcheck disable=SC2154
# Rationale: SPOONMAP_OUT_DIR / PORTSCAN_DIR / PORTS_DIR / MSF_SCRIPTS_DIR /
# MSF_OUT_DIR / TEE_DIR and the LOG / internal::* helpers come from
# internal_lib.sh.

###############################################################################
# TASK: 05-msf-import
# DESCRIPTION: Import the spoonmap (nmap/masscan) XML results into the
#              Metasploit database via db_import so later msf module tasks can
#              target the discovered hosts/services. Builds a resource script
#              dynamically from the XML actually present (more robust than the
#              hardcoded paths in pentest_setup's import_nmap_scans.rc), then
#              also runs that shipped rc if it exists.
###############################################################################

set -uo pipefail
IFS=$'\n\t'

###############################################################################
# run_task_05_msf_import
###############################################################################
function run_task_05_msf_import() {
    internal::require_cmd msfconsole "install metasploit-framework" || return 1

    mkdir -p "${MSF_OUT_DIR}" "${TEE_DIR}"

    # Collect every XML result under the scan output trees.
    local -a xml_files=()
    local f
    while IFS= read -r f; do
        [[ -n "${f}" ]] && xml_files+=("${f}")
    done < <(find "${SPOONMAP_OUT_DIR}" "${PORTSCAN_DIR}" "${PORTS_DIR}" \
        -type f -name '*.xml' 2> /dev/null | sort -u)

    if ((${#xml_files[@]} == 0)); then
        LOG warn "No XML scan files found to import; skipping db_import"
        return 0
    fi
    LOG info "Found ${#xml_files[@]} XML file(s) to import"

    # Generate a resource script that imports each file, then dumps state.
    local rc
    rc="$(mktemp --suffix=.rc 2> /dev/null || mktemp)"
    {
        echo "db_status"
        for f in "${xml_files[@]}"; do
            printf 'db_import %q\n' "${f}"
        done
        echo "hosts"
        echo "services"
        echo "exit"
    } > "${rc}"

    local tee_log
    tee_log="${TEE_DIR}/msf_import_$(date +%Y%m%d_%H%M%S).tee"

    if internal::is_dry_run; then
        LOG info "[DRY RUN] would run: msfconsole -q -r ${rc}"
        LOG info "[DRY RUN] resource script contents:"
        while IFS= read -r line; do LOG info "[DRY RUN]   ${line}"; done < "${rc}"
        rm -f "${rc}"
        return 0
    fi

    LOG info "Importing scans into Metasploit database..."
    msfconsole -q -r "${rc}" 2>&1 | tee -a "${tee_log}" || {
        LOG warn "msfconsole import returned non-zero (is msfdb initialised?)"
    }
    rm -f "${rc}"

    # Also run the shipped importer if present (harmless, path-hardcoded).
    local shipped="${MSF_SCRIPTS_DIR}/import_nmap_scans.rc"
    if [[ -f "${shipped}" ]]; then
        LOG info "Running shipped importer: ${shipped}"
        msfconsole -q -r "${shipped}" 2>&1 | tee -a "${tee_log}" || true
    fi

    LOG pass "db_import complete (log: ${tee_log})"
    return 0
}
