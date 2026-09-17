#!/usr/bin/env bash
# =============================================================================
# NAME         : m365_recon_NG.sh
# DESCRIPTION  : Thin launcher for the Microsoft 365 / Entra / Azure external
#                recon CLI. All logic now lives in the canonical shared library
#                ${SCRIPTS_DIR}/bash/lib/m365.sh (sourced below); this wrapper
#                exists so the recon phases (02-dns-email, 03-cloud) and
#                operators can invoke the CLI by a stable path. Requires
#                common_core (Bash 4+), which the library hard-sources.
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-21
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-21 | Adam Compton | Initial creation
# 2026-09-17 | Adam Compton | Reduced to launcher; logic moved to lib/m365.sh
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

_here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
_m365_lib="${M365_LIB:-${_here}/../lib/m365.sh}"
if [[ ! -r "${_m365_lib}" ]]; then
    printf '[ERROR] m365 library not found at %s\n' "${_m365_lib}" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "${_m365_lib}"

main "$@"
