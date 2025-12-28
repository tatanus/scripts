#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : cloud_surface_utils.sh
# DESCRIPTION  : Cloud endpoint helpers and Azure hinting utilities (reused).
# AUTHOR       : Adam Compton
# DATE CREATED : 2025-08-21
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2025-08-21 | Adam Compton | Initial creation
# =============================================================================

#----------------------------------------------------------------------------
# Required libs (adjust paths as needed)
#----------------------------------------------------------------------------
# shellcheck source=./common_utils.sh
. "./common_utils.sh"

###############################################################################
# _azure_hint_from_cname
#------------------------------------------------------------------------------
# PURPOSE:
#   Map a CNAME target FQDN to a coarse Azure service hint. This is useful when
#   passively inferring whether a host likely backs onto Azure CDN, Azure
#   Storage (Blob), or Azure App Service, without any active scanning.
#
# ARGUMENTS:
#   $1 - target
#        The CNAME target (e.g., "myapp.azurewebsites.net").
#
# RETURNS (stdout):
#   One of the following strings:
#     - "cdn"         : for *.azureedge.net / *.azurefd.net
#     - "storage"     : for *.blob.core.windows.net
#     - "app_service" : for *.azurewebsites.net
#     - "unknown"     : no mapping matched
#
# EXIT STATUS:
#   Always 0 (pure mapping helper; callers consume the string).
#
# SECURITY / ROBUSTNESS:
#   - Uses anchored-ish regexes to avoid false positives (endswith patterns).
#   - Works with empty input (returns "unknown").
###############################################################################
function _azure_hint_from_cname() {
    local target="${1}"

    if grep -Eq 'azure(edge|fd)\.net$' <<< "${target}"; then
        printf '%s\n' "cdn"
        return 0
    fi
    if grep -Eq 'blob\.core\.windows\.net$' <<< "${target}"; then
        printf '%s\n' "storage"
        return 0
    fi
    if grep -Eq 'azurewebsites\.net$' <<< "${target}"; then
        printf '%s\n' "app_service"
        return 0
    fi

    printf '%s\n' "unknown"
}

###############################################################################
# _domain_prefix
# Utility: derive leftmost label for convenience hosts.
###############################################################################
function _domain_prefix() {
    local domain="${1}"
    printf '%s\n' "${domain%%.*}"
}

###############################################################################
# get_cloud_endpoints
# Map cloud choice to key endpoints.
# Arguments:
#   $1 - cloud (na|gov|china)
# Output (stdout):
#   "login_host|outlook_host|autodiscover_global|eop_suffix"
###############################################################################
function get_cloud_endpoints() {
    local cloud="${1}"
    local login_host="" outlook_host="" autod_global="" eop_suffix=""
    case "${cloud}" in
        na | NA | Na)
            login_host="login.microsoftonline.com"
            outlook_host="outlook.office365.com"
            autod_global="autodiscover-s.outlook.com"
            eop_suffix=".mail.protection.outlook.com"
            ;;
        gov | GOV | Gov)
            login_host="login.microsoftonline.us"
            outlook_host="outlook.office365.us"
            autod_global="autodiscover-s.office365.us"
            eop_suffix=".mail.protection.office365.us"
            ;;
        china | cn | CN | China)
            login_host="login.partner.microsoftonline.cn"
            outlook_host="partner.outlook.cn"
            autod_global="autodiscover.partner.outlook.cn"
            eop_suffix=".mail.protection.partner.outlook.cn"
            ;;
        *)
            # Default to NA
            login_host="login.microsoftonline.com"
            outlook_host="outlook.office365.com"
            autod_global="autodiscover-s.outlook.com"
            eop_suffix=".mail.protection.outlook.com"
            ;;
    esac
    printf '%s|%s|%s|%s\n' "${login_host}" "${outlook_host}" "${autod_global}" "${eop_suffix}"
}
