#!/usr/bin/env bash

# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'

# =============================================================================
# NAME         : json_utils.sh
# DESCRIPTION  : JSON composition helpers used across modules.
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
# json_kv
# Build a simple object from key=value pairs safely.
# Arguments:
#   Pairs: key jsonvalue (use --arg/--argjson upstream when calling jq -n)
###############################################################################
function json_kv() {
    # Usage example (internal):
    # jq -n --arg k1 v1 --arg k2 v2 '{ ($k1): $v1, ($k2): $v2 }'
    :
}

###############################################################################
# json_merge
# Merge multiple JSON objects into one (shallow object union, later wins).
# Arguments:
#   JSON strings via stdin or args
# Output:
#   merged JSON object
###############################################################################
function json_merge() {
    if (("$#" > 0)); then
        jq -s '
          reduce .[] as $i (
            {};
            # Start with a shallow merge for general keys
            . * $i
            #
            # Now deep-merge azure_services sub-structure so fragments don’t clobber each other
            | .azure_services =
                ( (.azure_services // {})
                  + ($i.azure_services // {})
                )
            | .azure_services.hints =
                ((.azure_services.hints // [])
                  + ($i.azure_services.hints // []))
            | .azure_services.storage_accounts =
                ((.azure_services.storage_accounts // [])
                  + ($i.azure_services.storage_accounts // []))
            | .azure_services.power_apps =
                ((.azure_services.power_apps // [])
                  + ($i.azure_services.power_apps // []))
            | .azure_services.cdn_endpoints =
                ((.azure_services.cdn_endpoints // [])
                  + ($i.azure_services.cdn_endpoints // []))
            # app_services is a map; merge maps (later entries override identical keys)
            | .azure_services.app_services =
                ((.azure_services.app_services // {})
                  + ($i.azure_services.app_services // {}))
          )' <<< "$(printf '%s\n' "$@")"
    else
        jq -s '
          reduce .[] as $i (
            {};
            . * $i
            | .azure_services =
                ( (.azure_services // {})
                  + ($i.azure_services // {})
                )
            | .azure_services.hints =
                ((.azure_services.hints // [])
                  + ($i.azure_services.hints // []))
            | .azure_services.storage_accounts =
                ((.azure_services.storage_accounts // [])
                  + ($i.azure_services.storage_accounts // []))
            | .azure_services.power_apps =
                ((.azure_services.power_apps // [])
                  + ($i.azure_services.power_apps // []))
            | .azure_services.cdn_endpoints =
                ((.azure_services.cdn_endpoints // [])
                  + ($i.azure_services.cdn_endpoints // []))
            | .azure_services.app_services =
                ((.azure_services.app_services // {})
                  + ($i.azure_services.app_services // {}))
          )'
    fi
}

###############################################################################
# json_output
# Merge all collected JSON fragments into one final object.
# Arguments:
#   All JSON fragment strings as args
# Output:
#   JSON object (merged)
###############################################################################
function json_output() {
    json_merge "$@"
}
