# tests/independent/helpers/common.bash
# Shared helpers for bats tests in tests/independent/

# Simple predicate
function function_exists() {
  local fn="${1:-}"
  if [[ -z "${fn}" ]]; then
    return 1
  fi
  declare -F "${fn}" > /dev/null 2>&1
}

# Stub logging functions if missing (so sourcing repo files won't fail)
if ! declare -f info > /dev/null; then function info() { printf '[* INFO  ] %s\n' "$*"; }; fi
if ! declare -f warn > /dev/null; then function warn() { printf '[! WARN  ] %s\n' "$*" >&2; }; fi
if ! declare -f error > /dev/null; then function error() { printf '[- ERROR ] %s\n' "$*" >&2; }; fi
if ! declare -f pass > /dev/null; then function pass() { printf '[+ PASS  ] %s\n' "$*"; }; fi
if ! declare -f fail > /dev/null; then function fail() { printf '[- FAIL  ] %s\n' "$*" >&2; }; fi

# Repo root from the test file location (independent tests are 2 levels deep)
repo_root="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
export REPO_ROOT="${repo_root}"

# Real common_core source location (one repo up from scripts/).
COMMON_CORE_SRC="$(cd "${REPO_ROOT}/../common_core" 2> /dev/null && pwd)" || COMMON_CORE_SRC=""
export COMMON_CORE_SRC

# temp HOME helpers
function setup_temp_home() {
  export TEST_HOME="$(mktemp -d "/tmp/scripts-test.XXXXXX")"
  export HOME="${TEST_HOME}"
}

function teardown_temp_home() {
  rm -rf "${TEST_HOME}"
}

# Install a real common_core into the sandbox HOME (the install.sh
# preflight requires it). Falls back to a minimal mock if the sibling
# repo isn't present.
function install_common_core_into_temp_home() {
  local cc_dir="${HOME}/.config/bash/lib/common_core"
  mkdir -p "${cc_dir}"

  if [[ -n "${COMMON_CORE_SRC}" && -f "${COMMON_CORE_SRC}/lib/util.sh" ]]; then
    cp "${COMMON_CORE_SRC}/lib/util.sh" "${cc_dir}/util.sh"
    cp -r "${COMMON_CORE_SRC}/lib/utils" "${cc_dir}/utils"
  else
    # Minimal mock providing only the helpers install.sh needs.
    cat > "${cc_dir}/util.sh" << 'MOCK_CC_EOF'
#!/usr/bin/env bash
info()  { printf '[* INFO  ] %s\n' "$*"; }
warn()  { printf '[! WARN  ] %s\n' "$*" >&2; }
error() { printf '[- ERROR ] %s\n' "$*" >&2; }
fail()  { printf '[- FAIL  ] %s\n' "$*" >&2; }
pass()  { printf '[+ PASS  ] %s\n' "$*"; }
debug() { printf '[. DEBUG ] %s\n' "$*"; }

cmd::exists() { command -v "$1" > /dev/null 2>&1; }

file::copy() {
  local src="$1" dst="$2"
  mkdir -p "$(dirname "${dst}")"
  cp "${src}" "${dst}"
  pass "Copied: ${src} -> ${dst}"
}

dir::create() {
  mkdir -p "$1" && pass "Directory created: $1"
}
MOCK_CC_EOF
  fi
}

# Lay down a stub .bashrc so install.sh's bash_setup preflight passes.
function install_bashrc_stub() {
  : > "${HOME}/.bashrc"
}
