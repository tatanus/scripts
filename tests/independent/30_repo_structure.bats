#!/usr/bin/env bats
# tests/independent/30_repo_structure.bats
# Cheap structural checks. install.sh / Makefile / docs presence,
# expected source trees, expected counts.

load 'helpers/common.bash'

@test "structure: install.sh is present and executable" {
  [ -f "${REPO_ROOT}/install.sh" ]
  [ -x "${REPO_ROOT}/install.sh" ]
}

@test "structure: Makefile is present" {
  [ -f "${REPO_ROOT}/Makefile" ]
}

@test "structure: VERSION + CHANGELOG.md + README.md are present" {
  [ -f "${REPO_ROOT}/VERSION" ]
  [ -f "${REPO_ROOT}/CHANGELOG.md" ]
  [ -f "${REPO_ROOT}/README.md" ]
}

@test "structure: bash/ and python/ source trees are present" {
  [ -d "${REPO_ROOT}/bash" ]
  [ -d "${REPO_ROOT}/python" ]
}

@test "structure: bash/recon/ subtree is present" {
  [ -d "${REPO_ROOT}/bash/recon" ]
}

@test "structure: install.sh has the project-mandated strict mode" {
  grep -q "set -uo pipefail" "${REPO_ROOT}/install.sh"
}

@test "structure: install.sh does NOT use set -e (banned by CLAUDE.md)" {
  ! grep -qE "set -e\b|set -Ee\b|set -ueo|set -euo" "${REPO_ROOT}/install.sh"
}

@test "structure: install.sh uses function name() form throughout" {
  # All function declarations should use `function name() {` form. Allow
  # `function name()` followed by `{` on the same line or next; reject
  # bare `name() {`. Skip the heredoc'd USAGE block by stopping at EOF.
  run bash -c '
    awk "/<<-? *EOF/,/^EOF/ {next}
         /^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_:]*\(\)[[:space:]]*\{/ {print; exit 1}
         END {exit 0}" "$1"
  ' _ "${REPO_ROOT}/install.sh"
  [ "$status" -eq 0 ]
}
