#!/usr/bin/env bats
# tests/independent/10_smoke.bats
# install.sh smoke tests that do not require common_core / bash_setup:
# arg parsing, --help, --version, --dry-run, error paths.

load 'helpers/common.bash'

setup() {
  setup_temp_home
}

teardown() {
  teardown_temp_home
}

@test "install.sh --help exits 0 and prints USAGE" {
  run bash "${REPO_ROOT}/install.sh" --help
  [ "$status" -eq 0 ]
  [[ "${output}" =~ "USAGE" ]]
}

@test "install.sh --version prints v\${VERSION}" {
  run bash "${REPO_ROOT}/install.sh" --version
  [ "$status" -eq 0 ]
  [[ "${output}" =~ ^install\.sh\ v ]]
}

@test "install.sh rejects unknown options" {
  run bash "${REPO_ROOT}/install.sh" --not-a-real-flag
  [ "$status" -eq 1 ]
  [[ "${output}" =~ "Unknown option" ]]
}

@test "install.sh refuses to install without common_core" {
  install_bashrc_stub
  # no common_core deployed
  run bash "${REPO_ROOT}/install.sh" install
  [ "$status" -eq 1 ]
  [[ "${output}" =~ "common_core" ]]
}

@test "install.sh refuses to install without bash_setup (missing .bashrc)" {
  install_common_core_into_temp_home
  # no .bashrc
  run bash "${REPO_ROOT}/install.sh" install
  [ "$status" -eq 1 ]
  [[ "${output}" =~ "bash_setup" ]] || [[ "${output}" =~ ".bashrc" ]]
}
