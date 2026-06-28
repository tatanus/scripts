#!/usr/bin/env bats
# tests/independent/20_lifecycle.bats
# End-to-end install / update / uninstall lifecycle tests in a sandbox
# HOME. Requires a real (or mock) common_core under
# ${HOME}/.config/bash/lib/common_core/ and a stub ${HOME}/.bashrc to
# satisfy install.sh's preflight.

load 'helpers/common.bash'

setup() {
  setup_temp_home
  install_common_core_into_temp_home
  install_bashrc_stub
}

teardown() {
  teardown_temp_home
}

@test "lifecycle: install creates ${HOME}/DATA/TOOLS/SCRIPTS/{bash,python}/" {
  run bash "${REPO_ROOT}/install.sh" install
  [ "$status" -eq 0 ]
  [ -d "${HOME}/DATA/TOOLS/SCRIPTS/bash" ]
  [ -d "${HOME}/DATA/TOOLS/SCRIPTS/python" ]
}

@test "lifecycle: install deploys both bash/ and python/ trees byte-for-byte" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1

  # Compare a handful of representative files
  for f in bash/logger.sh bash/safe_source.sh python/ad_dns_enum.py python/upnp.py; do
    cmp -s "${REPO_ROOT}/${f}" "${HOME}/DATA/TOOLS/SCRIPTS/${f}"
  done
}

@test "lifecycle: install preserves bash/recon/ subtree" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  [ -d "${HOME}/DATA/TOOLS/SCRIPTS/bash/recon" ]
  [ -f "${HOME}/DATA/TOOLS/SCRIPTS/bash/recon/FRAMEWORK_OVERVIEW.md" ]
}

@test "lifecycle: install creates DATA/TOOLS/SCRIPTS when it does not exist" {
  [ ! -d "${HOME}/DATA" ]
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  [ -d "${HOME}/DATA/TOOLS/SCRIPTS" ]
}

@test "lifecycle: update with no changes re-skips every file" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  run bash "${REPO_ROOT}/install.sh" update
  [ "$status" -eq 0 ]
  [[ "${output}" =~ "copied=0" ]]
}

@test "lifecycle: update after mutation re-copies exactly the changed file" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  # Mutate one deployed file
  echo "# user-mod" >> "${HOME}/DATA/TOOLS/SCRIPTS/bash/logger.sh"

  run bash "${REPO_ROOT}/install.sh" update
  [ "$status" -eq 0 ]
  # 1 file should have been copied (logger.sh); rest skipped.
  [[ "${output}" =~ "copied=1" ]]

  # Mutation should be wiped out by the re-copy
  cmp -s "${REPO_ROOT}/bash/logger.sh" "${HOME}/DATA/TOOLS/SCRIPTS/bash/logger.sh"
}

@test "lifecycle: --force re-copies even unchanged files" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  run bash "${REPO_ROOT}/install.sh" install --force
  [ "$status" -eq 0 ]
  # Every file should be reported as copied (skipped=0).
  [[ "${output}" =~ "skipped=0" ]]
}

@test "lifecycle: --dry-run does not write" {
  run bash "${REPO_ROOT}/install.sh" install --dry-run
  [ "$status" -eq 0 ]
  [[ "${output}" =~ "DRY-RUN" ]]
  [ ! -d "${HOME}/DATA/TOOLS/SCRIPTS/bash" ]
  [ ! -d "${HOME}/DATA/TOOLS/SCRIPTS/python" ]
}

@test "lifecycle: uninstall removes both subtrees, leaves target root" {
  bash "${REPO_ROOT}/install.sh" install > /dev/null 2>&1
  # Drop a user-owned file under the target root so we can confirm we
  # do not nuke it.
  echo "user-owned" > "${HOME}/DATA/TOOLS/SCRIPTS/keep-me.txt"

  run bash "${REPO_ROOT}/install.sh" uninstall
  [ "$status" -eq 0 ]
  [ ! -d "${HOME}/DATA/TOOLS/SCRIPTS/bash" ]
  [ ! -d "${HOME}/DATA/TOOLS/SCRIPTS/python" ]
  # Target root still exists; user's own file preserved.
  [ -f "${HOME}/DATA/TOOLS/SCRIPTS/keep-me.txt" ]
}

@test "lifecycle: uninstall is idempotent when nothing is installed" {
  run bash "${REPO_ROOT}/install.sh" uninstall
  [ "$status" -eq 0 ]
}
