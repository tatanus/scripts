# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the project-wide date-based versioning scheme
(`YYYY.MM.DD.N`).

## [Unreleased]

### Added

- `bash/internal/` — modular **internal penetration-test suite**. A
  task-based orchestrator (`run_internal_pentest.sh`) that auto-discovers
  and runs the steps under `bash/internal/tasks/` in filename order:
  validate/prompt for targets, iptables-block excludes, DNS + domain-
  controller discovery, TrustedSec spoonmap scan, Metasploit `db_import`,
  gowitness, httpx + nuclei, every `SCRIPTS/MSF/modules/*.rc`, and NetExec
  (`nxc smb --pass-pol` / `nxc ldap`). Shared bootstrap, the `DATA/` path
  layout and helpers live in `bash/internal/internal_lib.sh`; defaults are
  overridable via `bash/internal/config/default.conf` or `--config`. New
  steps drop in as `tasks/NN-name.sh` (defining `run_task_NN_name()`) with
  no orchestrator edit. See [`bash/internal/README.md`](bash/internal/README.md).
  - Reuses tools/artifacts deployed by `pentest_setup` at **runtime**
    (spoonmap, the `SCRIPTS/MSF/` resource scripts, gowitness, httpx,
    nuclei, netexec, metasploit) and follows the same `DATA/` layout as
    `pentest_setup/config/config.sh`. This is a runtime tool dependency
    resolved by path with graceful degradation when a tool is absent — not
    a source-time load-order dependency, so the
    `common_core → … → scripts → pentest_setup` contract is preserved.

## [2026.06.29.0] - 2026-06-29

### Changed

- `.shellcheckrc` synced to the canonical 108-line version used by
  `common_core`, `bash_setup`, and `pentest_setup`. Brings the
  block-commented rule taxonomy (severity=style, bash-version=4,
  enforced safety rules, controlled deviations, modern-Bash enables,
  security foot-gun rules, function-semantics policy) in line with
  the rest of the stack. All four repos now share a byte-identical
  `.shellcheckrc`.
- `bash/recon/setup_engagement.sh`: replaced the
  `mkdir -p …` + `if [[ $? -eq 0 ]]; then` pattern with the
  `if mkdir -p …; then` form (SC2181).

### Fixed

- `bash/wireless.sh:401`: the rename-failure `warn` message
  interpolated `${mon_iface}`, but that variable does not exist in
  scope at that point. The intended variable was `${base_iface}`
  (the target name the rename is trying to set). Corrected; the
  diagnostic now prints the actual target name on failure.

### Internal

- File-level `# shellcheck disable=` headers (with rationale) added
  to recon-suite modules and other one-off scripts so the canonical
  `.shellcheckrc` does not surface 33 expected SC2034 / SC2154
  findings. Affected files: `bash/logger.sh`,
  `bash/auto-mount-shares.sh`, `bash/setup-mail-server.sh`,
  `bash/update_gophish.sh`, `bash/recon/common_utils.sh`,
  `bash/recon/dns_email_recon.sh`, `bash/recon/entra_azure_recon.sh`,
  `bash/recon/m365_recon_NG.sh`, `bash/recon/services_recon.sh`,
  `bash/recon/run_external_recon_suite.sh`,
  `bash/recon/tasks/00-validate.sh`, `bash/recon/tasks/01-osint.sh`,
  `bash/recon/tasks/02-nmap.sh`, `bash/recon/tasks/03-http-scan.sh`,
  `bash/recon/tasks/04-testssl.sh`. Each disable cites the
  load-chain reason (e.g. CURL_UA / ENGAGEMENT_DIR are exported by
  the recon-suite orchestrator before invocation).

## [2026.06.28.0] - 2026-06-28

### Added

- `install.sh` (new, ~250 lines). Deploys `bash/` and `python/` into
  `${HOME}/DATA/TOOLS/SCRIPTS/{bash,python}/`, creating the target
  directory and parents if missing. install / update / uninstall
  subcommands; checksum-skip-unchanged on update; `--dry-run`,
  `--force`, `--quiet` flags. Preflight refuses to run unless
  common_core is installed at the documented system path AND
  bash_setup has deployed `${HOME}/.bashrc`.
- `Makefile` rewritten to parity with common_core / bash_setup /
  pentest_setup: 4-part `SEMVER_RE`, `make fmt-check`, non-mutating
  `make ci`, `make release V=…`, `make release-today`, `make style`.
  `make test` target now finds bats files under subdirectories via
  `find` (was `ls tests/*.bats`).
- `CHANGELOG.md` (this file).
- `.github/workflows/main.yml` rewritten to mirror the standard CI
  workflow in the other three repos (shellcheck + pinned shfmt v3.8.0
  + bats; runs `make lint`, `make fmt-check`, `make test`).
- `tools/check_bash_style.sh`, copied from common_core (was referenced
  by the new Makefile but not present in this repo). Bonus: extended
  the backtick check to skip backslash-escaped backticks (`\\\``),
  which are markdown formatting in heredocs that emit READMEs.
- BATS coverage for `install.sh` under `tests/independent/`:
  - `10_smoke.bats` (5 tests): arg parsing, `--help`, `--version`,
    preflight failures when common_core / bash_setup is absent.
  - `20_lifecycle.bats` (10 tests): end-to-end install / update /
    uninstall round-trip in a sandbox HOME.
  - `30_repo_structure.bats` (8 tests): repo invariants.
  - `tests/independent/helpers/common.bash`: shared helper that
    drops a real (or mock) common_core into the sandbox HOME and
    stubs a `.bashrc`.

### Changed

- **README rewritten end-to-end.** The previous version documented a
  fictional `scripts/` directory containing only `logger.sh` and
  `safe_source.sh`, ignored the actual `bash/` + `python/` +
  `bash/recon/` layout, and had a `tatanus/BASH` typo in the
  Last-Commit badge. New README mirrors the bash_setup / pentest_setup
  structure.
- Moved `policy/CODE_OF_CONDUCT.md`, `policy/CONTRIBUTING.md`,
  `policy/SECURITY.md` to `.github/` (their standard location).
  `policy/` directory removed.
- Rewrote `.github/CONTRIBUTING.md` using the common_core template
  (the previous version was the same `BASH`-placeholder /
  `-bn -kp` shfmt / `set -euo pipefail` drift I fixed earlier for
  common_core).

### Fixed

- All **156 ShellCheck findings** in the bash tree cleared:
  - **79 SC2250** brace-quoting (`$var` → `${var}`) auto-applied via
    `shellcheck -f diff | patch -p1`.
  - **9 SC2329** trap-handler `cleanup()` functions: per-line disable
    with rationale (invoked via `trap cleanup EXIT`).
  - **4 SC2249** missing default case: added `*) : ;;` or
    `*) warn ... ;;` arms.
  - **3 SC2155** declare-and-assign-separately: split
    `local x="$(...)"` into `local x; x="$(...)"` so the inner
    command's exit status is not masked by `local`.
  - **3 SC2016** single-quoted expressions: per-line / per-block
    disable with rationale (jq filter strings, xargs-passed
    `bash -c` body — both intentional).
  - **2 SC2126** `grep | wc -l` → `grep -c` real refactor.
  - **2 SC2059** printf with variable format string: per-line disable
    with rationale (the format string is a deliberate template).
  - **2 SC1112** unicode quote: replaced. (In `json_utils.sh`, the
    U+2019 apostrophe was inside a `jq -s '...'` single-quoted string
    deliberately so the outer quotes would not close; rewrote the
    comment to use "do not" instead.)
  - **1 SC2153** false positive (`TARGETS_FILE` env-global vs
    `targets_file` local are intentionally different identifiers).
  - **1 SC2004** redundant `${}` in arithmetic: removed.
  - **1 SC2001** sed-could-be-PE: per-line disable (bash parameter
    expansion does not support character classes).
- `echo -e "..."` → `printf '%b\n' "..."` across 35 sites in
  `setup_engagement.sh`, `wireless.sh`, `smtp_utils.sh`. CLAUDE.md
  bans `echo -e`. Verified semantically identical against the ANSI
  color globals these scripts use.
- `set -euo pipefail` → `set -uo pipefail` in `mount-try.sh`,
  `auto-mount-shares.sh`, `gophish_install.sh`. The `-e` (errexit)
  is banned by CLAUDE.md project-wide.

### Removed

- Root `compile.sh` (~170 lines). Used banned `set -Eeuo pipefail`,
  referenced a (also-removed) `lib/common_core` submodule that was
  never actually registered, and overlapped with `make ci` /
  `make release-today` from the new Makefile.
- `.gitmodules`. Declared `lib/common_core` but had no `path` /
  `url` and no gitlink in the index. Dead debris.
- `policy/LICENSE` and `docs/LICENSE`. The repo had **three** LICENSE
  files (root, policy/, docs/) that differed only in the copyright
  year. Kept the root copy (2025); deleted the other two.

### Verification

- `make ci` (fmt-check + lint + bats) — all green.
- `make lint` — 0 findings (was 156 pre-cleanup).
- `make fmt-check` — clean.
- `make test` — 23 passing, 0 failing.
- `make style` — "All Bash scripts passed style checks."

## [0.0.1]

### Note

This was the version stamped in the `VERSION` file before the date-based
scheme was adopted in `2026-06-27`. It is recorded here only as a marker
for the historical baseline; no per-feature release notes were maintained
prior to this point. See `git log` for granular history before the
adoption of this changelog.

Notable history (most recent first, sourced from `git log`):

- `2026-06-27` — Handed `capture_traffic.sh` (script + 109-line README) and
  `screenshot.sh` (script + 85-line README) over to `pentest_setup`. These
  were the only two files in the repo that the rest of the stack actually
  consumed; everything else here is standalone one-off utilities.
- `2025-09-11` — Introduced `compile.sh` CI/release wrapper (later replaced
  by `make ci` / `make release-today`).
- `2024-12-08` — Initial collection of Bash one-off utilities.

Subsequent releases use date-based versioning and carry per-release notes.
