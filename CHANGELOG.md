# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the project-wide date-based versioning scheme
(`YYYY.MM.DD.N`).

## [Unreleased]

## [2026.09.17.3] - 2026-09-17

### Removed
- The **internal** penetration-test suite (`bash/internal/`), the **external**
  recon framework (`bash/recon/`), and the **M365/Entra/Azure** library
  (`bash/lib/m365/` + `m365.sh`) were moved out of this repo into **pentest_menu**
  (`pentest_menu/suites/internal/`, `pentest_menu/suites/external/`, and the
  m365 library alongside the external suite), where they are now exposed as menu
  tasks. This repo keeps only the standalone one-off utilities under `bash/`
  and `python/`.

### Changed
- Structure/lifecycle tests no longer assert the moved `bash/recon` / `bash/lib`
  subtrees; they assert the standalone `bash/logger.sh` / `bash/safe_source.sh`
  utilities instead. README updated to match.


## [2026.09.17.2] - 2026-09-17

### Changed
- **Recon suite now hard-depends on common_core (Bash 4+)** and the M365 logic
  is consolidated into one canonical library. `bash/lib/m365.sh` was rebuilt
  from the suite's richer implementation (it previously held a junior copy
  extracted from pentest_menu): it aggregates a new `bash/lib/m365/` package —
  `core.sh` (common_core bridge + `have_cmd`/`run_with_timeout`/`die`/
  `dns_query_generic`/… shims + JSON/HTTP/SMTP/cloud helpers) plus the relocated
  `dns_email_recon.sh`, `entra_azure_recon.sh`, `msgraph_recon.sh`,
  `services_recon.sh`, `smtp_recon.sh`, `osint.sh`, `analysis_and_output.sh` —
  and exposes `main`/`usage` and an `m365::analyze <domain> [json_out]` entry.
- `bash/recon/m365_recon_NG.sh` reduced to a thin launcher that sources
  `../lib/m365.sh`. `run_recon.sh` now requires common_core (was an optional
  logger bridge with a `common_utils.sh` fallback); `lib/recon_lib.sh`'s
  `have_cmd` delegates to `cmd::exists`; `phases/07-report.sh` points at the
  relocated `analysis_and_output.sh`.

### Removed
- `bash/recon/{common_utils.sh,dns_utils.sh,smtp_utils.sh,web_utils.sh,
  json_utils.sh,cloud_surface_utils.sh}` — their logging/color/`have_cmd`/DNS
  reimplementations are replaced by common_core, and their M365-specific helpers
  fold into `bash/lib/m365/core.sh`. Also fixes a latent bug: `die` was called
  on error paths but defined nowhere; it is now provided by `core.sh`.

## [2026.09.17.1] - 2026-09-17

### Added
- `bash/lib/m365.sh`: shared Microsoft 365 / Entra OSINT library (`m365::`
  namespace) — tenant discovery, user-realm/MFA info, autodiscover + federation
  metadata, SaaS-service detection, and domain correlation. Sourceable by any
  pentest tool as `${SCRIPTS_DIR}/bash/lib/m365.sh`. Generic DNS lookups
  delegate to common_core's `dns::` helpers (util_dns.sh) instead of
  re-implementing them.

## [2026.09.17.0] - 2026-09-17


### Changed

- `bash/internal/internal_lib.sh`: `TARGETS_FILE`/`EXCLUDES_FILE` now default to
  `${DATA_DIR}/targets.txt` / `excludes.txt` (was `${RECON_DIR}/...`). These are
  engagement INPUTS and live at the DATA root -- matching pentest_setup's
  exported values (which internal_lib defers to when `pentest.env.sh` is present)
  and every other consumer in the stack. `RECON/` is for derived recon outputs.

## [2026.09.16.2] - 2026-09-16


### Removed

- `bash/recon_new.sh` is no longer tracked (now gitignored). It is a
  work-in-progress rewrite that does not yet pass the format/lint gates; it had
  been committed inadvertently. Its staged scanning engine is already merged
  into `bash/recon/`, so nothing depends on it, and it remains on disk as a
  local archive.

### Fixed

- Lifecycle tests are now hermetic w.r.t. `DATA_DIR`. Since `install.sh`'s
  `TARGET_ROOT` honors `DATA_DIR`, an ambient `DATA_DIR` in the caller's shell
  sent the deploy outside the sandbox HOME and failed the `${HOME}/DATA/...`
  assertions. The test harness now pins `DATA_DIR="${HOME}/DATA"` in
  `setup_temp_home` (and unsets it on teardown), which also exercises the
  `DATA_DIR` code path.

## [2026.09.16.1] - 2026-09-16


### Changed

- `install.sh` now honors `DATA_DIR`: `TARGET_ROOT` is
  `${DATA_DIR:-${HOME}/DATA}/TOOLS/SCRIPTS` (was a hardcoded `${HOME}/DATA/...`).
  This keeps the deploy under the same tree the internal/recon suites read from
  (`internal_lib.sh` derives `SCRIPTS_DIR` from `${DATA_DIR}`) when the stack is
  relocated; the default is unchanged since `DATA_DIR` is unset at this stage.
- Doc/comment paths that read `/root/DATA/...` now read `${HOME}/DATA/...`
  (internal_lib.sh, run_internal_pentest.sh, bash/internal/README.md) so they
  are correct for non-root runs. The one intentional exception is
  `08-msf-modules.sh`'s `MSF_HARDCODED_RUNNER` -- that literal `/root/DATA/...`
  string is the path baked into pentest_setup's shipped `.rc` files, which the
  task sed-rewrites to the real `MSF_SCRIPTS_DIR` at runtime, so it must match
  the shipped content and stays as-is.

## [2026.09.16.0] - 2026-09-16


### Changed

- `bash/internal` now shares the stack's unified env: `internal_lib.sh` sources
  the deployed `pentest.env.sh` when present, and its variable names were
  aligned to the engagement contract — `DNS_SERVERS`->`DNS_SERVER`,
  `DC_IP_LIST_FILE`->`DC_IP_FILE`, `DC_FQDN_LIST_FILE`->`DC_FQDN_FILE` (across
  `internal_lib.sh` and tasks `02-dns-lookup`/`03-domain-controllers`), DC
  output files defaulting under `RECON/`. Standalone `${VAR:-default}` fallbacks
  are retained for use without the env file.

### Fixed

- `bash/internal` `03-domain-controllers`: now writes three DC output files in
  `WORK_DIR` — `DC_IP_LIST.txt` (unique IPs), `DC_FQDN_LIST.txt` (unique
  FQDNs), and `DC_LIST.txt` (the `IP<TAB>FQDN` mapping; apex-A IPs are
  reverse-resolved to recover their FQDN). The raw `dig`/`host`/`nslookup`
  output of every query is saved to `DNS/dc_raw_queries.txt`.

- `bash/internal` `03-domain-controllers`: reports the number of domain
  controllers identified per domain (logged per domain and written to
  `DNS/domain_controllers_by_domain.txt`), alongside the overall total.

- `bash/internal` `03-domain-controllers`: now also performs an apex-A ("DA")
  lookup of each identified domain (in AD the bare domain name resolves to
  every DC's IP), in addition to the DC SRV records — and honors `DNS_SERVERS`
  so SRV/A queries hit the internal DNS/domain controllers rather than the
  host's default resolver (the same internal-DNS gap fixed in `02-dns-lookup`).

- `bash/internal` `02-dns-lookup`: DNS enumeration now works for CIDR-scoped
  internal engagements. The task rebuilt around `nmap -sL`, which expands
  CIDRs and does the PTR sweep in one pass — the old per-host `dig` loop
  skipped every `*/*` (CIDR) entry, so a subnet-scoped scope resolved nothing.
  Added a `DNS_SERVERS` knob so the sweep queries the internal DNS / domain
  controllers (`nmap --dns-servers`); PTR of internal IPs against a public
  resolver returns nothing. `dig`/`host`/`nslookup` remain the no-nmap
  fallback (bare IPs/hostnames only).

- `bash/recon`: phase `00-validate` no longer crashes with `line 60: 2:
  unbound variable` under `set -u`. `scope_expand`'s space-separated counts
  were not split because the suite runs under `IFS=$'\n\t'`; a local `IFS`
  now re-admits the space (and the positionals are defaulted).
- `bash/recon`: `--engagement`/`--targets`/`--domains` are resolved to
  absolute paths up front (new `recon_abspath`), so phases that `cd` into
  output subdirs (gowitness, spoonmap) no longer fail with `source is not
  readable` when relative paths are passed. The phase-05 gowitness fallback
  also now feeds an expanded one-address-per-line list instead of raw
  `targets.txt` (gowitness cannot expand CIDRs).

### Added

- `bash/recon`: every tool's output is saved. `run`/`run_pipe` mirror each
  tool's combined stdout+stderr to `OUTPUT/TEE/<tool>.<ts>.tee` (captured
  even when the terminal is silenced with `> /dev/null 2>&1`), and a master
  session log `LOGS/recon_<ts>.full.log` captures all STDOUT/STDERR of the run.

- Unified external-recon framework under `bash/recon/`: a phase-based
  orchestrator `run_recon.sh` (v2.0.0) with `lib/` (recon_lib, scope_lib,
  discovery_lib) and `phases/` (`00-validate` … `07-report`), plus
  `config/unified-{quick,default,aggressive}.conf` and `README_UNIFIED.md`.
  Merges the staged scanning engine of `bash/recon_new.sh` with the breadth of
  the previous task-based suite; adds naabu (fast port sweep), tldfinder,
  urlfinder and vulnx, and selectable port-scan engines (nmap/naabu/spoonmap).

### Removed

- Superseded task-based recon entrypoint `bash/recon/run_external_recon_suite.sh`,
  its `bash/recon/tasks/00-validate.sh … 04-testssl.sh`, and the old
  `bash/recon/config/{default,quick,aggressive}.conf` profiles. Their behavior
  is now provided by `run_recon.sh` + `phases/` + `config/unified-*.conf`.
  (An untracked `bash/old_recon/` copy remains as a local archive.)

### Changed

- `install.sh` now marks every deployed `*.sh` executable after each subtree
  copy (a blanket `find … -name '*.sh' -exec chmod +x` pass), including files
  skipped as unchanged. Previously only sources that already carried the exec
  bit were made executable, so sourced-but-not-executable scripts (the recon
  `lib/`/`phases/` and intel modules) deployed non-executable.
- `install.sh install` now detects a previous install (via a new
  `${TARGET_ROOT}/VERSION` marker) and, when run interactively, prompts before
  overwriting/updating it. `-f`/`--force` bypasses the prompt; `--dry-run`
  never prompts; a non-interactive shell proceeds. The marker is written after
  a successful install and removed on uninstall. (`update` is unaffected — its
  checksum comparison already governs re-copies.)
- `bash/internal/tasks/08-msf-modules.sh` now hands off to the shipped
  `run_all_modules.sh` (deployed by pentest_setup beside the MSF scripts) when
  it can — running every module in a single `msfconsole` session and parsing
  the `OUTPUT/TEE` spool logs for Metasploit successes (`[+]`), so an internal
  run ends with a consolidated findings summary instead of just `.tee` files.
  It passes `MSF_TEE_DIR`/`MSF_SCRIPTS_HOME`/`MSF_MODULES_DIR` so the engagement
  paths line up. The previous per-module `msfconsole -q -r` loop is retained as
  a fallback and is used when `MSF_MODULES_INCLUDE`/`_EXCLUDE` glob filters are
  set, when the helper is absent, or when the install is relocated off the
  canonical `/root/DATA` path (where the rc files' hardcoded runner-load line
  must be rewritten).
- Added explicit OS guards to the four Linux-only Bash scripts, which
  previously ran bare `apt`, `systemctl`, and GNU `sed -i` on any platform
  and would abort mid-run (often after a sudo prompt) on macOS. Each now
  refuses up front with a clear reason:
  - `bash/wireless.sh` — requires the Linux Wi-Fi stack (`iw`, `airmon-ng`,
    `nmcli`) and `apt`.
  - `bash/setup-mail-server.sh` — targets Debian/Ubuntu (`apt-get`, systemd,
    Postfix/OpenDKIM).
  - `bash/update_gophish.sh` — manages a systemd service and `/etc/gophish`
    paths.
  - `bash/update-mail-domain.sh` — edits `/etc/postfix` and reloads services
    via `systemctl`.

### Added

- `python/azure_tenant_enum.py` — resolve a DNS domain against Azure AD /
  Entra ID via public, unauthenticated Microsoft endpoints to recover the
  tenant GUID, federation brand / company name, and namespace type; also
  identifies any domains supplied via `-f/--file`. Outputs text, JSON, or
  CSV (`-F`), to stdout or a file (`-o`). Marked executable to match the
  other CLI tools in `python/`.
  - Reports the identity provider fronting each tenant (`auth_provider`:
    Okta, Microsoft ADFS, Ping, OneLogin, Shibboleth, Duo, Google, Auth0,
    CAS, or Entra-managed), derived unauthenticated from the federation
    AuthURL.
  - Optional `--mfa-test` for MFA / authentication posture, best-effort by
    input (useful when an engagement has a target user but no password):
    `-u USER -p PASS` (or `--prompt-password`) runs a real ROPC sign-in test
    across several first-party clients and maps the `AADSTS` result to MFA
    enforcement / bypass (MFASweep technique); `-u USER` alone runs an
    unauthenticated `GetCredentialType` probe (account existence, IdP,
    Seamless SSO, has-password); neither reports domain-level posture only.
    Single-account (not a sprayer), halts on smart-lockout, and prints an
    authorization warning before any sign-in attempt.
  - Resolves the `*.onmicrosoft.com` tenant name from multiple sources (most
    authoritative first), since Microsoft has curtailed the Autodiscover
    `GetFederationInformation` endpoint (it now only echoes the queried domain):
    the ACS metadata endpoint
    (`accounts.accesscontrol.windows.net/{domain-or-tenantId}/metadata/json/1`,
    the TeamFiltration technique; authoritative but empty on newer tenants as
    ACS is retired); the Office 365 **DKIM selector CNAMEs**
    (`selector1/2._domainkey.<domain>`, whose target embeds the tenant name —
    reliable org-published DNS, recovers non-obvious names such as
    `paulweiss.com` → `pwrwg`, `tesla.com` → `teslamotorsinc`; requires
    dnspython, imported softly); and a GUID-verified guess (domain/brand-derived
    candidates accepted only when `<candidate>.onmicrosoft.com` resolves to the
    same tenant GUID). A wrong name is never reported; the name is blank only
    when every source fails (e.g. a domain whose mail isn't Exchange Online).
    Tenant GUID, brand, and namespace type remain reliable regardless.
  - Enumerates additional tenant domains with **high certainty only**. Since a
    full unauthenticated domain dump is no longer possible (GetFederationInfo
    curtailed, ACS retired), candidate domains — from ACS metadata, `-f/--file`,
    and optionally Certificate Transparency (`--crt`, `--crt-limit`) — are each
    confirmed to belong to the tenant by matching their openid-configuration
    tenant GUID (checked concurrently). Only verified domains are reported in a
    consolidated `verified_tenant_domains` list, and every per-domain record
    gains a `same_tenant` flag; unverifiable candidates are dropped. CT uses
    crt.sh with a **certSpotter fallback** (crt.sh is frequently 5xx/404;
    `CERTSPOTTER_API_KEY` raises the certSpotter rate limit); an outage of one
    source degrades gracefully to the others / authoritative results.

## [2026.08.26.0] - 2026-08-26

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
