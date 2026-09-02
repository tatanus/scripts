# scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/tatanus/scripts/actions/workflows/main.yml/badge.svg)](https://github.com/tatanus/scripts/actions/workflows/main.yml)
[![Last Commit](https://img.shields.io/github/last-commit/tatanus/scripts)](https://github.com/tatanus/scripts/commits/main)

![Bash >=4.0](https://img.shields.io/badge/Bash-%3E%3D4.0-4EAA25?logo=gnu-bash&logoColor=white)
![Python >=3.12](https://img.shields.io/badge/Python-%3E%3D3.12-3776AB?logo=python&logoColor=white)

---

## Overview

A grab-bag of standalone one-off Bash and Python utilities used during
pen-testing engagements. Unlike `common_core` / `bash_setup` /
`pentest_setup`, this repo is **not** a shell-environment library — these
scripts are intended to be invoked directly. `install.sh` deploys the
`bash/` and `python/` trees into `${HOME}/DATA/TOOLS/SCRIPTS/` so they
end up next to the engagement-data directory created by `pentest_setup`.

It is the third repo in the five-repo stack:

```
common_core  →  bash_setup  →  scripts  →  pentest_setup  →  pentest_menu
```

---

## Requirements

- **Bash 4+** (macOS users: `brew install bash`)
- **Python 3.12+** for the `python/` scripts
- **`common_core`** installed at `${HOME}/.config/bash/lib/common_core/`
- **`bash_setup`** installed (its `bashrc` deployed to `${HOME}/.bashrc`)
- `install.sh`'s preflight refuses to run unless both are present.
- Recommended for development:
  - `shellcheck` (lint)
  - `shfmt` (format) — must support `-i 4 -ci -sr`
  - `bats` (test)

---

## Quick Start

```bash
# Prereqs: common_core and bash_setup already installed
git clone https://github.com/tatanus/scripts.git
cd scripts
make install   # equivalent to: bash install.sh
```

`install.sh` deploys the entire `bash/` and `python/` trees into
`${HOME}/DATA/TOOLS/SCRIPTS/`, creating the directory (and parents) if
missing. Use `bash install.sh update` to refresh only the changed files
on subsequent runs, or `bash install.sh uninstall` to remove the deployed
copy.

---

## Repository Layout

```
.
├── install.sh                  # deploy bash/ + python/ to ${HOME}/DATA/TOOLS/SCRIPTS/
├── Makefile                    # quality gates + release automation
├── VERSION                     # date-based version: YYYY.MM.DD.N
├── CHANGELOG.md                # Keep a Changelog
├── bash/                       # standalone Bash utilities
│   ├── auto-mount-shares.sh    # bulk SMB share mount helper
│   ├── gophish_install.sh      # GoPhish installer (Linux-only)
│   ├── update_gophish.sh       # GoPhish updater (Linux-only)
│   ├── setup-mail-server.sh    # mail server bootstrap (Debian/Ubuntu-only)
│   ├── update-mail-domain.sh   # mail-domain rotation (Debian/Ubuntu-only)
│   ├── wireless.sh             # wireless interface helpers (Linux-only)
│   ├── mount-try.sh            # mount with backoff
│   ├── logger.sh               # structured logging (see docs/LOGGER_README.md)
│   ├── safe_source.sh          # safe re-sourcing helper (see docs/SAFE_SOURCE_README.md)
│   ├── internal/               # internal penetration-test suite (see bash/internal/README.md)
│   │   ├── run_internal_pentest.sh   # task-based orchestrator (auto-discovers tasks/)
│   │   ├── internal_lib.sh           # common_core bootstrap + DATA/ paths + helpers
│   │   ├── config/default.conf       # overridable paths / tunables / task toggles
│   │   └── tasks/                    # 00-validate … 09-netexec (drop in NN-name.sh)
│   └── recon/                  # external reconnaissance mini-framework
│       ├── FRAMEWORK_OVERVIEW.md
│       ├── README_RECON_SUITE.md
│       ├── run_external_recon_suite.sh
│       ├── dns_email_recon.sh, dns_utils.sh
│       ├── entra_azure_recon.sh, msgraph_recon.sh
│       ├── m365_recon_NG.sh
│       ├── services_recon.sh, smtp_recon.sh, smtp_utils.sh
│       ├── cloud_surface_utils.sh, common_utils.sh
│       ├── json_utils.sh, web_utils.sh
│       ├── osint.sh
│       ├── setup_engagement.sh
│       ├── analysis_and_output.sh
│       ├── config/             # default config for the recon framework
│       └── examples/
├── python/                     # standalone Python utilities
│   ├── ad_dns_enum.py          # Active Directory DNS enumeration
│   ├── azure_tenant_enum.py    # Azure AD tenant/domain/company enumeration
│   ├── crypto_utils.py
│   ├── dhcp_enum.py
│   ├── EvilWinRM.py
│   ├── extractDefaultCreds.py
│   ├── getAESKey.py
│   ├── LDAP.AD.py
│   ├── mdns_enum.py
│   ├── nessus_cli.py, nessus_parser.py
│   ├── rtsp.py
│   └── upnp.py
├── docs/                       # standalone usage docs
│   ├── LOGGER_README.md
│   ├── SAFE_SOURCE_README.md
│   └── M365_RECON_NG.md
├── tests/                      # BATS coverage
└── tools/
    └── check_bash_style.sh     # comprehensive style scan
```

### Notable docs

- `bash/logger.sh` — structured logging utility (`info`/`warn`/`error`/
  `debug`/`pass`/`fail`). See [`docs/LOGGER_README.md`](docs/LOGGER_README.md).
- `bash/safe_source.sh` — safely re-source other shell scripts and roll
  back env changes. See [`docs/SAFE_SOURCE_README.md`](docs/SAFE_SOURCE_README.md).
- `bash/recon/` — see its own [`FRAMEWORK_OVERVIEW.md`](bash/recon/FRAMEWORK_OVERVIEW.md)
  and [`README_RECON_SUITE.md`](bash/recon/README_RECON_SUITE.md).
- `bash/recon/m365_recon_NG.sh` — see [`docs/M365_RECON_NG.md`](docs/M365_RECON_NG.md).
- `bash/internal/` — modular internal penetration-test suite (spoonmap →
  Metasploit → gowitness/httpx/nuclei → NetExec). See its own
  [`README.md`](bash/internal/README.md). It consumes tools and MSF
  resource scripts deployed by `pentest_setup` at runtime (resolved by
  path, degrading gracefully when a tool is absent).

### What's not here

The previous versions of `screenshot.sh` and `capture_traffic.sh` used to
live in this repo. Both were handed over to `pentest_setup` (the natural
owner) in the `2026-06-27` move. If you need them, install `pentest_setup`
and they will be sourced into your interactive shell via the
`${BASH_DIR}/pentest.sh` hook.

---

## Make targets

| Target              | What it does                                                     |
|---------------------|------------------------------------------------------------------|
| `make help`         | Show all targets.                                                |
| `make ci`           | Format check + lint + tests. **Non-mutating. Run before PRs.**   |
| `make fmt`          | Auto-format with `shfmt -i 4 -ci -sr` (writes in place).         |
| `make fmt-check`    | Verify formatting without writing.                               |
| `make lint`         | `shellcheck -x` across `git ls-files '*.sh'`.                    |
| `make test`         | `bats -r tests`.                                                 |
| `make style`        | Comprehensive style scan via `tools/check_bash_style.sh`.        |
| `make install`      | `bash install.sh` — deploy bash/ + python/ to `${HOME}/DATA/TOOLS/SCRIPTS/`. |
| `make show-version` | Print current `VERSION`.                                         |
| `make release V=…`  | Cut a release (see [Releases](#releases)).                       |
| `make release-today`| Cut a release using today's UTC date (`YYYY.MM.DD.0`).           |

The mandated formatter flags are **`-i 4 -ci -sr`**. Do not add `-bn` or
`-kp` anywhere.

---

## Cross-repo contract

- **Depends on**: `common_core` (installed at
  `${HOME}/.config/bash/lib/common_core/util.sh`) and `bash_setup`
  (`${HOME}/.bashrc` deployed). `install.sh` will refuse to run unless
  both are present.
- **Deploys to**: `${HOME}/DATA/TOOLS/SCRIPTS/{bash,python}/`. Both
  trees are mirrored verbatim into that target.
- **Provides for the rest of the stack**: nothing implicit — these are
  standalone utilities, invoked directly.

---

## Releases

Date-based four-part versioning (`YYYY.MM.DD.N`), tracked in `VERSION`
and `CHANGELOG.md`. To cut a release:

```bash
# 1. Land your changes as normal commits with `## [Unreleased]` notes.
git add …; git commit -m "feat(…): …"; git push

# 2. Cut the release. `make release` will:
#    - run `make ci` (refuse if anything fails)
#    - refuse on a dirty working tree
#    - stamp `## [Unreleased]` -> `## [Vx] - YYYY-MM-DD` (UTC) in CHANGELOG
#    - write VERSION
#    - single commit `chore(release): cut Vx`
#    - annotated tag `vVx`
#    - `git push --follow-tags`
make release-today          # today's UTC date.0
make release-today N=1      # second cut of the same UTC day -> .1
make release V=2026.06.27.0 # explicit version
```

---

## License

MIT — see [LICENSE](LICENSE). Each script may also include header-based
licensing or author notes.
