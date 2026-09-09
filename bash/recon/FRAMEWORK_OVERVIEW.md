# External Reconnaissance Framework — Overview

Modular external-recon framework for penetration-testing engagements. The
entry point is **`run_recon.sh`** (v2.0.0): a thin orchestrator that runs an
ordered set of phases, each a self-contained module under `phases/`, sharing
helpers from `lib/`. It combines the staged scanning engine of the original
`../recon_new.sh` with the breadth of the earlier task-based suite, written to
the project Bash style (`set -uo pipefail`, `function name()`, `[[ ]]`,
`shfmt -i4 -ci -sr`, header blocks, source guards — no `set -e`).

> The previous `run_external_recon_suite.sh` + `tasks/` + `config/*.conf`
> design has been replaced by this framework. See `README_UNIFIED.md` for
> full usage.

## Directory structure

```
recon/
├── run_recon.sh               # orchestrator (argv, config, phase loop, state)
├── lib/
│   ├── recon_lib.sh           # logging bridge, run()/run_pipe(), state, signals
│   ├── scope_lib.sh           # scope expansion + nmap-XML -> web-URL derivation
│   └── discovery_lib.sh       # 8-technique IP->domain discovery + provenance
├── phases/
│   ├── 00-validate.sh         # env/input validation, output tree, expansion
│   ├── 01-osint.sh            # subfinder/bbot/tldfinder/asnmap/cdncheck/crt.sh/dnsx
│   ├── 02-dns-email.sh        # DNS/SPF/DMARC/DKIM/MX/MTA-STS + SMTP  (opt-in)
│   ├── 03-cloud.sh            # M365/Entra/Azure/SharePoint/Teams/B2C/SAML (opt-in)
│   ├── 04-portscan.sh         # nmap (default) | naabu | spoonmap
│   ├── 05-web.sh              # gowitness v3 + urlfinder + httpx + whatweb
│   ├── 06-vuln.sh             # nuclei + nmap NSE + msfconsole + testssl + vulnx
│   └── 07-report.sh           # aggregate JSON/summary (+ analysis_and_output.sh)
├── config/                    # unified-{quick,default,aggressive}.conf
├── examples/                  # targets.txt.example, domains.txt.example
│
│  # Shared intel/util modules (used by phases 02/03/07 via m365_recon_NG.sh):
├── common_utils.sh  dns_utils.sh  smtp_utils.sh  web_utils.sh
├── cloud_surface_utils.sh  json_utils.sh
├── dns_email_recon.sh  entra_azure_recon.sh  m365_recon_NG.sh
├── services_recon.sh  smtp_recon.sh  osint.sh  msgraph_recon.sh
├── analysis_and_output.sh
└── setup_engagement.sh        # engagement-directory scaffolding helper
```

## Phase workflow

```
00-validate → 01-osint → [02-dns-email] → [03-cloud]
            → 04-portscan → 05-web → 06-vuln → 07-report
```

`02-dns-email` and `03-cloud` are opt-in (enable via `--enable` or `--only`).

## Scope model

`targets.txt` feeds scanning only; `domains.txt` feeds enumeration only.
Resolved IPs are recorded but never auto-scanned. If `domains.txt` is absent,
phase 01 derives candidate apex domains from the IP scope (techniques: scope,
rdns, tls, ike, http, smtp, smb-ldap, whois) and stops at a **review gate**
(exit code 3); the operator copies approved apexes into `domains.txt` and
re-runs with `--resume`. tldfinder-discovered sibling domains are handled the
same way (written to `related-domains-candidates.txt` for review).

## Configuration

Built-in defaults → `--config <profile>` → environment variables (highest
precedence). Profiles: `unified-quick` (naabu engine, minimal depth),
`unified-default` (balanced), `unified-aggressive` (full TCP/UDP, all NSE,
testssl on, dns-email + cloud phases enabled).

## Cross-cutting features

Per-phase `.done` state + `--resume`, `--only/--skip/--enable`, `--dry-run`,
`--fail-fast`, `--force`, privilege priming, recursive child-process cleanup on
Ctrl-C, config profiles, common_core logger bridge with local fallback,
`--update-tools` (pdtm), and provenance for discovery.

## Tooling

subfinder, bbot, tldfinder, asnmap, cdncheck, dnsx, tlsx, naabu, nmap (+NSE),
spoonmap (optional), gowitness (v3), urlfinder, httpx, whatweb, nuclei,
msfconsole (opt-in), testssl (opt-in), vulnx, and the M365/Entra/DNS-email
modules via `m365_recon_NG.sh`. Every tool is optional: a missing tool logs a
warning and the phase degrades rather than failing the run.

## Extending

Add a phase by dropping `phases/NN-name.sh` defining `run_phase_<name>` and
adding `NN-name` to `RECON_ALL_PHASES` (and, if it should run by default,
`RECON_DEFAULT_PHASES`) in `run_recon.sh`.
