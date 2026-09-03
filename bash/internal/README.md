# Internal Penetration Test Suite

A modular, task-based orchestrator for an internal network penetration test.
It chains reconnaissance, port scanning, Metasploit import/modules, web triage
and NetExec against the targets described under `/root/DATA/RECON/`.

It reuses tooling installed by **pentest_setup** (spoonmap, the MSF resource
scripts under `SCRIPTS/MSF/`, netexec) and follows the same `DATA/` directory
layout as `pentest_setup/config/config.sh`, sourcing **common_core** for
logging and helpers.

## Layout

```
bash/internal/
├── run_internal_pentest.sh   # orchestrator (auto-discovers tasks)
├── internal_lib.sh           # common_core bootstrap + shared helpers + paths
├── config/
│   └── default.conf          # overridable paths / tunables / task toggles
└── tasks/
    ├── 00-validate.sh         # verify (or prompt for) targets.txt; make dirs
    ├── 01-excludes.sh         # iptables DROP for excludes.txt (own chain)
    ├── 02-dns-lookup.sh       # PTR/A lookups; harvest domains
    ├── 03-domain-controllers.sh # AD DC SRV lookups per domain
    ├── 04-spoonmap.sh         # TrustedSec spoonmap scan -> hosts/ip:ports
    ├── 05-msf-import.sh        # db_import scan XML into Metasploit
    ├── 06-gowitness.sh        # screenshot web ip:ports -> responsive list
    ├── 07-httpx-nuclei.sh     # httpx probe + nuclei on responsive web
    ├── 08-msf-modules.sh      # run SCRIPTS/MSF/modules/*.rc (delegates to
    │                          #   run_all_modules.sh: single session + parses
    │                          #   TEE for [+] successes; loop fallback)
    └── 09-netexec.sh          # nxc smb --pass-pol + nxc ldap
```

## Inputs (defaults, all overridable)

| File                         | Purpose                                  |
|------------------------------|------------------------------------------|
| `/root/DATA/RECON/targets.txt`  | IPs / CIDRs / hostnames to test (required) |
| `/root/DATA/RECON/excludes.txt` | IPs / CIDRs to iptables-block (optional)   |
| `/root/DATA/RECON/domains.txt`  | Seed AD domains (optional)                 |

Outputs land under `/root/DATA/OUTPUT/` (`TEE/`, `PORTSCAN/SPOONMAP/`, `DNS/`,
`WEB/`, `GOWITNESS/`, `MSF/`, and the work files in `INTERNAL/`).

## Usage

```bash
# Full run (needs root for the iptables/excludes and spoonmap masscan steps)
sudo run_internal_pentest.sh

# See what will run, in order
run_internal_pentest.sh --list

# Run a single step / skip a step
run_internal_pentest.sh --task 04-spoonmap
run_internal_pentest.sh --skip 01-excludes

# Preview everything without executing any tool
run_internal_pentest.sh --dry-run

# Override paths / tunables / task toggles
run_internal_pentest.sh --config /path/to/my.conf
```

Once deployed by `scripts/install.sh`, the suite lives at
`~/DATA/TOOLS/SCRIPTS/bash/internal/` (the whole `bash/` tree is mirrored
automatically — no `install.sh` array edits are needed to add a task).

## Extending it

Tasks are **discovered**, not hardcoded. Drop a new `tasks/NN-name.sh` that
defines a `run_task_NN_name()` function (dashes in the file name become
underscores in the function name); it is picked up automatically in `NN`
order. Shared paths and helpers (`LOG`, `internal::require_cmd`,
`internal::run`, the `DATA/` path variables, the `*_FILE` work files) are all
provided by `internal_lib.sh`, which the orchestrator sources before any task.

Disable or make a task fatal from a config file:

```bash
TASK_ENABLED["01-excludes"]=false
TASK_REQUIRED["04-spoonmap"]=true
```

## Dependencies

- **common_core** at `~/.config/bash/lib/common_core/util.sh` (falls back to
  minimal built-ins if absent).
- Tools installed by **pentest_setup**: `spoonmap.py`, `msfconsole`
  (+ initialised `msfdb`), the `SCRIPTS/MSF/` resource scripts, `gowitness`,
  `httpx`, `nuclei`, `nxc`, and a DNS resolver (`dig`/`host`/`nslookup`).

Missing *required* tools abort a task; missing *optional* tools (gowitness,
httpx, nuclei) are logged and skipped so the rest of the run proceeds.
