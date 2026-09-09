# External Recon Suite

The recon suite's entry point is **`run_recon.sh`**. For the full reference —
layout, phases, scope model, tool coverage and the exact httpx/nuclei command
forms — see **[`README_UNIFIED.md`](README_UNIFIED.md)** and
**[`FRAMEWORK_OVERVIEW.md`](FRAMEWORK_OVERVIEW.md)**.

## Quick start

```bash
# 1. Scaffold an engagement directory (targets.txt / domains.txt templates).
./setup_engagement.sh acme-pentest
cd ~/engagements/acme-pentest
vim targets.txt        # IPs / CIDRs / hosts to scan
vim domains.txt        # root domains to enumerate (optional)

# 2. Run the suite.
export ENGAGEMENT_DIR="$PWD"
/path/to/recon/run_recon.sh \
    -e "$ENGAGEMENT_DIR" \
    -t "$ENGAGEMENT_DIR/targets.txt" \
    -d "$ENGAGEMENT_DIR/domains.txt" \
    --config /path/to/recon/config/unified-default.conf
```

## Common invocations

```bash
run_recon.sh ... --dry-run                 # preview without executing
run_recon.sh ... --only 04-portscan,05-web # run a subset
run_recon.sh ... --enable 02-dns-email,03-cloud   # add opt-in phases
run_recon.sh ... --engine naabu            # fast port sweep -> nmap -sV
run_recon.sh ... --resume                  # skip phases already complete
run_recon.sh --list                        # list phases
run_recon.sh --update-tools                # update ProjectDiscovery tools (pdtm)
```

## Phases

`00-validate → 01-osint → [02-dns-email] → [03-cloud] → 04-portscan → 05-web
→ 06-vuln → 07-report`. Phases 02/03 are opt-in.

## Scope & review gate

`targets.txt` is scanned; `domains.txt` is enumerated; the two never cross.
With no `domains.txt`, phase 01 derives candidate domains from the IP scope and
stops at a review gate (exit 3) — approve the apexes into `domains.txt` and
re-run with `--resume`.

Exit codes: `0` ok · `1` deps · `2` input · `3` awaiting domain review ·
`4` phase failed.
