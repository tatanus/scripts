# Unified External Recon Suite (`run_recon.sh` v2.0.0)

Combines the staged scanning engine of `../recon_new.sh` with the modular
breadth of this `recon/` suite, in the project's mandated Bash style
(`set -uo pipefail`, `function name()`, `[[ ]]`, `shfmt -i4 -ci -sr`,
header blocks, source guards, no `set -e`).

## Layout

```
run_recon.sh              orchestrator (argv, config, phase loop, state/resume,
                          summary, sudo prime, signal cleanup)
lib/recon_lib.sh          logging bridge, run()/run_pipe(), state, signals, gate
lib/scope_lib.sh          scope expansion + nmap-XML -> web-URL derivation
lib/discovery_lib.sh      8-technique IP->domain discovery + provenance
phases/00-validate.sh     env + input validation, output tree, scope expansion
phases/01-osint.sh        subfinder + bbot(passive) + asnmap + cdncheck + crt.sh
                          + dnsx; or IP->domain discovery + review gate
phases/02-dns-email.sh    DNS/SPF/DMARC/DKIM/MX/MTA-STS + SMTP  (opt-in)
phases/03-cloud.sh        M365/Entra/Azure/SharePoint/Teams/B2C/SAML + Graph (opt-in)
phases/04-portscan.sh     nmap (default) or spoonmap
phases/05-web.sh          gowitness v3 (smart port derivation) + httpx + whatweb
phases/06-vuln.sh         nuclei + nmap NSE + msfconsole (opt-in) + testssl (opt-in)
phases/07-report.sh       aggregate JSON/summary (+ analysis_and_output.sh)
config/unified-{quick,default,aggressive}.conf
```

## Scope model (inherited from recon_new.sh)

`targets.txt` feeds scanning only; `domains.txt` feeds enumeration only.
Resolved IPs are recorded but never auto-scanned. If `domains.txt` is absent,
phase 01 derives candidate apex domains from the IP scope and stops at a
**review gate** (exit code 3) — you copy the approved apexes into `domains.txt`
and re-run.

## Usage

```bash
export ENGAGEMENT_DIR=~/engagements/acme
mkdir -p "$ENGAGEMENT_DIR"
printf '203.0.113.0/24\n' > "$ENGAGEMENT_DIR/targets.txt"
printf 'acme.com\n'       > "$ENGAGEMENT_DIR/domains.txt"

# full default run
./run_recon.sh -e "$ENGAGEMENT_DIR" -t "$ENGAGEMENT_DIR/targets.txt" \
    -d "$ENGAGEMENT_DIR/domains.txt" --config config/unified-default.conf

# preview only
./run_recon.sh -e "$ENGAGEMENT_DIR" -t "$ENGAGEMENT_DIR/targets.txt" --dry-run

# add the opt-in cloud/email phases
./run_recon.sh ... --enable 02-dns-email,03-cloud

# resume, re-run one phase, pick the spoonmap engine
./run_recon.sh ... --resume
./run_recon.sh ... --only 05-web --force
./run_recon.sh ... --engine spoonmap   # needs RECON_SPOONMAP_PATH
```

Exit codes: `0` ok · `1` deps · `2` input · `3` awaiting domain review ·
`4` a phase failed.

## Tool coverage

| Tool | Phase | Role |
|------|-------|------|
| subfinder, bbot | 01 | subdomain enumeration (passive) |
| tldfinder | 01 | related/sibling org domains -> review candidates |
| asnmap, cdncheck | 01 | ASN / CDN context |
| crt.sh (curl) | 01 | certificate transparency |
| dnsx, tlsx | 01 / discovery | resolution, cert names |
| naabu | 04 | fast port sweep feeding `nmap -sV` (`--engine naabu`) |
| nmap | 04 / 06 | service detection; NSE (`vuln` / `default,safe,vuln`) |
| spoonmap | 04 | optional masscan engine (`--engine spoonmap`) |
| gowitness (v3) | 05 | screenshots (smart port derivation) |
| urlfinder | 05 | passive historical URLs -> httpx/nuclei |
| httpx | 05 / 06 | fingerprint; live-host pre-filter for nuclei |
| whatweb | 05 | tech fingerprint |
| nuclei | 06 | template scan (`-t` set from the mandated command form) |
| msfconsole | 06 | opt-in resource-script pass (`MSF_ENABLED=1`) |
| testssl | 06 | opt-in TLS analysis (`RECON_TESTSSL_ENABLED=1`) |
| vulnx | 06 | enrich discovered CVE IDs (severity/CVSS/EPSS/KEV) |
| m365_recon_NG.sh | 02 / 03 | DNS/email + M365/Entra/Azure/msgraph |
| analysis_and_output.sh | 07 | aggregate report |
| pdtm | n/a | tool management: `run_recon.sh --update-tools` |

The mandated command forms are used verbatim:

```
cat urls.txt | httpx -title -status-code -web-server -vhost -o httpx.out
cat urls.txt | httpx -silent | nuclei -ni -o nuclei.out -t dns -t headless \
  -t http/default-logins -t http/exposed-panels -t http/exposures -t http/fuzzing \
  -t http/global-matchers -t http/honeypot -t http/iot -t http/takeovers \
  -t http/vulnerabilities -t network/default-login -t network/enumeration \
  -t network/enumeration/smtp -t network/exposures -t network/honeypot \
  -t network/misconfig -t network/vulnerabilities
```

## Notes / follow-ups

- Phases 02/03 delegate to `m365_recon_NG.sh`; phase 07 can call
  `analysis_and_output.sh`. Those modules are used as-is (already compliant).
- The discovery normalizer uses a compact public-suffix heuristic; the
  `recon_new.sh` original had a fuller PSL-aware reducer if deeper accuracy is
  needed later.
- `msfconsole` and `testssl` are off by default (`MSF_ENABLED`,
  `RECON_TESTSSL_ENABLED`). `testssl` was not in the requested phase-6 list but
  is included as a clearly-gated extra since it was in the old suite.
