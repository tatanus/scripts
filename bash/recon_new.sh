#!/usr/bin/env bash
#
# recon-pipeline.sh — staged external recon harness
#
#   discover -> bbot -> dnsx -> spoonmap -> gowitness -> urls -> httpx -> nuclei
#
# Scope model: STRICTLY SEPARATE.
#   domains.txt  feeds passive subdomain enumeration (bbot, dnsx) only.
#   targets.txt  feeds port/web scanning (spoonmap, gowitness) only.
#   Resolved IPs discovered by dnsx are recorded as recon artifacts but are
#   NEVER appended to the scan list. Nothing gets scanned that you did not
#   explicitly put in targets.txt.
#
# urls.txt for the httpx/nuclei stages is derived from gowitness output.
#
# DOMAIN DISCOVERY
#   If domains.txt is missing or empty, the 'discover' stage derives candidate
#   DNS domains from the IP scope in targets.txt using:
#       scope      hostnames already present in targets.txt
#       rdns       PTR records for every IP in scope (dnsx, else dig)
#       tls        certificate subject CN + SANs (tlsx, else httpx, else built in)
#       ike        IKE aggressive-mode ID_FQDN / ID_USER_FQDN payloads
#                  (ike-scan, elevated so it can bind source port 500)
#       http       HTTP Location redirects, CSP directives, response bodies (httpx)
#       smtp       MTA 220 greetings and EHLO responses (built-in grabber)
#       smb-ldap   SMB OS discovery + LDAP RootDSE naming contexts (nmap)
#       whois      registry org names, netnames, contact email domains
#   Results are reduced to registrable apexes, filtered against a hosting /
#   CDN / ISP / third-party denylist, and written to domains-candidates.txt
#   with full provenance. THE PIPELINE NEVER FEEDS THESE TO bbot ON ITS OWN:
#   review the candidates, copy the ones in scope to domains.txt, and re-run
#   with --resume. The target-based stages continue in the meantime.
#
# Usage:
#   ./recon-pipeline.sh [options]
#
# Options:
#   -t, --targets FILE      IP/CIDR/host scan scope        (default: ./targets.txt)
#   -d, --domains FILE      Root domains for enumeration   (default: ./domains.txt)
#   -o, --outdir DIR        Output directory               (default: ./recon-<timestamp>)
#   -r, --resume DIR        Reuse DIR and skip stages already marked complete
#       --only  a,b,c       Run only these stages
#       --skip  a,b,c       Run everything except these stages
#       --force             Re-run stages even if marked complete
#       --fail-fast         Abort the run on the first stage failure
#       --dry-run           Print the commands that would run, execute nothing
#       --spoonmap PATH     spoonmap.py, or the directory containing it
#                           (or set SPOONMAP_PATH). It runs with that directory
#                           as its working directory, so config.json, nse/ and
#                           tools/ resolve and its artifacts land beside them.
#       --spoonmap-args STR Args for spoonmap. Default is none: it is driven
#                           interactively from its own repo, reading ranges.txt
#                           / exclusions.txt / config.json there and leaving its
#                           artifacts beside them. Set this to run it unattended;
#                           "{TARGETS}"/"{OUTDIR}" are expanded.
#       --no-sudo           Do not elevate spoonmap or ike-scan (spoonmap's
#                           masscan phase fails; ike-scan falls back to
#                           --sport=0 and misses some concentrators)
#       --threads N         Concurrency hint for dnsx/httpx/tlsx (default: 50)
#       --list-stages       Print stage names and exit
#   -h, --help              This help
#
#   gowitness options:
#       --gw-threads N      Concurrent Chrome workers (default: 40; gowitness
#                           itself defaults to 6, which is far too few when
#                           filtered ports each hold a worker for the timeout)
#       --gw-timeout N      Seconds before a page is considered dead (default:
#                           10; gowitness defaults to 60)
#       --gw-delay N        Seconds between navigation and screenshot
#                           (default: 2; raise for JS-heavy apps)
#       --gw-full           Ignore spoonmap's results and expand every target
#                           over the large port list (34 ports x 2 schemes)
#       --gw-all-ports      Screenshot every open port spoonmap found, not
#                           just the ones that plausibly speak HTTP
#       --gw-trust-spoonmap Screenshot spoonmap's findings even when they fall
#                           outside targets.txt (use when spoonmap's ranges.txt
#                           is the authoritative scope)
#
#   Domain-discovery options:
#       --rediscover        Run discovery even when domains.txt already exists
#                           (writes candidates only; never overwrites domains.txt)
#       --disc  a,b,c       Run only these techniques
#       --no-disc a,b,c     Skip these techniques
#       --max-hosts N       Cap on IPs expanded from targets.txt (default: 8192)
#       --no-body-scrape    Do not harvest hostnames from HTTP response bodies
#       --keep-providers    Keep apex domains that look like carrier/ISP
#                           reverse DNS instead of filtering them out
#       --whois-max N       Cap on registry queries, one per /24 (default: 64)
#       --halt-on-review    Stop the whole run at the review gate instead of
#                           continuing with the target-based stages
#
# The gowitness stage reads spoonmap's nmap output (spoonmap_output.xml/.gnmap/
# .json, nmap_results/*.xml) and screenshots only the open ports that plausibly
# speak HTTP, one probe per URL with the scheme chosen from nmap's service
# detection. Falling back to --ports-large over a raw range costs 68 probes per
# host; on a filtered /24 that is the difference between a minute and two days.
# Results outside targets.txt are dropped, so the scope model still holds.
#
# Environment overrides: TARGETS DOMAINS OUTDIR SPOONMAP_PATH SPOONMAP_ARGS
#                        THREADS MAX_HOSTS WHOIS_MAX
#                        TLS_PORTS WEB_PORTS SMTP_PORTS SMB_LDAP_PORTS
#                        GOWITNESS_THREADS GOWITNESS_TIMEOUT GOWITNESS_DELAY
#
# Exit codes: 0 clean · 1 one or more stages failed · 2 awaiting domain review
#
# Requires bash 3.2+ (works with macOS system bash) and python3. Every scanner
# is checked in a preflight pass for the stages actually selected; discovery
# techniques whose tools are absent are skipped with a warning, not an error.
#
# ---------------------------------------------------------------------------
# AUTHORIZATION: only run this against scope you have written permission to
# test. bbot is invoked with "-ef active" so enumeration stays passive, and the
# rdns/whois discovery techniques are passive, but tls, ike, http, smtp and
# smb-ldap discovery all send traffic to the hosts in targets.txt — as do
# spoonmap, gowitness, httpx and nuclei.
# ---------------------------------------------------------------------------

set -euo pipefail

VERSION="1.6.0"
SCRIPT_NAME="$(basename "$0")"

# ------------------------------- configuration ------------------------------

TARGETS="${TARGETS:-targets.txt}"
DOMAINS="${DOMAINS:-domains.txt}"
OUTDIR="${OUTDIR:-}"
THREADS="${THREADS:-50}"
MAX_HOSTS="${MAX_HOSTS:-8192}"
WHOIS_MAX="${WHOIS_MAX:-64}"

TLS_PORTS="${TLS_PORTS:-443,465,636,993,995,1443,2443,3269,4443,5986,7443,8443,8834,9443,10443}"
WEB_PORTS="${WEB_PORTS:-80,443,3000,4443,5000,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,10000}"
SMTP_PORTS="${SMTP_PORTS:-25,587,2525}"
SMB_LDAP_PORTS="${SMB_LDAP_PORTS:-139,389,445,636,3268,3269}"

SPOONMAP_PATH="${SPOONMAP_PATH:-}"
# spoonmap is driven interactively and reads its scope, exclusions and config
# from its own repository (ranges.txt, exclusions.txt, config.json), so it is
# invoked with NO arguments and with its repo as the working directory. Its
# artifacts stay there, beside nse/ and tools/, where --resume expects them.
# Pass --spoonmap-args (or export SPOONMAP_ARGS) to drive it non-interactively;
# {TARGETS} and {OUTDIR} are expanded there if you use them.
SPOONMAP_ARGS="${SPOONMAP_ARGS:-}"

# gowitness tuning. Its own defaults (6 threads, 60s timeout, 3s delay) assume
# a handful of known-good URLs; pointed at raw IP ranges they turn every
# firewalled port into a 60-second stall on one of six workers.
GW_THREADS="${GOWITNESS_THREADS:-40}"
GW_TIMEOUT="${GOWITNESS_TIMEOUT:-10}"
GW_DELAY="${GOWITNESS_DELAY:-2}"
GW_MODE="auto"          # auto = use spoonmap's open ports; full = expand ports
GW_ALL_PORTS=0          # 1 = screenshot every open port, not just web-ish ones
# spoonmap drives masscan and ike-scan binds UDP source port 500; both need
# raw sockets, so both are invoked through sudo. Credentials are primed up
# front (see below) so a password prompt cannot stall the run hours later, and
# anything spoonmap writes as root is handed back to the invoking user.
SUDO=1

# Nuclei template selection, exactly as specified.
NUCLEI_TEMPLATES=(
  -t dns
  -t headless
  -t http/default-logins
  -t http/exposed-panels
  -t http/exposures
  -t http/fuzzing
  -t http/global-matchers
  -t http/honeypot
  -t http/iot
  -t http/takeovers
  -t http/vulnerabilities
  -t network/default-login
  -t network/enumeration
  -t network/enumeration/smtp
  -t network/exposures
  -t network/honeypot
  -t network/misconfig
  -t network/vulnerabilities
)

ALL_STAGES="discover bbot dnsx spoonmap gowitness urls httpx nuclei"
ALL_TECHNIQUES="scope rdns tls ike http smtp smb-ldap whois"

ONLY=""
SKIP=""
DISC_ONLY=""
DISC_SKIP=""
FORCE=0
FAIL_FAST=0
DRY_RUN=0
RESUME_DIR=""
REDISCOVER=0
BODY_SCRAPE=1
HALT_ON_REVIEW=0
AWAITING_REVIEW=0
NO_DOMAINS=0
NO_URLS=0
PROVIDER_FILTER=1
GW_TRUST=0             # 1 = keep spoonmap results even if outside targets.txt

# ---------------------------------- output ----------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RST=$'\033[0m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'
  C_BLU=$'\033[34m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_RED=$'\033[31m'
else
  C_RST=""; C_DIM=""; C_BLD=""; C_BLU=""; C_GRN=""; C_YEL=""; C_RED=""
fi

RUNLOG=""

_ts() { date '+%H:%M:%S'; }

_emit() {
  local color="$1" plain="$2"; shift 2
  printf '%s[%s]%s %s%s%s %s\n' "$C_DIM" "$(_ts)" "$C_RST" "$color" "$plain" "$C_RST" "$*" >&2
  if [ -n "$RUNLOG" ]; then
    printf '[%s] %s %s\n' "$(date '+%F %T')" "$plain" "$*" >>"$RUNLOG"
  fi
}

info()  { _emit "$C_BLU" "[*]" "$@"; }
good()  { _emit "$C_GRN" "[+]" "$@"; }
warn()  { _emit "$C_YEL" "[!]" "$@"; }
err()   { _emit "$C_RED" "[-]" "$@"; }
die()   { err "$@"; exit 1; }

banner() {
  printf '\n%s%s== %s ==%s\n' "$C_BLD" "$C_BLU" "$*" "$C_RST" >&2
  [ -n "$RUNLOG" ] && printf '\n=== %s === (%s)\n' "$*" "$(date '+%F %T')" >>"$RUNLOG"
  return 0
}

usage() { sed -n '2,/^set -euo/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -euo/d'; }

# --------------------------------- helpers ----------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# GNU coreutils timeout, or gtimeout from homebrew coreutils on macOS.
TIMEOUT_CMD=""
if have timeout; then TIMEOUT_CMD="timeout"
elif have gtimeout; then TIMEOUT_CMD="gtimeout"
fi

in_list() {
  local needle="$1" hay="$2" item
  hay="$(printf '%s' "$hay" | tr ',' ' ')"
  for item in $hay; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

abspath() {
  local p="$1"
  case "$p" in
    /*) : ;;
    *)  p="$(pwd -P)/$p" ;;
  esac
  printf '%s\n' "$p" | sed -e 's#/\./#/#g' -e 's#/\.$##'
}

count_lines() {
  local n
  if [ -f "$1" ]; then
    # grep -c always prints a count; it just exits 1 when that count is zero
    n="$(grep -cve '^[[:space:]]*$' "$1" 2>/dev/null || true)"
    [ -n "$n" ] || n=0
    printf '%s\n' "$n"
  else
    printf '0\n'
  fi
}

# Merge several comma lists into one sorted, deduplicated comma list.
merge_ports() {
  printf '%s\n' "$@" | tr ',' '\n' | sed -e 's/[[:space:]]//g' -e '/^$/d' \
    | sort -un | paste -sd, - 2>/dev/null || printf '%s\n' "$1"
}

# Log a command line, then run it (or not, under --dry-run).
run() {
  local pretty="" a
  for a in "$@"; do
    case "$a" in
      *[![:alnum:]/._=:@,-]*) pretty="$pretty '$a'" ;;
      *) pretty="$pretty $a" ;;
    esac
  done
  printf '%s    $%s%s\n' "$C_DIM" "$pretty" "$C_RST" >&2
  [ -n "$RUNLOG" ] && printf '    $%s\n' "$pretty" >>"$RUNLOG"
  [ "$DRY_RUN" -eq 1 ] && return 0
  "$@"
}

# Log a shell pipeline (string form) and eval it, honoring --dry-run.
run_pipe() {
  printf '%s    $ %s%s\n' "$C_DIM" "$1" "$C_RST" >&2
  [ -n "$RUNLOG" ] && printf '    $ %s\n' "$1" >>"$RUNLOG"
  [ "$DRY_RUN" -eq 1 ] && return 0
  eval "$1"
}

need_file() {
  [ -f "$1" ] || die "required input not found: $1"
  [ -s "$1" ] || die "required input is empty: $1"
}

# --------------------------------- elevation --------------------------------
# spoonmap (masscan) and ike-scan (UDP source port 500) both need raw sockets.
# Sets ELEV_STATUS to root, sudo, or unprivileged; each caller decides what to
# do about it, since spoonmap treats missing elevation as fatal and ike-scan
# only degrades.
ELEV_STATUS=""

set_elevation() {
  if [ "$(id -u)" -eq 0 ]; then
    ELEV_STATUS="root"
  elif [ "$SUDO" -eq 1 ] && have sudo; then
    ELEV_STATUS="sudo"
  else
    ELEV_STATUS="unprivileged"
  fi
}

# ------------------------------- spoonmap paths -----------------------------
# Both the spoonmap stage and the gowitness stage need the repo: one to run in
# it, the other to read the open ports it recorded there.
SPOONMAP_SCRIPT=""
SPOONMAP_REPO=""
SPOONMAP_TRIED=""

resolve_spoonmap() {
  SPOONMAP_SCRIPT=""; SPOONMAP_REPO=""; SPOONMAP_TRIED=""
  local cand candidates=()
  if [ -n "$SPOONMAP_PATH" ]; then
    local base="${SPOONMAP_PATH%/}"
    candidates+=("$base" "$base/spoonmap.py")
  fi
  candidates+=("./spoonmap.py" "./spoonmap/spoonmap.py")
  cand="$(command -v spoonmap.py 2>/dev/null || true)"
  [ -n "$cand" ] && candidates+=("$cand")

  for cand in ${candidates[@]+"${candidates[@]}"}; do
    SPOONMAP_TRIED="${SPOONMAP_TRIED}      ${cand}"$'\n'
    [ -f "$cand" ] || continue
    SPOONMAP_SCRIPT="$(abspath "$cand")"
    SPOONMAP_REPO="$(dirname "$SPOONMAP_SCRIPT")"
    return 0
  done
  return 1
}

# The repo path is remembered so a later --resume can find spoonmap's results
# without --spoonmap being passed again.
spoonmap_repo_hint() {
  if [ -s "$STATE_DIR/spoonmap-repo" ]; then
    local r
    r="$(cat "$STATE_DIR/spoonmap-repo" 2>/dev/null || true)"
    if [ -n "$r" ] && [ -d "$r" ]; then printf '%s\n' "$r"; return 0; fi
  fi
  if resolve_spoonmap; then printf '%s\n' "$SPOONMAP_REPO"; return 0; fi
  return 1
}

# Warn once, at the moment of use, if sudo is going to want a password.
warn_if_sudo_prompts() {
  [ "$ELEV_STATUS" = "sudo" ] || return 0
  sudo -n true 2>/dev/null && return 0
  warn "sudo needs a password for $1; stdin is attached so answer the prompt below"
}

# ------------------------------ signal handling -----------------------------

# Walk the descendant tree deepest-first so wrapped tools (gowitness -> chrome,
# spoonmap -> masscan/nmap) do not survive a Ctrl-C.
kill_tree() {
  local sig="$1" pid="$2" child
  if have pgrep; then
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do
      kill_tree "$sig" "$child"
    done
  fi
  if [ "$pid" != "$$" ]; then
    kill "-$sig" "$pid" 2>/dev/null || true
  fi
}

kill_children() {
  local sig="${1:-TERM}"
  if have pgrep; then
    kill_tree "$sig" $$
  elif have pkill; then
    pkill "-$sig" -P $$ >/dev/null 2>&1 || true
  else
    local kid
    for kid in $(jobs -p 2>/dev/null); do kill "-$sig" "$kid" 2>/dev/null || true; done
  fi
}

on_interrupt() {
  printf '\n' >&2
  warn "interrupted — terminating child processes"
  trap - INT TERM
  kill_children TERM
  sleep 2
  kill_children KILL
  print_summary
  err "run aborted by user"
  exit 130
}

trap on_interrupt INT TERM

# --------------------------- stage bookkeeping ------------------------------

STATE_DIR=""
SUMMARY=""          # newline-separated "stage|status|duration"
FAILED_STAGES=""
STAGE_NOTE=""       # a stage sets this to report "did not run, and why"

stage_deps() {
  case "$1" in
    discover)  echo "python3" ;;
    bbot)      echo "bbot" ;;
    dnsx)      echo "dnsx" ;;
    spoonmap)
      if [ "$(id -u)" -ne 0 ] && [ "$SUDO" -eq 1 ]; then
        echo "python3 sudo"
      else
        echo "python3"
      fi ;;
    gowitness) echo "gowitness" ;;
    urls)      echo "python3" ;;
    httpx)     echo "httpx" ;;
    nuclei)    echo "nuclei httpx" ;;
    *)         echo "" ;;
  esac
}

stage_selected() {
  local s="$1"
  if [ -n "$ONLY" ]; then in_list "$s" "$ONLY" || return 1; fi
  if [ -n "$SKIP" ]; then in_list "$s" "$SKIP" && return 1; fi
  return 0
}

tech_selected() {
  local t="$1"
  if [ -n "$DISC_ONLY" ]; then in_list "$t" "$DISC_ONLY" || return 1; fi
  if [ -n "$DISC_SKIP" ]; then in_list "$t" "$DISC_SKIP" && return 1; fi
  return 0
}

record() { SUMMARY="${SUMMARY}${1}|${2}|${3}"$'\n'; }

fmt_dur() {
  local t="$1"
  if [ "$t" -lt 60 ]; then printf '%ds\n' "$t"
  elif [ "$t" -lt 3600 ]; then printf '%dm%02ds\n' "$((t/60))" "$((t%60))"
  else printf '%dh%02dm\n' "$((t/3600))" "$(((t%3600)/60))"
  fi
}

run_stage() {
  local name="$1" fn="stage_$1" start elapsed rc

  if ! stage_selected "$name"; then
    record "$name" "skipped (filter)" "-"
    return 0
  fi
  # bbot and dnsx are the only stages that need domains.txt; they stand down
  # when candidates are awaiting review, and are skipped outright when no
  # domain could be established at all.
  case "$name" in
    bbot|dnsx)
      if [ "$AWAITING_REVIEW" -eq 1 ]; then
        info "stage '$name' blocked — domains awaiting review"
        record "$name" "blocked (review)" "-"
        return 0
      fi
      if [ "$NO_DOMAINS" -eq 1 ]; then
        info "stage '$name' skipped — no domains to enumerate"
        record "$name" "skipped (no domains)" "-"
        return 0
      fi ;;
    httpx|nuclei)
      # these consume urls.txt; without it there is nothing to do
      if [ "$NO_URLS" -eq 1 ]; then
        info "stage '$name' skipped — no live URLs were found"
        record "$name" "skipped (no URLs)" "-"
        return 0
      fi ;;
  esac
  if [ "$FORCE" -eq 0 ] && [ -f "$STATE_DIR/$name.done" ]; then
    info "stage '$name' already complete (use --force to re-run)"
    record "$name" "cached" "-"
    return 0
  fi

  banner "stage: $name"
  start=$SECONDS
  rc=0
  STAGE_NOTE=""
  set +e
  "$fn"
  rc=$?
  set -e
  elapsed=$((SECONDS - start))

  # A stage that declined to run reports why and leaves no completion marker,
  # so a later --resume will try it again.
  if [ "$rc" -eq 0 ] && [ -n "$STAGE_NOTE" ]; then
    record "$name" "$STAGE_NOTE" "-"
    return 0
  fi

  if [ "$rc" -eq 0 ]; then
    [ "$DRY_RUN" -eq 0 ] && : >"$STATE_DIR/$name.done"
    good "stage '$name' finished in $(fmt_dur "$elapsed")"
    record "$name" "ok" "$(fmt_dur "$elapsed")"
  else
    err "stage '$name' failed (exit $rc) after $(fmt_dur "$elapsed")"
    record "$name" "FAILED (rc=$rc)" "$(fmt_dur "$elapsed")"
    FAILED_STAGES="$FAILED_STAGES $name"
    if [ "$FAIL_FAST" -eq 1 ]; then
      print_summary
      die "--fail-fast: aborting after '$name'"
    fi
  fi
  return 0
}

print_review_gate() {
  local cand="$OUTDIR/domains-candidates.txt"
  printf '\n%s%s' "$C_BLD" "$C_YEL" >&2
  printf '+--------------------------------------------------------------+\n' >&2
  printf '|  REVIEW REQUIRED — candidate domains are NOT yet in scope    |\n' >&2
  printf '+--------------------------------------------------------------+%s\n' "$C_RST" >&2
  printf '\n  %s candidate apex domain(s) discovered from the IP scope.\n\n' \
    "$(count_lines "$cand")" >&2
  printf '    candidates : %s\n' "$cand" >&2
  printf '    report     : %s\n' "$OUTDIR/discovery-report.txt" >&2
  printf '    provenance : %s\n' "$OUTDIR/00-discover/provenance.tsv" >&2
  printf '    observed   : %s\n' "$OUTDIR/observed-fqdns.txt" >&2
  printf '    filtered   : %s\n' "$OUTDIR/filtered-out.txt" >&2
  printf '    internal   : %s\n' "$OUTDIR/internal-domains.txt" >&2
  printf '    odd TLDs   : %s\n' "$OUTDIR/unknown-tld.txt" >&2
  printf '\n  Review, keep only what you are authorized to enumerate, then:\n\n' >&2
  printf '    %s$ cp %s %s%s\n' "$C_DIM" "$cand" "$DOMAINS" "$C_RST" >&2
  printf '    %s$ %s --resume %s%s\n\n' "$C_DIM" "$0" "$OUTDIR" "$C_RST" >&2
  return 0
}

print_summary() {
  [ -z "$SUMMARY" ] && return 0
  banner "summary"
  printf '  %-12s %-22s %s\n' "STAGE" "STATUS" "TIME" >&2
  printf '  %-12s %-22s %s\n' "-----" "------" "----" >&2
  printf '%s' "$SUMMARY" | while IFS='|' read -r s st d; do
    [ -z "$s" ] && continue
    printf '  %-12s %-22s %s\n' "$s" "$st" "$d" >&2
  done

  if [ "$DRY_RUN" -eq 0 ] && [ -d "$OUTDIR" ]; then
    printf '\n  artifacts in %s%s%s\n' "$C_BLD" "$OUTDIR" "$C_RST" >&2
    if [ -f "$OUTDIR/domains-candidates.txt" ]; then
      printf '    domains-candidates  %s\n' \
        "$(count_lines "$OUTDIR/domains-candidates.txt")" >&2
      printf '    observed-fqdns.txt  %s\n' "$(count_lines "$OUTDIR/observed-fqdns.txt")" >&2
    fi
    printf '    subdomains.txt      %s\n' "$(count_lines "$OUTDIR/subdomains.txt")" >&2
    printf '    resolved-ips.txt    %s (recon only, not scanned)\n' \
      "$(count_lines "$OUTDIR/resolved-ips.txt")" >&2
    printf '    urls.txt            %s\n' "$(count_lines "$OUTDIR/urls.txt")" >&2
    printf '    httpx.txt           %s\n' "$(count_lines "$OUTDIR/06-httpx/httpx.txt")" >&2
    printf '    nuclei.out          %s\n' "$(count_lines "$OUTDIR/07-nuclei/nuclei.out")" >&2
    printf '    run.log             %s\n' "$RUNLOG" >&2
  fi
  return 0
}

# ============================ stage 0: discovery ============================

PROV=""       # provenance.tsv for the current discovery run
DISC_DIR=""
IPFILE=""
OPENPORTS=""

# Append "<name>\t<technique>\t<evidence>" rows, cleaning the name column.
emit_findings() {
  local src="$1"
  awk -F'\t' -v src="$src" '
    NF >= 1 {
      name = $1; ev = (NF >= 2 ? $2 : "")
      gsub(/^[ \t"'"'"']+|[ \t"'"'"'.]+$/, "", name)
      name = tolower(name)
      sub(/^\*\./, "", name)
      sub(/\.$/, "", name)
      # NB: no {n,} intervals here — mawk 1.3.4 silently treats {2,} as {2},
      # which would drop every name whose TLD is longer than two characters.
      if (name ~ /^[a-z0-9][a-z0-9._-]*\.[a-z0-9-][a-z0-9-]+$/ && name !~ /\.\./) {
        print name "\t" src "\t" ev
      }
    }' >>"$PROV"
}

# ip:port lines for the given comma-separated port list, preferring the
# results of the fast sweep when one ran.
target_pairs() {
  local ports="$1"
  if [ -s "$OPENPORTS" ]; then
    awk -F: -v pl="$ports" 'BEGIN { n=split(pl, a, ","); for (i=1;i<=n;i++) want[a[i]]=1 }
                            NF==2 && ($2 in want) { print }' "$OPENPORTS"
  else
    awk -v pl="$ports" 'BEGIN { n=split(pl, a, ",") }
                        NF { for (i=1;i<=n;i++) print $0 ":" a[i] }' "$IPFILE"
  fi
}

# --- expand a scope file into an IP list + any hostnames it contains --------
# Shared by the discover stage and the gowitness fallback: gowitness's file
# reader does NOT expand CIDRs (it url-parses each line, so "10.0.0.0/24"
# becomes host 10.0.0.0 with path /24), so anything handed to it must already
# be one address per line.
# usage: expand_ip_scope <scope-file> <max-hosts> <ip-out> <hostname-out>
expand_ip_scope() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import ipaddress, re, sys

src, maxh, ipout, hostout = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
ips, hosts, seen, hseen = [], [], set(), set()
over = unparsed = 0

def add(ip):
    global over
    s = str(ip)
    if s in seen:
        return
    if len(seen) >= maxh:
        over += 1
        return
    seen.add(s)
    ips.append(s)

with open(src, encoding="utf-8", errors="replace") as fh:
    for raw in fh:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "://" in line:
            line = re.sub(r"^[a-z0-9+.-]+://", "", line, flags=re.I)
        line = line.split("/")[0] if ("/" in line and not re.search(r"/\d+$", line)) else line
        if re.match(r"^[^:\[\]]+:\d+$", line):
            line = line.rsplit(":", 1)[0]
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            net = None
        if net is not None:
            it = net.hosts() if net.num_addresses > 2 else iter(net)
            for ip in it:
                add(ip)
            continue
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+(?:\.\d+\.\d+\.\d+)?)$", line)
        if m:
            start = ipaddress.ip_address(m.group(1))
            tail = m.group(2)
            end = ipaddress.ip_address(
                tail if "." in tail else ".".join(m.group(1).split(".")[:3] + [tail]))
            cur = int(start)
            while cur <= int(end):
                add(ipaddress.ip_address(cur))
                cur += 1
            continue
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9-]{2,}$", line):
            h = line.lower().rstrip(".")
            if h not in hseen:
                hseen.add(h)
                hosts.append(h)
            continue
        unparsed += 1
        print("unparsed scope entry: %s" % line, file=sys.stderr)

with open(ipout, "w") as fh:
    fh.write("".join(i + "\n" for i in ips))
with open(hostout, "w") as fh:
    fh.write("".join(h + "\n" for h in sorted(hosts)))

print("%d %d %d %d" % (len(ips), len(hosts), over, unparsed))
PY
}

# --- optional fast sweep so the active techniques only touch live services --
probe_ports() {
  local ports
  ports="$(merge_ports "$TLS_PORTS" "$WEB_PORTS" "$SMTP_PORTS" "$SMB_LDAP_PORTS")"
  : >"$OPENPORTS"

  if have naabu; then
    info "sweeping $(count_lines "$IPFILE") host(s) with naabu to focus the active techniques"
    naabu -list "$IPFILE" -p "$ports" -silent -o "$OPENPORTS" >/dev/null 2>&1 || true
  elif have nmap; then
    info "sweeping $(count_lines "$IPFILE") host(s) with nmap to focus the active techniques"
    nmap -Pn -n -sT --open -p "$ports" -iL "$IPFILE" -oG - 2>/dev/null \
      | awk '/^Host:/ && /Ports:/ {
              ip = $2
              split($0, a, "Ports: ")
              n = split(a[2], p, ", ")
              for (i = 1; i <= n; i++) {
                split(p[i], f, "/")
                if (f[2] == "open") print ip ":" f[1]
              }
            }' | sort -u >"$OPENPORTS" || true
  else
    warn "neither naabu nor nmap found — active techniques will probe every scope IP"
    return 0
  fi

  if [ -s "$OPENPORTS" ]; then
    good "$(count_lines "$OPENPORTS") open service(s) found; techniques will target those"
  else
    warn "sweep returned nothing — falling back to probing every scope IP"
    : >"$OPENPORTS"
  fi
  return 0
}

# --- technique: hostnames already sitting in targets.txt --------------------
disc_scope() {
  [ -s "$DISC_DIR/scope-hostnames.txt" ] || return 0
  awk 'NF { print $0 "\ttargets.txt entry" }' "$DISC_DIR/scope-hostnames.txt" \
    | emit_findings scope
}

# --- technique: reverse DNS -------------------------------------------------
disc_rdns() {
  local out="$DISC_DIR/rdns.txt"
  if have dnsx; then
    if have jq; then
      dnsx -l "$IPFILE" -ptr -json -silent -t "$THREADS" 2>/dev/null \
        | jq -r 'select(.ptr) | .host as $h | .ptr[] | "\(.)\tPTR of \($h)"' \
        >"$out" 2>/dev/null || true
    else
      dnsx -l "$IPFILE" -ptr -resp-only -silent -t "$THREADS" 2>/dev/null \
        | awk 'NF { print $0 "\tPTR record" }' >"$out" || true
    fi
  elif have dig; then
    warn "dnsx not found — using a serial dig fallback (slow)"
    head -n 4096 "$IPFILE" | while IFS= read -r ip; do
      [ -z "$ip" ] && continue
      dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null \
        | awk -v ip="$ip" 'NF { print $0 "\tPTR of " ip }'
    done >"$out" || true
  else
    warn "no dnsx or dig — skipping rdns"
    return 0
  fi
  emit_findings rdns <"$out"
}

# --- technique: TLS certificate CN / SAN ------------------------------------
disc_tls() {
  local out="$DISC_DIR/tls.txt" pairs="$DISC_DIR/tls-pairs.txt"
  target_pairs "$TLS_PORTS" >"$pairs"
  [ -s "$pairs" ] || return 0
  : >"$out"

  if have tlsx; then
    if have jq; then
      tlsx -l "$pairs" -cn -san -silent -json -c "$THREADS" 2>/dev/null \
        | jq -r '. as $r | ([$r.subject_cn] + ($r.subject_an // []))[]?
                 | select(. != null and . != "")
                 | "\(.)\tcert on \($r.host):\($r.port)"' >>"$out" 2>/dev/null || true
    else
      tlsx -l "$pairs" -cn -san -silent -resp-only -c "$THREADS" 2>/dev/null \
        | awk 'NF { print $0 "\tcertificate CN/SAN" }' >>"$out" || true
    fi
  elif have httpx; then
    info "tlsx not found — grabbing certificates with httpx -tls-grab"
    if have jq; then
      httpx -l "$pairs" -tls-grab -silent -json -no-color -threads "$THREADS" 2>/dev/null \
        | jq -r 'select(.tls) | .input as $i | .tls as $t
                 | ([$t.subject_cn] + ($t.subject_an // []))[]?
                 | select(. != null and . != "") | "\(.)\tcert on \($i)"' \
        >>"$out" 2>/dev/null || true
    else
      httpx -l "$pairs" -tls-grab -silent -json -no-color -threads "$THREADS" 2>/dev/null \
        | grep -ohE '"(subject_cn|subject_an)":[^]}]*' \
        | grep -ohE '[a-z0-9*][a-z0-9.*_-]+\.[a-z]{2,}' \
        | awk 'NF { print $0 "\tcertificate CN/SAN" }' >>"$out" || true
    fi
  else
    # Last resort: grab the peer certificate ourselves. Concurrent, with hard
    # socket timeouts — a serial `openssl s_client` loop stalls for hours on an
    # unroutable range because s_client has no connect timeout of its own.
    warn "no tlsx or httpx — grabbing certificates directly (last resort)"
    python3 - "$pairs" "$THREADS" >>"$out" <<'PY' || true
import re, socket, ssl, sys
from concurrent.futures import ThreadPoolExecutor

pairs = [l.strip() for l in open(sys.argv[1]) if l.strip()][:4096]
workers = max(8, min(256, int(sys.argv[2]) * 2))
IP = re.compile(r"^[0-9.]+$|^[0-9a-fA-F:]+$")
# SANs and the CN sit in the DER as plain IA5/UTF8 strings; pulling
# hostname-shaped ASCII out of the blob avoids shipping an ASN.1 parser, and
# the TLD allowlist downstream discards whatever noise slips through.
NAME = re.compile(rb"[a-z0-9*](?:[a-z0-9.*_-]{1,61}[a-z0-9])\.[a-z]{2,24}")

def grab(hp):
    host, _, port = hp.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sni = None if IP.match(host) else host
    der = None
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            sock.settimeout(4)
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(True)
    except Exception:
        return []
    if not der:
        return []
    return [(m.group(0).decode("ascii", "ignore"), "cert on %s" % hp)
            for m in {m for m in NAME.finditer(der.lower())}]

with ThreadPoolExecutor(max_workers=workers) as pool:
    for res in pool.map(grab, pairs):
        for name, ev in res:
            print("%s\t%s" % (name, ev))
PY
  fi
  emit_findings tls <"$out"
}

# --- technique: IKE aggressive mode ID payloads -----------------------------
disc_ike() {
  local out="$DISC_DIR/ike.txt" raw="$DISC_DIR/ike-raw.txt"
  if ! have ike-scan; then
    warn "ike-scan not found — skipping ike (UDP/500 ID payloads)"
    return 0
  fi
  : >"$raw"

  # Elevated, ike-scan keeps the default source port 500, which is the only
  # port some concentrators will answer. Unprivileged it must use a random
  # high port instead, and those devices go undetected.
  set_elevation
  local runner=() sport=()
  case "$ELEV_STATUS" in
    root)
      info "running ike-scan as root (source port 500)" ;;
    sudo)
      runner=(sudo)
      warn_if_sudo_prompts ike-scan ;;
    unprivileged)
      warn "cannot elevate ike-scan — falling back to --sport=0; concentrators"
      warn "that only answer source port 500 will be missed"
      sport=(--sport=0) ;;
  esac

  # Resolve the binary before elevating: sudo replaces PATH with its own
  # secure_path, so an ike-scan built into /usr/local/bin (the usual case,
  # since it is not always packaged) is invisible to a bare `sudo ike-scan`.
  local ike_bin
  ike_bin="$(command -v ike-scan)"

  # aggressive mode first (it is what leaks the ID payload), then IKEv2
  local rc1=0 rc2=0
  ${runner[@]+"${runner[@]}"} "$ike_bin" -A -M --retry=1 --timeout=1000 \
    ${sport[@]+"${sport[@]}"} --file="$IPFILE" >>"$raw" 2>&1 || rc1=$?
  ${runner[@]+"${runner[@]}"} "$ike_bin" -2 -M --retry=1 --timeout=1000 \
    ${sport[@]+"${sport[@]}"} --file="$IPFILE" >>"$raw" 2>&1 || rc2=$?

  # Never let a broken invocation masquerade as "no VPN endpoints found".
  if [ "$rc1" -ne 0 ] && [ "$rc2" -ne 0 ] \
     && ! grep -qE 'Handshake|Notify|returned' "$raw" 2>/dev/null; then
    warn "ike-scan produced nothing and exited $rc1/$rc2 — this is a tool"
    warn "problem, not evidence that nothing is listening. See $raw"
  fi

  awk '{
        ip = $1
        s = $0
        while (match(s, /ID\(Type=ID_(USER_)?FQDN,[ \t]*Value=[^)]*\)/)) {
          tok = substr(s, RSTART, RLENGTH)
          sub(/.*Value=/, "", tok)
          sub(/\)$/, "", tok)
          if (tok ~ /@/) sub(/^[^@]*@/, "", tok)
          if (tok != "") print tok "\tIKE ID payload from " ip
          s = substr(s, RSTART + RLENGTH)
        }
      }' "$raw" >"$out" || true

  if [ -s "$out" ]; then
    good "IKE ID payloads leaked $(count_lines "$out") name(s)"
  fi
  emit_findings ike <"$out"
}

# --- technique: HTTP redirects, CSP, response bodies ------------------------
disc_http() {
  local out="$DISC_DIR/http.txt" pairs="$DISC_DIR/http-pairs.txt"
  local json="$DISC_DIR/http.json"
  if ! have httpx; then
    warn "httpx not found — skipping http"
    return 0
  fi
  target_pairs "$WEB_PORTS" >"$pairs"
  [ -s "$pairs" ] || return 0
  : >"$out"

  local extra=()
  [ "$BODY_SCRAPE" -eq 1 ] && extra=(-irr)
  httpx -l "$pairs" -silent -json -no-color -tls-grab -csp-probe \
    -threads "$THREADS" ${extra[@]+"${extra[@]}"} >"$json" 2>/dev/null || true
  [ -s "$json" ] || return 0

  if have jq; then
    # Location redirects
    jq -r 'select(.location != null and .location != "") | "\(.location)\t\(.input)"' "$json" \
      2>/dev/null | sed -E 's#^[a-z0-9+.-]+://##I; s#/.*\t#\t#; s#:[0-9]+\t#\t#' \
      | awk -F'\t' 'NF==2 { print $1 "\tLocation redirect from " $2 }' >>"$out" || true
    # CSP directives
    jq -r 'select(.csp != null) | .input as $i | (.csp.domains // [])[]
           | "\(.)\tCSP directive on \($i)"' "$json" >>"$out" 2>/dev/null || true
    # certificate names seen on the web ports
    jq -r 'select(.tls != null) | .input as $i | .tls as $t
           | ([$t.subject_cn] + ($t.subject_an // []))[]?
           | select(. != null and . != "") | "\(.)\tcert on \($i)"' "$json" \
      >>"$out" 2>/dev/null || true
    # response bodies
    if [ "$BODY_SCRAPE" -eq 1 ]; then
      jq -r 'select(.raw_response != null or .response != null)
             | (.raw_response // .response)' "$json" 2>/dev/null \
        | grep -ohE '[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?\.[a-z]{2,24}' \
        | awk 'NF { print $0 "\tHTTP response body" }' >>"$out" || true
    fi
  else
    grep -ohE '[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?\.[a-z]{2,24}' "$json" \
      | awk 'NF { print $0 "\thttpx output (unparsed)" }' >>"$out" || true
  fi
  emit_findings http <"$out"
}

# --- technique: SMTP greeting / EHLO hostnames ------------------------------
disc_smtp() {
  local out="$DISC_DIR/smtp.txt" pairs="$DISC_DIR/smtp-pairs.txt"
  target_pairs "$SMTP_PORTS" >"$pairs"
  [ -s "$pairs" ] || return 0

  python3 - "$pairs" "$THREADS" >"$out" <<'PY' || true
import re, socket, sys
from concurrent.futures import ThreadPoolExecutor

pairs = [l.strip() for l in open(sys.argv[1]) if l.strip()]
workers = max(8, min(400, int(sys.argv[2]) * 4))
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,24}$")

def grab(hp):
    host, _, port = hp.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return []
    found = []
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            s.settimeout(4)
            greet = s.recv(2048).decode("utf-8", "replace")
            s.sendall(b"EHLO recon.invalid\r\n")
            ehlo = s.recv(4096).decode("utf-8", "replace")
    except Exception:
        return []
    for line, what in ((greet, "220 greeting"), (ehlo, "EHLO response")):
        for row in line.splitlines():
            m = re.match(r"^(?:220|250)[- ]([^\s;,]+)", row.strip())
            if m and HOST.match(m.group(1)):
                found.append((m.group(1), "SMTP %s on %s" % (what, hp)))
                break
    return found

with ThreadPoolExecutor(max_workers=workers) as pool:
    for res in pool.map(grab, pairs):
        for name, ev in res:
            print("%s\t%s" % (name, ev))
PY
  emit_findings smtp <"$out"
}

# --- technique: SMB OS discovery + LDAP RootDSE -----------------------------
disc_smb_ldap() {
  local out="$DISC_DIR/smb-ldap.txt" raw="$DISC_DIR/smb-ldap.nmap"
  if ! have nmap; then
    warn "nmap not found — skipping smb-ldap (AD domain discovery)"
    return 0
  fi

  local hosts="$DISC_DIR/smb-ldap-hosts.txt"
  if [ -s "$OPENPORTS" ]; then
    awk -F: -v pl="$SMB_LDAP_PORTS" \
      'BEGIN { n=split(pl,a,","); for (i=1;i<=n;i++) want[a[i]]=1 }
       NF==2 && ($2 in want) { print $1 }' "$OPENPORTS" | sort -u >"$hosts"
  else
    cp "$IPFILE" "$hosts"
  fi
  [ -s "$hosts" ] || return 0

  nmap -Pn -n -sT --open -p "$SMB_LDAP_PORTS" \
    --script "smb-os-discovery,ldap-rootdse" \
    -iL "$hosts" -oN "$raw" >/dev/null 2>&1 || true
  [ -s "$raw" ] || return 0

  python3 - "$raw" >"$out" <<'PY' || true
import re, sys

host = "?"
KEYS = ("fqdn", "dns_domain_name", "dns_computer_name", "dns_tree_name",
        "domain name", "domain", "dnshostname", "ldapservicename",
        "defaultnamingcontext", "rootdomainnamingcontext", "configurationnamingcontext",
        "namingcontexts", "dnsdomainname", "forest_name")
HOSTRE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?\.[A-Za-z]{2,24}$")

def dc_to_domain(val):
    parts = [p.split("=", 1)[1] for p in re.split(r"\s*,\s*", val)
             if p.lower().startswith("dc=") and "=" in p]
    return ".".join(parts) if len(parts) >= 2 else None

for raw in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = raw.rstrip("\n")
    m = re.match(r"^Nmap scan report for (?:\S+ \()?([0-9a-fA-F:.]+)\)?", line)
    if m:
        host = m.group(1)
        continue
    body = line.lstrip("|_| ").strip()
    if ":" not in body:
        continue
    key, _, val = body.partition(":")
    key = key.strip().lower()
    val = val.strip().strip("<>").strip()
    if key not in KEYS or not val:
        continue
    cands = []
    if "dc=" in val.lower():
        for chunk in val.split(";"):
            d = dc_to_domain(chunk.strip())
            if d:
                cands.append(d)
    elif key == "ldapservicename":
        # corp.example.com:dc01$@CORP.EXAMPLE.COM
        cands.append(val.split(":", 1)[0])
        if "@" in val:
            cands.append(val.rsplit("@", 1)[1])
    else:
        cands.append(val)
    for c in cands:
        c = c.strip().strip(".").lower()
        if HOSTRE.match(c):
            print("%s\t%s on %s" % (c, key, host))
PY
  if [ -s "$out" ]; then
    good "SMB/LDAP disclosed $(count_lines "$out") name(s) — check for AD domains"
  fi
  emit_findings smb-ldap <"$out"
}

# --- technique: registry data for the netblocks -----------------------------
disc_whois() {
  local out="$DISC_DIR/whois.txt" nets="$DISC_DIR/whois-nets.txt"
  local wdir="$DISC_DIR/whois"
  if ! have whois && ! have curl; then
    warn "neither whois nor curl found — skipping whois"
    return 0
  fi
  mkdir -p "$wdir"
  : >"$out"

  # one representative address per /24, capped and rate limited
  awk -F. 'NF==4 { print $1"."$2"."$3".1" }' "$IPFILE" | sort -u \
    | head -n "$WHOIS_MAX" >"$nets"
  [ -s "$nets" ] || return 0
  info "querying the registries for $(count_lines "$nets") netblock(s)"

  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    local f="$wdir/${ip}.txt"
    if have whois; then
      if [ -n "$TIMEOUT_CMD" ]; then
        "$TIMEOUT_CMD" 20 whois "$ip" >"$f" 2>/dev/null || true
      else
        whois "$ip" >"$f" 2>/dev/null || true
      fi
    else
      curl -sS --max-time 15 -H 'Accept: application/rdap+json' \
        "https://rdap.arin.net/registry/ip/$ip" >"$f" 2>/dev/null || true
    fi
    # contact email domains, plus FQDNs in org/netname/descr style fields
    grep -ohiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}' "$f" 2>/dev/null \
      | sed -e 's/.*@//' | awk -v ip="$ip" 'NF { print $0 "\tregistry contact for " ip }' >>"$out" || true
    grep -ohiE '(orgname|org-name|organization|netname|descr|owner|responsible)[^a-z0-9]*[^\r\n]*' "$f" 2>/dev/null \
      | grep -ohE '[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?\.[a-z]{2,24}' \
      | awk -v ip="$ip" 'NF { print $0 "\tregistry record for " ip }' >>"$out" || true
    sleep 1
  done <"$nets"
  emit_findings whois <"$out"
}

# --- reduce to registrable apexes, filter, and write the review artifacts ---
normalize_candidates() {
  python3 - "$PROV" "$OUTDIR" "$PROVIDER_FILTER" <<'PY'
import os, re, sys
from collections import defaultdict

prov, outdir = sys.argv[1], sys.argv[2]
PROVIDER_FILTER = (len(sys.argv) < 4 or sys.argv[3] != "0")

# Public suffixes with two or more labels. tldextract is used instead when it
# is importable (it carries the real Public Suffix List); this table is the
# offline fallback and covers the suffixes that actually turn up in scoping.
MULTI = set("""
co.uk org.uk ac.uk gov.uk me.uk net.uk sch.uk nhs.uk police.uk ltd.uk plc.uk service.gov.uk
com.au net.au org.au edu.au gov.au asn.au id.au act.gov.au nsw.gov.au qld.gov.au vic.gov.au
wa.gov.au sa.gov.au tas.gov.au nt.gov.au
co.nz net.nz org.nz govt.nz ac.nz school.nz geek.nz
co.za org.za net.za web.za gov.za ac.za
co.jp ne.jp or.jp ac.jp go.jp ad.jp ed.jp gr.jp lg.jp
com.br net.br org.br gov.br edu.br
com.mx org.mx net.mx gob.mx edu.mx
com.ar net.ar org.ar gob.ar edu.ar
com.cn net.cn org.cn gov.cn edu.cn ac.cn
com.hk net.hk org.hk edu.hk gov.hk idv.hk
com.sg net.sg org.sg edu.sg gov.sg
com.tw net.tw org.tw edu.tw gov.tw idv.tw
com.tr net.tr org.tr gov.tr edu.tr bel.tr k12.tr
co.in net.in org.in gen.in firm.in ind.in gov.in nic.in ac.in edu.in res.in
co.kr or.kr ne.kr re.kr pe.kr go.kr ac.kr hs.kr ms.kr es.kr
com.pl net.pl org.pl gov.pl edu.pl waw.pl
com.ua net.ua org.ua gov.ua edu.ua kiev.ua
co.il org.il net.il ac.il gov.il muni.il k12.il
com.my net.my org.my gov.my edu.my
com.ph net.ph org.ph gov.ph edu.ph
com.vn net.vn org.vn gov.vn edu.vn
com.co net.co org.co gov.co edu.co
co.th in.th ac.th go.th or.th net.th
com.pk net.pk org.pk gov.pk edu.pk
co.ae net.ae org.ae ac.ae gov.ae
co.id or.id ac.id go.id web.id my.id
co.ir ac.ir gov.ir org.ir net.ir
com.ru net.ru org.ru edu.ru gov.ru spb.ru msk.ru
com.es org.es nom.es gob.es edu.es
com.pt org.pt edu.pt gov.pt
com.gr net.gr org.gr edu.gr gov.gr
com.cy net.cy org.cy ac.cy gov.cy
com.mt org.mt net.mt edu.mt gov.mt
co.ma com.ma net.ma gov.ma com.tn com.dz com.eg com.ly
com.sa com.qa com.om com.bh com.kw com.jo com.lb
com.ng com.gh com.ke co.ke or.ke ac.ke go.ke com.et
co.tz co.ug co.zm co.zw co.bw co.mz
com.pe com.ve com.ec com.uy com.py com.bo com.do com.gt com.sv com.hn com.ni
com.pa com.cr co.cr com.bz com.jm com.tt com.bs com.bb
com.bd com.np com.lk
co.at or.at ac.at gv.at priv.at co.hu com.hr from.hr iz.hr com.ee pri.ee fie.ee
on.ca qc.ca bc.ca ab.ca mb.ca sk.ca ns.ca nb.ca nl.ca pe.ca yk.ca nt.ca nu.ca
eu.com us.com uk.com cn.com de.com jpn.com gb.net eu.org us.org
""".split())

# Apexes that belong to hosting, CDN, SaaS, analytics, mail security, or
# transit providers. Finding one tells you nothing about the client's estate.
HOSTING = set("""
amazonaws.com awsglobalaccelerator.com cloudfront.net elasticbeanstalk.com amazonses.com
awsapps.com awsdns-01.org awsdns-02.co.uk awsdns-03.net awsdns-04.com
azurewebsites.net azure.com cloudapp.net cloudapp.azure.com azureedge.net trafficmanager.net
windows.net azurefd.net azure-api.net microsoftonline.com office.com office365.com outlook.com
sharepoint.com onmicrosoft.com msappproxy.net azure-devices.net microsoft.com msecnd.net
akamai.net akamaiedge.net akamaitechnologies.com akamaized.net edgekey.net edgesuite.net akadns.net
cloudflare.com cloudflare.net cloudflaressl.com cloudflare-dns.com pages.dev workers.dev
trycloudflare.com
googleusercontent.com googlehosted.com appspot.com googleapis.com gstatic.com google.com
googlevideo.com 1e100.net gvt1.com gvt2.com withgoogle.com doubleclick.net google-analytics.com
googletagmanager.com googlesyndication.com googleadservices.com recaptcha.net firebaseapp.com web.app
fastly.net fastlylb.net fastly-edge.com herokuapp.com herokussl.com herokudns.com
digitalocean.com digitaloceanspaces.com linode.com linodeusercontent.com vultr.com
vultrusercontent.com ovh.net ovh.ca ovh.com hetzner.de hetzner.com your-server.de contabo.net
scaleway.com online.net leaseweb.com hostwinds.com ionos.com secureserver.net godaddy.com
hostgator.com bluehost.com dreamhost.com siteground.com wpengine.com kinsta.cloud namecheap.com
registrar-servers.com
incapdns.net imperva.com impervadns.net sucuri.net stackpathdns.com stackpathcdn.com bunnycdn.com
b-cdn.net keycdn.com cdn77.org cachefly.net llnwd.net edgecastcdn.net azioncdn.net
netlify.app netlify.com vercel.app vercel.com now.sh render.com onrender.com fly.dev railway.app
surge.sh github.io githubusercontent.com github.com gitlab.io bitbucket.io readthedocs.io
glitch.me repl.co replit.dev ngrok.io ngrok-free.app ngrok.app localtunnel.me
wordpress.com wp.com wixsite.com wix.com squarespace.com sqspcdn.com shopify.com myshopify.com
shopifycdn.com bigcommerce.com weebly.com webflow.io webflow.com hubspot.com hs-sites.com
hsforms.com marketo.com mktoresp.com pardot.com salesforce.com force.com zendesk.com zdassets.com
freshdesk.com intercom.io intercomcdn.com atlassian.net statuspage.io pingdom.net newrelic.com
nr-data.net sentry.io segment.com segment.io mixpanel.com hotjar.com optimizely.com cloudinary.com
imgix.net typekit.net fontawesome.com bootstrapcdn.com jsdelivr.net unpkg.com cdnjs.com jquery.com
w3.org schema.org facebook.com facebook.net fbcdn.net instagram.com twitter.com twimg.com x.com
linkedin.com licdn.com youtube.com ytimg.com vimeo.com vimeocdn.com tiktok.com pinterest.com
reddit.com addthis.com sharethis.com criteo.com adnxs.com adsrvr.org scorecardresearch.com
quantserve.com chartbeat.net clarity.ms bing.com live.com msn.com apple.com icloud.com mzstatic.com
adobe.com typekit.com adobedtm.com demdex.net omtrdc.net tealiumiq.com ensighten.com
sendgrid.net mailgun.org mandrillapp.com mailchimp.com list-manage.com constantcontact.com
createsend.com exacttarget.com mcsv.net rsgsv.net postmarkapp.com zoho.com protonmail.ch proton.me
mimecast.com pphosted.com ppe-hosted.com messagelabs.com barracudanetworks.com barracuda.com
spamexperts.com emailsrvr.com rackspace.com mailanyone.net trendmicro.com iphmx.com umbrella.com
opendns.com zscaler.net zscalerthree.net netskope.com
twilio.com stripe.com stripenetwork.com paypal.com paypalobjects.com braintreegateway.com adyen.com
squareup.com okta.com oktacdn.com auth0.com onelogin.com pingidentity.com duosecurity.com
jumpcloud.com cyberark.com
comcast.net comcast.com comcastbusiness.net comcastbusiness.com xfinity.com
verizon.net verizon.com verizonbusiness.com verizonwireless.com vzw.com myvzw.com mci.com uu.net
alter.net att.net att.com sbcglobal.net ameritech.net bellsouth.net pacbell.net swbell.net
prodigy.net t-mobile.com sprint.com sprintpcs.com sprintlink.net
charter.com charter.net spectrum.com spectrum.net twcable.com rr.com brighthouse.com
cox.net cox.com coxbusiness.com
centurylink.net centurylink.com qwest.net qwest.com embarq.com lumen.com lumen.net
frontier.com frontiernet.net windstream.net windstream.com consolidated.com ziply.com fairpoint.net
level3.net level3.com cogentco.com cogent.com gtt.net gtt.com zayo.com zayo.net celito.net
telia.net telianet.net telia.com arelion.com he.net hurricane-electric.net ntt.net ntt.com
gin.ntt.net tatacommunications.com tinet.net seabone.net retn.net rostelecom.ru mts.ru
btconnect.com bt.net bt.com virginm.net virginmedia.com virginmediabusiness.co.uk sky.com
talktalk.net talktalk.co.uk plusnet.co.uk zen.co.uk ee.co.uk gigaclear.net hyperoptic.com colt.net
easynet.net entanet.net m247.com iomart.com
digiweb.ie eir.ie vodafone.ie three.ie virginmedia.ie magnet.ie imagine.ie
proxad.net free.fr sfr.net sfr.fr bouyguestelecom.fr bouygtel.fr numericable.fr completel.fr
orange.com jaguar-network.com
t-ipnet.de kabel-deutschland.de versatel.de telekom.de t-online.de deutsche-telekom.com
vodafone.de o2online.de 1und1.de netcologne.de m-net.de ewetel.de arcor.de
telecomitalia.it telecomitalia.com tim.it vodafone.it infracom.it
telefonica.es telefonicaglobalsolutions.com telefonica.com rima-tde.net movistar.es vodafone.es
orange.es masmovil.es euskaltel.es
kpn.net kpn.com ziggo.nl xs4all.nl tele2.nl odido.nl proximus.be telenet.be voo.be
swisscom.ch sunrise.ch salt.ch init7.net a1.net magenta.at liwest.at upc.at
telenor.no altibox.no telia.se bahnhof.se tele2.se elisa.fi dna.fi sonera.fi
tdc.dk yousee.dk stofa.dk fibia.dk
orange.pl play.pl netia.pl tpnet.pl vectranet.pl upc.pl hrvatski-telekom.hr
turktelekom.com.tr superonline.net
shawcable.net shaw.ca bell.ca bellcanada.ca bell.com telus.net telus.com videotron.ca
videotron.com rogers.com rogers.ca cogeco.ca distributel.ca ebox.ca teksavvy.com
optusnet.com.au optus.com.au telstra.net telstra.com telstra.com.au bigpond.net.au iinet.net.au
internode.on.net tpg.com.au aussiebroadband.com.au superloop.com vocus.com.au exetel.com.au
spark.co.nz xtra.co.nz vodafone.co.nz 2degrees.nz orcon.net.nz slingshot.co.nz
chinatelecom.cn chinatelecom.com.cn chinaunicom.cn chinaunicom.com chinamobile.com
kddi.com ocn.ne.jp so-net.ne.jp plala.or.jp nuro.jp asahi-net.or.jp ntt.co.jp iij.ad.jp
biglobe.ne.jp nifty.com jcom.co.jp softbank.jp kt.com sktelecom.com lguplus.com
singtel.com starhub.com m1.com.sg pldt.com globe.com.ph converge.com.ph
airtel.in jio.com bsnl.co.in actcorp.in hathway.com
etisalat.ae du.ae stc.com.sa mobily.com.sa ooredoo.com zain.com batelco.com omantel.om
mtn.com vodacom.co.za telkom.co.za liquidtelecom.com safaricom.co.ke
claro.com vivo.com.br oi.com.br telmex.com izzi.mx totalplay.com.mx cantv.net antel.com.uy
entel.cl movistar.com etb.com.co tigo.com
arin.net ripe.net apnic.net lacnic.net afrinic.net iana.org icann.org internic.net registro.br
verisign.com verisign-grs.com markmonitor.com cscglobal.com comlaude.com afilias.net
dnsimple.com dnsmadeeasy.com ultradns.com ultradns.net ultradns.org ultradns.biz nsone.net
in-addr.arpa ip6.arpa arpa invalid example example.com example.net example.org test localhost
""".split())

HOSTING_RE = [re.compile(p) for p in (
    r"^awsdns-\d+\.(?:com|net|org|co\.uk)$",
    r"^(?:ns|dns)\d*\.[a-z0-9-]+\.(?:com|net)$",
    r"\.cdn\d*\.[a-z]+$",
)]

# TLDs that only exist inside someone's network. Valuable findings, but bbot
# cannot enumerate them passively, so they are reported separately.
INTERNAL_TLDS = set("""
local localdomain lan home internal intranet corp ad domain private workgroup belkin router
localhost dhcp sitelocal test invalid
""".split())

# Every ccTLD, plus the gTLDs that turn up in real engagements. Scraping HTML
# bodies otherwise yields "jquery.min.js" and "logo.svg" as "domains"; anything
# not on this list is parked in unknown-tld.txt for the operator to look at.
CCTLD = set("""
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt
bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh
er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr
ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk
lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf
ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc
sd se sg sh si sj sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt
tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
""".split())

GTLD = set("""
com net org edu gov mil int arpa info biz name pro aero coop museum jobs mobi travel post tel
asia cat xxx xyz app dev cloud page site online store tech space website top club shop live life
world today news blog wiki media agency solutions services group network systems digital global
center email works company industries technology consulting international management partners
ventures capital finance financial insurance bank health care clinic dental legal law academy
education school institute training design studio photography gallery art music video film
security cyber software host hosting server vpn support help team tools link one run codes zone
ltd llc inc gmbh limited plc holdings enterprises energy engineering construction properties
realty estate ninja guru rocks cool wtf lol fyi
""".split())

VALID_TLDS = CCTLD | GTLD

AUTO_PTR = re.compile(r"(?:^|[.-])\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}(?:[.-]|$)")

try:
    import tldextract
    _extract = tldextract.TLDExtract(suffix_list_urls=())
    def apex(name):
        r = _extract(name)
        if r.suffix and r.domain:
            return "%s.%s" % (r.domain, r.suffix)
        return None
    PSL = "tldextract"
except Exception:
    def apex(name):
        labels = name.split(".")
        if len(labels) < 2:
            return None
        for n in (3, 2):
            if len(labels) >= n + 1 and ".".join(labels[-n:]) in MULTI:
                return ".".join(labels[-(n + 1):])
        if ".".join(labels[-2:]) in MULTI:
            return None          # bare public suffix, e.g. "co.uk"
        return ".".join(labels[-2:])
    PSL = "built-in suffix table"

rows = []
with open(prov, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            rows.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))

fqdns = {}                                  # fqdn -> {source -> evidence}
for name, src, ev in rows:
    fqdns.setdefault(name, {}).setdefault(src, ev)

groups = defaultdict(lambda: {"fq": set(), "src": {}, "auto": 0, "total": 0})
internal, unknown = {}, {}
filtered = {}                       # apex -> [reason, {fqdns}]

def mark_filtered(ap, reason, fqs):
    ent = filtered.setdefault(ap, [reason, set()])
    ent[1].update(fqs)

for fq, srcmap in fqdns.items():
    tld = fq.rsplit(".", 1)[-1]
    if tld in INTERNAL_TLDS:
        internal.setdefault(fq, sorted(srcmap))
        continue
    if tld not in VALID_TLDS:
        # almost always a filename or asset path scraped out of an HTML body
        unknown.setdefault(fq, sorted(srcmap))
        continue
    ap = apex(fq)
    if not ap:
        internal.setdefault(fq, sorted(srcmap))
        continue
    if ap in HOSTING or any(r.search(ap) for r in HOSTING_RE):
        mark_filtered(ap, "hosting/CDN/carrier/SaaS", [fq])
        continue
    g = groups[ap]
    g["fq"].add(fq)
    g["total"] += 1
    if AUTO_PTR.search(fq):
        g["auto"] += 1
    for s, ev in srcmap.items():
        g["src"].setdefault(s, ev)

# No denylist can name every service provider, so catch the rest structurally:
# an apex whose only evidence is reverse DNS, and whose every observed name is
# machine-generated (1-2-3-4.dsl.provider.net), belongs to whoever assigned the
# address space — not to the client. Anything corroborated by a certificate,
# an IKE payload, an MTA banner, LDAP, or the scope file itself is kept.
if PROVIDER_FILTER:
    for ap in list(groups):
        g = groups[ap]
        if set(g["src"]) == {"rdns"} and g["total"] > 0 and g["auto"] == g["total"]:
            mark_filtered(ap, "provider reverse DNS", g["fq"])
            del groups[ap]

def rank(item):
    ap, g = item
    # a name confirmed by anything other than an HTML body sorts first
    corroborating = [s for s in g["src"] if s != "http"]
    body_only = set(g["src"]) == {"http"}
    auto_only = g["total"] > 0 and g["auto"] == g["total"]
    return (-len(corroborating), body_only, auto_only, -len(g["src"]), -len(g["fq"]), ap)

ordered = sorted(groups.items(), key=rank)

def w(path, lines):
    with open(os.path.join(outdir, path), "w") as fh:
        fh.write("".join(l + "\n" for l in lines))

w("domains-candidates.txt", [ap for ap, _ in ordered])
w("observed-fqdns.txt", sorted(fqdns))
w("internal-domains.txt", ["%-40s  %s" % (n, ",".join(s)) for n, s in sorted(internal.items())])
w("filtered-out.txt",
  ["%-34s  %-22s  %s" % (ap, reason, ",".join(sorted(fq)[:4]))
   for ap, (reason, fq) in sorted(filtered.items())])
w("unknown-tld.txt",
  ["%-48s  %s" % (n, ",".join(s)) for n, s in sorted(unknown.items())])

report = []
report.append("candidate apex domains derived from the IP scope")
report.append("public-suffix source: %s" % PSL)
report.append("")
report.append("%-30s %-4s %-40s %s" % ("APEX", "FQDN", "SOURCES", "FLAGS / SAMPLE EVIDENCE"))
report.append("%-30s %-4s %-40s %s" % ("-" * 30, "----", "-" * 40, "-" * 42))
for ap, g in ordered:
    srcs = sorted(g["src"])
    flags = []
    if srcs == ["http"]:
        flags.append("[body-only]")
    if g["total"] and g["auto"] == g["total"]:
        flags.append("[auto-ptr]")
    if "ike" in srcs or "smb-ldap" in srcs:
        flags.append("[infra-disclosed]")
    pick = next((s for s in ("ike", "smb-ldap", "tls", "smtp", "rdns", "scope", "whois", "http")
                 if s in g["src"]), srcs[0])
    report.append("%-30s %-4d %-40s %s %s" % (
        ap[:30], len(g["fq"]), ",".join(srcs)[:40], " ".join(flags), g["src"][pick][:60]))
report.append("")
report.append("flags: [body-only] seen only in an HTTP response body — likely third party")
report.append("       [auto-ptr]  every name looks like generated ISP reverse DNS")
report.append("       [infra-disclosed] leaked by a VPN or directory service — usually the real thing")
report.append("")
report.append("set aside: %d hosting/CDN/carrier/provider apex domains (filtered-out.txt)"
              % len(filtered))
report.append("           %d internal / non-public names (internal-domains.txt)" % len(internal))
report.append("           %d names with an implausible TLD (unknown-tld.txt)" % len(unknown))
w("discovery-report.txt", report)

print("%d %d %d %d %d" % (len(ordered), len(fqdns), len(filtered), len(internal), len(unknown)))
PY
}

stage_discover() {
  DISC_DIR="$OUTDIR/00-discover"
  PROV="$DISC_DIR/provenance.tsv"
  IPFILE="$DISC_DIR/ips.txt"
  OPENPORTS="$DISC_DIR/open-ports.txt"
  mkdir -p "$DISC_DIR"

  if [ -s "$DOMAINS" ] && [ "$REDISCOVER" -eq 0 ]; then
    info "$DOMAINS supplied ($(count_lines "$DOMAINS") entries) — nothing to discover"
    return 0
  fi
  need_file "$TARGETS"

  if [ "$DRY_RUN" -eq 1 ]; then
    local t
    info "would expand $TARGETS (cap $MAX_HOSTS hosts) and run these techniques:"
    for t in $ALL_TECHNIQUES; do
      tech_selected "$t" && printf '      - %s\n' "$t" >&2
    done
    info "would then write domains-candidates.txt and stop for review"
    # mirror the real run so the preview shows bbot/dnsx as review-blocked
    # instead of dying on the absent domains file
    AWAITING_REVIEW=1
    return 0
  fi

  : >"$PROV"

  local stats
  stats="$(expand_ip_scope "$TARGETS" "$MAX_HOSTS" "$IPFILE" \
            "$DISC_DIR/scope-hostnames.txt")" || return 1
  set -- $stats
  info "scope expands to $1 IP(s) and $2 hostname(s)"
  [ "${3:-0}" -gt 0 ] && warn "hit the --max-hosts cap ($MAX_HOSTS) — $3 address(es) dropped"
  [ "${4:-0}" -gt 0 ] && warn "$4 scope line(s) could not be parsed (see above)"
  if [ ! -s "$IPFILE" ] && [ ! -s "$DISC_DIR/scope-hostnames.txt" ]; then
    err "nothing usable in $TARGETS"
    return 1
  fi

  # a fast sweep keeps tls/http/smtp/smb-ldap off dead addresses
  if [ -s "$IPFILE" ]; then
    if tech_selected tls || tech_selected http || tech_selected smtp || tech_selected smb-ldap; then
      probe_ports
    fi
  fi

  local t
  for t in $ALL_TECHNIQUES; do
    if ! tech_selected "$t"; then
      continue
    fi
    local before after fn
    before="$(count_lines "$PROV")"
    case "$t" in
      scope)    fn=disc_scope ;;
      rdns)     fn=disc_rdns ;;
      tls)      fn=disc_tls ;;
      ike)      fn=disc_ike ;;
      http)     fn=disc_http ;;
      smtp)     fn=disc_smtp ;;
      smb-ldap) fn=disc_smb_ldap ;;
      whois)    fn=disc_whois ;;
    esac
    info "technique: $t"
    set +e
    "$fn"
    set -e
    after="$(count_lines "$PROV")"
    printf '      %s-> %s row(s)%s\n' "$C_DIM" "$((after - before))" "$C_RST" >&2
  done

  # Finding nothing is a legitimate outcome for an IP-only engagement, not an
  # error: the domain-dependent stages simply stand down.
  if [ ! -s "$PROV" ]; then
    warn "no domain evidence recovered from the scope"
    warn "bbot and dnsx will be skipped; the target-based stages continue"
    warn "to try harder: --disc with more techniques, or supply $DOMAINS yourself"
    NO_DOMAINS=1
    return 0
  fi

  local res
  res="$(normalize_candidates)" || return 1
  # shellcheck disable=SC2086
  set -- $res
  good "$1 candidate apex domain(s) from $2 observed name(s)"
  info "set aside: $3 provider/hosting, $4 internal, $5 implausible-TLD name(s)"

  if [ "$1" -eq 0 ]; then
    warn "every name recovered belonged to a provider, was internal-only, or was"
    warn "not a plausible domain — nothing left to enumerate, so bbot and dnsx"
    warn "will be skipped. See $OUTDIR/filtered-out.txt to check that call."
    NO_DOMAINS=1
    return 0
  fi

  sed -n '1,30p' "$OUTDIR/discovery-report.txt" >&2
  AWAITING_REVIEW=1
  return 0
}

# ----------------------------------- stages ---------------------------------

# 1. Passive subdomain enumeration against the root domains.
stage_bbot() {
  local d="$OUTDIR/01-bbot"
  local subs="$OUTDIR/subdomains.txt"
  mkdir -p "$d"
  [ "$DRY_RUN" -eq 0 ] && need_file "$DOMAINS"

  info "enumerating $(count_lines "$DOMAINS") domain(s) — passive only (-ef active)"
  run bbot -t "$DOMAINS" -f subdomain-enum -ef active \
      -om txt,csv,json,subdomains -o "$d" -n scan --yes || return 1

  [ "$DRY_RUN" -eq 1 ] && return 0
  collect_subdomains "$d" "$subs" || return 1
  good "collected $(count_lines "$subs") unique in-scope subdomain(s)"
}

# Pull hostnames out of whatever bbot wrote, then clamp them to the roots in
# domains.txt so an out-of-scope name never reaches the next stage.
collect_subdomains() {
  local d="$1" out="$2" raw="$OUTDIR/.tmp-subs"
  : >"$raw"

  # Preferred: bbot's own subdomains output module.
  find "$d" -type f -name 'subdomains.txt' -exec cat {} + >>"$raw" 2>/dev/null || true

  # Fallback: DNS_NAME events from output.json (ndjson).
  if [ ! -s "$raw" ] && have jq; then
    find "$d" -type f -name 'output.json' 2>/dev/null | while IFS= read -r f; do
      jq -r 'select(.type=="DNS_NAME") | .data' "$f" 2>/dev/null || true
    done >>"$raw"
  fi

  # Last resort: scrape the human-readable log.
  if [ ! -s "$raw" ]; then
    find "$d" -type f -name 'output.txt' -exec awk '/\[DNS_NAME\]/ {print $2}' {} + \
      >>"$raw" 2>/dev/null || true
  fi

  if [ ! -s "$raw" ]; then
    rm -f "$raw"
    err "no subdomains recovered from $d — inspect bbot's output manually"
    return 1
  fi

  # normalize, strip wildcards, keep only names inside the provided roots
  tr 'A-Z' 'a-z' <"$raw" \
    | sed -e 's/^\*\.//' -e 's/\.$//' -e 's/[[:space:]]//g' \
    | grep -E '^[a-z0-9._-]+\.[a-z0-9-]{2,}$' \
    | sort -u >"$OUTDIR/.tmp-subs-clean" || true

  tr 'A-Z' 'a-z' <"$DOMAINS" \
    | sed -e 's/[[:space:]]//g' -e '/^$/d' -e 's/^\*\.//' \
    | sort -u >"$OUTDIR/.tmp-roots"

  awk 'NR==FNR { roots[$0]=1; next }
       {
         for (r in roots) {
           if ($0 == r) { print; break }
           if (length($0) > length(r) &&
               substr($0, length($0) - length(r)) == "." r) { print; break }
         }
       }' "$OUTDIR/.tmp-roots" "$OUTDIR/.tmp-subs-clean" | sort -u >"$out"

  rm -f "$raw" "$OUTDIR/.tmp-subs-clean" "$OUTDIR/.tmp-roots"
  [ -s "$out" ] || { err "all recovered names fell outside $DOMAINS"; return 1; }
}

# 2. Resolve + enrich the enumerated names.
stage_dnsx() {
  local d="$OUTDIR/02-dnsx"
  local subs="$OUTDIR/subdomains.txt"
  mkdir -p "$d"

  if [ "$DRY_RUN" -eq 0 ]; then
    need_file "$subs"
  fi

  info "resolving $(count_lines "$subs") name(s) with A / ASN / recursion detail"
  run_pipe "cat $(printf '%q' "$subs") | dnsx -a -asn -re -v -t ${THREADS} \
    -o $(printf '%q' "$d/dnsx.txt") | tee $(printf '%q' "$d/dnsx-verbose.txt")" || return 1

  # Resolved IPs are captured for reporting only — the scope model keeps them
  # out of every scanning stage.
  run_pipe "cat $(printf '%q' "$subs") | dnsx -a -resp-only -silent -t ${THREADS} \
    | sort -u > $(printf '%q' "$OUTDIR/resolved-ips.txt")" || true

  [ "$DRY_RUN" -eq 1 ] && return 0
  good "$(count_lines "$OUTDIR/resolved-ips.txt") resolved IP(s) recorded (not scanned)"
}

# 3. Port discovery over the authorized scan scope.
stage_spoonmap() {
  local d="$OUTDIR/03-spoonmap"
  mkdir -p "$d"
  need_file "$TARGETS"

  # --spoonmap accepts either the script itself or the directory holding it,
  # since the repo path is the more natural thing to have on hand.
  if ! resolve_spoonmap; then
    err "spoonmap.py not found. Looked at:"
    printf '%s' "$SPOONMAP_TRIED" >&2
    [ -n "$RUNLOG" ] && printf '%s' "$SPOONMAP_TRIED" >>"$RUNLOG"
    if [ -n "$SPOONMAP_PATH" ] && [ -d "${SPOONMAP_PATH%/}" ]; then
      err "'${SPOONMAP_PATH%/}' is a directory but holds no spoonmap.py"
    fi
    err "pass --spoonmap with the script, or with the directory containing it"
    return 1
  fi
  local sm="$SPOONMAP_SCRIPT"
  info "spoonmap script: $sm"

  # spoonmap resolves config.json, nse/ and tools/ against its working
  # directory and writes its artifacts there, so it runs inside its own repo.
  local repo="$SPOONMAP_REPO"
  # remembered so the gowitness stage (and a later --resume) can find its output
  [ "$DRY_RUN" -eq 0 ] && printf '%s\n' "$repo" >"$STATE_DIR/spoonmap-repo"

  local expanded args=()
  if [ -n "$SPOONMAP_ARGS" ]; then
    expanded="$(printf '%s' "$SPOONMAP_ARGS" \
      | sed -e "s#{TARGETS}#${TARGETS}#g" -e "s#{OUTDIR}#${d}#g")"
    # shellcheck disable=SC2086
    set -- $expanded
    args=("$@")
  fi

  # It prompts for scope and options, so an unattended run would block here
  # forever. Skip rather than hang, unless it was given arguments to drive it.
  if [ ! -t 0 ] && [ ${#args[@]} -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    warn "spoonmap is interactive but stdin is not a terminal — skipping it"
    warn "rather than hanging. Run this stage from a terminal:"
    warn "  $0 --resume $OUTDIR --only spoonmap"
    warn "or pass --spoonmap-args to drive it non-interactively."
    STAGE_NOTE="skipped (needs a TTY)"
    return 0
  fi

  # spoonmap shells out to masscan, which needs raw sockets
  set_elevation
  local runner=()
  case "$ELEV_STATUS" in
    root)
      info "already root — invoking spoonmap directly" ;;
    sudo)
      runner=(sudo)
      warn_if_sudo_prompts spoonmap ;;
    unprivileged)
      if [ "$SUDO" -eq 0 ]; then
        warn "--no-sudo: running spoonmap unprivileged; its masscan phase will likely fail"
      else
        err "sudo not found — install it or pass --no-sudo"
        return 1
      fi ;;
  esac
  info "working directory: $repo (its artifacts stay there)"
  [ ${#args[@]} -eq 0 ] && info "spoonmap drives itself interactively — answer its prompts below"

  # Absolute python3 path for the same secure_path reason as ike-scan: a
  # pyenv/homebrew/virtualenv interpreter is not on sudo's PATH.
  local py
  py="$(command -v python3)"

  local rc=0
  ( cd "$repo" && run ${runner[@]+"${runner[@]}"} "$py" "$sm" ${args[@]+"${args[@]}"} ) || rc=$?

  # Under sudo, everything spoonmap just wrote into the repo is owned by root,
  # which breaks its own --resume and any later git operation. Restore it, but
  # only when the repo is already yours — never seize someone else's tree.
  if [ ${#runner[@]} -gt 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    if [ -O "$repo" ]; then
      sudo chown -R "$(id -u):$(id -g)" "$repo" 2>/dev/null \
        || warn "could not reclaim ownership of $repo — some files are still root-owned"
    else
      warn "$repo is not yours, so ownership was left alone; files spoonmap wrote"
      warn "as root may need a manual chown"
    fi
  fi

  if [ "$rc" -eq 2 ]; then
    err "exit 2 from spoonmap is usually argparse rejecting its arguments."
    err "Check its usage line above against SPOONMAP_ARGS ('${SPOONMAP_ARGS:-<none>}')."
  fi

  # Leave a pointer, since the artifacts live in the repo rather than here.
  [ "$DRY_RUN" -eq 0 ] && record_spoonmap_outputs "$repo" "$d"
  return "$rc"
}

# Note where spoonmap's artifacts ended up, without moving anything.
record_spoonmap_outputs() {
  local repo="$1" d="$2" a n
  {
    printf 'spoonmap ran in place, in its own repository:\n\n    %s\n\n' "$repo"
    printf 'Its artifacts stay there so that spoonmap --resume keeps working.\n'
    printf 'Present after this run:\n\n'
    for a in spoonmap_output.json spoonmap_output.xml spoonmap_output.gnmap \
             all_live_hosts.txt findings.json findings.md findings.txt \
             ranges.txt exclusions.txt config.json; do
      [ -e "$repo/$a" ] && printf '    %s\n' "$repo/$a"
    done
    for a in nmap_results nse_results discovery; do
      if [ -d "$repo/$a" ]; then
        n="$(find "$repo/$a" -type f 2>/dev/null | wc -l | tr -d ' ')"
        printf '    %s/  (%s file(s))\n' "$repo/$a" "$n"
      fi
    done
  } >"$d/OUTPUTS-IN-REPO.txt" 2>/dev/null || true
  if [ -f "$repo/all_live_hosts.txt" ]; then
    info "spoonmap found $(count_lines "$repo/all_live_hosts.txt") live host(s): $repo/all_live_hosts.txt"
  fi
  info "artifact locations noted in $d/OUTPUTS-IN-REPO.txt"
}

# Turn spoonmap's nmap results into exact scheme://ip:port targets. gowitness
# takes any input that already carries both a scheme and a port verbatim, so
# one line here is one probe — no port expansion, no wasted timeouts.
derive_web_urls() {
  local repo="$1" out="$2" dropfile="$3"
  python3 - "$repo" "$out" "$TARGETS" "$GW_ALL_PORTS" "$dropfile" "$GW_TRUST" <<'PY'
import glob, ipaddress, json, os, re, socket, sys
import xml.etree.ElementTree as ET

repo, out, targets_file = sys.argv[1], sys.argv[2], sys.argv[3]
all_ports = sys.argv[4] == "1"
dropfile = sys.argv[5]
trust = sys.argv[6] == "1"

# Ports that plausibly speak HTTP. Used when nmap could not name the service.
WEB_PORTS = {
    80, 81, 88, 90, 300, 443, 591, 593, 631, 832, 981, 1010, 1311, 1443, 2077, 2078,
    2082, 2083, 2086, 2087, 2095, 2096, 2443, 2480, 3000, 3128, 3333, 4243, 4443,
    4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 5985, 5986,
    6543, 7000, 7001, 7002, 7015, 7080, 7171, 7396, 7443, 7474, 7547, 7777, 8000,
    8001, 8008, 8014, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8085, 8088, 8089,
    8090, 8091, 8095, 8123, 8172, 8180, 8181, 8222, 8243, 8280, 8281, 8333, 8443,
    8500, 8530, 8531, 8800, 8834, 8880, 8887, 8888, 8890, 8983, 8990, 9000, 9001,
    9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 10000, 10250, 11371,
    12443, 16080, 18091, 18092, 20720, 32000, 55440, 55672,
}
# Ports that are conventionally TLS, when nmap did not say.
TLS_PORTS = {
    443, 832, 981, 1311, 1443, 2083, 2087, 2096, 2443, 4443, 4993, 5986, 7002,
    7443, 8172, 8243, 8443, 8531, 8834, 9043, 9443, 10250, 12443, 16080,
}
WEB_SVC = re.compile(
    r"(^|[-_|/])(http|https|www|web|caldav|soap|wsdl|rest|tomcat|jetty|nginx|apache|"
    r"iis|websphere|weblogic|jboss|glassfish|lighttpd|webcache|proxy|cups|ipp)", re.I)
# nmap named something specific and it is not a web server
NON_WEB = {
    "ssh", "smtp", "smtps", "submission", "ftp", "ftps", "ftp-data", "telnet",
    "domain", "mysql", "ms-sql-s", "postgresql", "oracle-tns", "rdp",
    "ms-wbt-server", "vnc", "netbios-ssn", "netbios-ns", "microsoft-ds", "ldap",
    "ldapssl", "kerberos-sec", "snmp", "ntp", "imap", "imaps", "pop3", "pop3s",
    "redis", "mongodb", "memcached", "rsync", "nfs", "iscsi", "sip", "h323q931",
    "tftp", "syslog", "printer", "jetdirect", "x11", "afp", "smb", "sieve",
    "docker", "zookeeper", "cassandra", "kafka", "amqp", "mqtt",
}

# ---- scope guard: never emit a host that is not in targets.txt -------------
# A hostname in targets.txt authorises the addresses it resolves to, so those
# are folded into the allowed set. Without this, a scope written as hostnames
# rejects every IP-keyed result spoonmap recorded.
nets, names = [], set()
resolved_names = 0
try:
    with open(targets_file, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "://" in line:
                line = re.sub(r"^[a-z0-9+.-]+://", "", line, flags=re.I).split("/")[0]
            if re.match(r"^[^:\[\]]+:\d+$", line):
                line = line.rsplit(":", 1)[0]
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+(?:\.\d+\.\d+\.\d+)?)$", line)
            if m:
                a = ipaddress.ip_address(m.group(1))
                t = m.group(2)
                b = ipaddress.ip_address(
                    t if "." in t else ".".join(m.group(1).split(".")[:3] + [t]))
                nets.extend(ipaddress.summarize_address_range(a, b))
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
                continue
            except ValueError:
                pass
            name = line.lower().rstrip(".")
            names.add(name)
            try:
                infos = socket.getaddrinfo(name, None)
            except Exception:
                infos = []
            got = set()
            for info in infos:
                ip = info[4][0]
                try:
                    got.add(ipaddress.ip_network(ip + ("/32" if ":" not in ip else "/128")))
                except ValueError:
                    pass
            if got:
                resolved_names += 1
                nets.extend(got)
except OSError:
    pass

_resolve_cache = {}

def in_scope(host):
    if not nets and not names:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # a hostname in the results: allow it by name, or by where it resolves
        h = host.lower().rstrip(".")
        if h in names:
            return True
        if h not in _resolve_cache:
            try:
                _resolve_cache[h] = [ipaddress.ip_address(i[4][0])
                                     for i in socket.getaddrinfo(h, None)]
            except Exception:
                _resolve_cache[h] = []
        return any(a in n for a in _resolve_cache[h] for n in nets)
    return any(addr in n for n in nets)

# ---- readers ---------------------------------------------------------------
found = []          # (host, port, service, tunnel)

def from_xml(path):
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.iter("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            if (port.get("protocol") or "tcp") != "tcp":
                continue
            try:
                pnum = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            svc = port.find("service")
            found.append((addr, pnum,
                          (svc.get("name") if svc is not None else "") or "",
                          (svc.get("tunnel") if svc is not None else "") or ""))

def from_gnmap(path):
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            m = re.match(r"^Host:\s+(\S+)", line)
            if not m:
                continue
            host = m.group(1)
            rest = line.split("Ports:", 1)[1].split("Ignored State:")[0]
            for chunk in rest.split(","):
                f = chunk.strip().split("/")
                if len(f) < 5 or f[1] != "open" or f[2] not in ("tcp", ""):
                    continue
                try:
                    pnum = int(f[0])
                except ValueError:
                    continue
                svc = f[4]
                found.append((host, pnum, svc, "ssl" if "ssl" in svc.lower() else ""))

def from_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return
    IPRE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$|^[0-9a-fA-F:]+$")

    def walk(node, host=None):
        if isinstance(node, dict):
            here = host
            for key in ("ip", "address", "addr", "host", "hostname", "target"):
                val = node.get(key)
                if isinstance(val, str) and IPRE.match(val):
                    here = val
                    break
            port = node.get("port", node.get("portid"))
            if here is not None and port is not None:
                try:
                    pnum = int(port)
                except (TypeError, ValueError):
                    pnum = None
                state = str(node.get("state", node.get("status", "open"))).lower()
                if pnum and "open" in state and "closed" not in state:
                    found.append((here, pnum,
                                  str(node.get("service", node.get("name", "")) or ""),
                                  str(node.get("tunnel", "") or "")))
            for val in node.values():
                walk(val, here)
        elif isinstance(node, list):
            for val in node:
                walk(val, host)

    walk(data)

sources = []
for path in (os.path.join(repo, "spoonmap_output.xml"),):
    if os.path.exists(path):
        from_xml(path); sources.append(os.path.basename(path))
for path in sorted(glob.glob(os.path.join(repo, "nmap_results", "*.xml"))):
    from_xml(path)
if glob.glob(os.path.join(repo, "nmap_results", "*.xml")):
    sources.append("nmap_results/*.xml")
for path in (os.path.join(repo, "spoonmap_output.gnmap"),):
    if os.path.exists(path):
        from_gnmap(path); sources.append(os.path.basename(path))
for path in (os.path.join(repo, "spoonmap_output.json"),):
    if os.path.exists(path):
        from_json(path); sources.append(os.path.basename(path))

# ---- classify --------------------------------------------------------------
def schemes_for(pnum, service, tunnel):
    svc = (service or "").lower().strip()
    tun = (tunnel or "").lower()
    tls = "ssl" in tun or "tls" in tun or "https" in svc or "ssl" in svc or "tls" in svc
    if tls:
        return ("https",)
    if "http" in svc:                       # nmap said plain http
        return ("http",)
    if pnum in TLS_PORTS:                   # unknown service, conventional TLS port
        return ("https",)
    if pnum in WEB_PORTS:
        return ("http",)
    return ("http", "https")                # genuinely unknown: try both

def is_web(pnum, service):
    if all_ports:
        return True
    svc = (service or "").lower().strip()
    if svc and WEB_SVC.search(svc):
        return True
    base = svc.split("|")[-1] if "|" in svc else svc
    if base in NON_WEB:
        return False
    return pnum in WEB_PORTS

urls, hosts, pairs, skipped = set(), set(), set(), 0
dropped_pairs = set()
for host, pnum, svc, tun in found:
    if not in_scope(host):
        dropped_pairs.add((host, pnum))
        if not trust:
            continue
    if not is_web(pnum, svc):
        skipped += 1
        continue
    hosts.add(host)
    pairs.add((host, pnum))
    for scheme in schemes_for(pnum, svc, tun):
        urls.add("%s://%s:%d" % (scheme, host, pnum))
dropped = len(dropped_pairs)

# Fallback tier: hosts are known to be up but no port data survived.
tier = "open ports"
if not urls and os.path.exists(os.path.join(repo, "all_live_hosts.txt")):
    tier = "live hosts"
    with open(os.path.join(repo, "all_live_hosts.txt"),
              encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            host = raw.strip()
            if not host:
                continue
            if not in_scope(host):
                dropped += 1
                continue
            hosts.add(host)
            for pnum in (80, 443, 8080, 8443, 8000, 8888):
                pairs.add((host, pnum))
                for scheme in schemes_for(pnum, "", ""):
                    urls.add("%s://%s:%d" % (scheme, host, pnum))
    sources.append("all_live_hosts.txt")

def sort_key(u):
    scheme, _, rest = u.partition("://")
    host, _, port = rest.rpartition(":")
    try:
        addr = ipaddress.ip_address(host)
        return (0, int(addr), int(port), scheme)
    except ValueError:
        return (1, 0, int(port), host + scheme)

with open(out, "w") as fh:
    fh.write("".join(u + "\n" for u in sorted(urls, key=sort_key)))

# Anything excluded is written out, so a scope mismatch is visible rather than
# just a number in a log line.
if dropped_pairs:
    with open(dropfile, "w") as fh:
        fh.write("# open ports spoonmap found that are NOT inside %s\n" % targets_file)
        fh.write("# %s\n" % ("included anyway (--gw-trust-spoonmap)" if trust
                             else "excluded from the gowitness run"))
        for host, pnum in sorted(dropped_pairs, key=lambda x: (str(x[0]), x[1])):
            fh.write("%s:%d\n" % (host, pnum))
elif os.path.exists(dropfile):
    os.remove(dropfile)

print("%d %d %d %d %d %d %s" % (len(urls), len(hosts), len(pairs), dropped, skipped,
                                resolved_names,
                                ",".join(sources) if sources else "-"))
print(tier, file=sys.stderr)
PY
}

# Print the expected cost of a gowitness run before committing to it.
gowitness_estimate() {
  local n="$1" fast slow
  [ "$n" -gt 0 ] || return 0
  fast=$(( (n + GW_THREADS - 1) / GW_THREADS ))
  slow=$(( (n * GW_TIMEOUT + GW_THREADS - 1) / GW_THREADS ))
  info "$n probe(s) at --threads $GW_THREADS --timeout $GW_TIMEOUT"
  info "estimated $(fmt_dur "$fast") (all responsive) to $(fmt_dur "$slow") (all filtered)"
}

# 4. Screenshot + web-service discovery across the scan scope.
stage_gowitness() {
  local d="$OUTDIR/04-gowitness"
  mkdir -p "$d"
  need_file "$TARGETS"

  local urls="$d/gowitness-targets.txt"
  local dropfile="$d/out-of-scope-ports.txt"
  local repo="" stats="" n=0 kept=0 dropped=0

  if [ "$GW_MODE" = "auto" ] && [ "$DRY_RUN" -eq 0 ]; then
    repo="$(spoonmap_repo_hint || true)"
    if [ -n "$repo" ]; then
      stats="$(derive_web_urls "$repo" "$urls" "$dropfile" 2>/dev/null || true)"
      # shellcheck disable=SC2086
      set -- $stats
      n="${1:-0}"; kept="${3:-0}"; dropped="${4:-0}"
      if [ "$n" -gt 0 ]; then
        good "using spoonmap's results: $n URL(s) across $2 host(s) / $kept open port(s)"
        info "source: ${7:-?}"
        [ "${6:-0}" -gt 0 ] && info "resolved ${6} hostname(s) in $TARGETS to compare against"
        [ "${5:-0}" -gt 0 ] && info "${5} open port(s) skipped as non-web (--gw-all-ports keeps them)"
      else
        warn "no usable open-port data in $repo"
      fi

      # A scope filter that throws away most of what spoonmap found is far more
      # likely to be a mismatch between targets.txt and spoonmap's ranges.txt
      # than a genuine out-of-scope discovery. Do not let that pass quietly.
      if [ "$dropped" -gt 0 ]; then
        if [ "$dropped" -ge "$kept" ]; then
          warn "$dropped of $((dropped + kept)) open port(s) fell OUTSIDE $TARGETS and were excluded"
          warn "that is most of what spoonmap found, which usually means targets.txt and"
          warn "spoonmap's ranges.txt cover different scope. Check: $dropfile"
          warn "to screenshot them anyway, re-run with --gw-trust-spoonmap"
        else
          info "$dropped open port(s) outside $TARGETS excluded (see $dropfile)"
        fi
      fi
    else
      warn "spoonmap results not found — cannot narrow the target list"
    fi
  fi

  # Run with cwd inside the stage dir so gowitness's default artifact names
  # (gowitness.sqlite3, gowitness.csv, gowitness.jsonl, ./screenshots) land
  # there without depending on version-specific --write-*-file flags.
  if [ "$n" -gt 0 ]; then
    gowitness_estimate "$n"
    # --log-scan-errors is affordable on a narrowed list and is the only way to
    # see WHY a probe produced nothing: gowitness silently drops any target that
    # errors or answers with status 0, writing no row at all for it.
    ( cd "$d" && run gowitness scan file -f "$urls" \
        --threads "$GW_THREADS" --timeout "$GW_TIMEOUT" --delay "$GW_DELAY" \
        --log-scan-errors \
        --write-db --write-stdout --write-csv --write-jsonl ) || return 1
  else
    # No port data: expand every target over the large port list. That is
    # 34 ports x 2 schemes = 68 probes per host, so be explicit about it.
    if [ "$GW_MODE" = "full" ]; then
      info "--gw-full: expanding every target over the large port list"
    else
      warn "falling back to --ports-large over every target in $TARGETS"
      warn "run the spoonmap stage first to cut this down by orders of magnitude"
    fi

    # gowitness cannot expand CIDRs itself, so hand it explicit addresses.
    local expanded="$d/expanded-targets.txt"
    local stats2 hosts probes
    if [ "$DRY_RUN" -eq 0 ]; then
      stats2="$(expand_ip_scope "$TARGETS" "$MAX_HOSTS" "$d/.ips" "$d/.names" 2>/dev/null)" \
        || { err "could not expand $TARGETS"; return 1; }
      cat "$d/.ips" "$d/.names" 2>/dev/null | sed -e '/^$/d' | sort -u >"$expanded"
      rm -f "$d/.ips" "$d/.names"
      # shellcheck disable=SC2086
      set -- $stats2
      [ "${3:-0}" -gt 0 ] && warn "hit the --max-hosts cap ($MAX_HOSTS) — $3 address(es) dropped"
      hosts="$(count_lines "$expanded")"
      [ "$hosts" -gt 0 ] || { err "no usable targets after expanding $TARGETS"; return 1; }
      info "expanded $(count_lines "$TARGETS") scope line(s) to $hosts address(es)"
      probes=$(( hosts * 68 ))
      gowitness_estimate "$probes"
    else
      expanded="$TARGETS"
    fi

    ( cd "$d" && run gowitness scan file -f "$expanded" \
        --threads "$GW_THREADS" --timeout "$GW_TIMEOUT" --delay "$GW_DELAY" \
        --write-db --write-stdout --write-csv --ports-large --write-jsonl ) || return 1
  fi
}

# 5. Derive the URL list the web stages consume, from gowitness results.
stage_urls() {
  local d="$OUTDIR/04-gowitness"
  local out="$OUTDIR/urls.txt"

  if [ "$DRY_RUN" -eq 1 ]; then
    info "would build $out from $d/gowitness.jsonl or gowitness.csv"
    return 0
  fi

  local jsonl csv
  jsonl="$(find "$d" -maxdepth 2 -type f -name '*.jsonl' 2>/dev/null | head -n 1)"
  csv="$(find "$d" -maxdepth 2 -type f -name '*.csv' 2>/dev/null | head -n 1)"

  : >"$out"

  if [ -n "$jsonl" ] && [ -s "$jsonl" ]; then
    info "extracting URLs from $(basename "$jsonl")"
    if have jq; then
      jq -r '.url // .URL // empty' "$jsonl" 2>/dev/null >>"$out" || true
    fi
    [ -s "$out" ] || grep -ohE 'https?://[^"'"'"' ,]+' "$jsonl" >>"$out" 2>/dev/null || true
  fi

  if [ ! -s "$out" ] && [ -n "$csv" ] && [ -s "$csv" ]; then
    info "extracting URLs from $(basename "$csv")"
    python3 - "$csv" >>"$out" <<'PY' || true
import csv, sys
path = sys.argv[1]
with open(path, newline="", encoding="utf-8", errors="replace") as fh:
    reader = csv.reader(fh)
    try:
        header = next(reader)
    except StopIteration:
        sys.exit(0)
    lowered = [h.strip().lower() for h in header]
    # gowitness names CSV columns after its Go struct fields, so the header is
    # "URL"/"FinalURL" rather than the json-tag spellings.
    idx = next((i for i, h in enumerate(lowered)
                if h in ("url", "finalurl", "final_url", "final url")), None)
    if idx is None:
        sys.exit(0)
    for row in reader:
        if len(row) > idx and row[idx].strip().startswith(("http://", "https://")):
            print(row[idx].strip())
PY
  fi

  if [ ! -s "$out" ]; then
    rm -f "$out"
    # gowitness writes no row at all for a target that errors or answers with
    # status code 0, so an empty result set means every probe came back dead —
    # not that parsing failed. That is a legitimate outcome, so the web stages
    # stand down instead of the run collapsing.
    if [ -n "$jsonl$csv" ]; then
      warn "gowitness recorded no live web responses, so there are no URLs to test"
      warn "every probe errored or returned status 0 — check the scan errors above"
      if [ -s "$d/out-of-scope-ports.txt" ]; then
        warn "note that some open ports were excluded as out of scope:"
        warn "  $d/out-of-scope-ports.txt  (--gw-trust-spoonmap includes them)"
      fi
      warn "httpx and nuclei will be skipped"
      NO_URLS=1
      return 0
    fi
    err "gowitness produced no .jsonl or .csv in $d"
    err "supply your own list at $out and re-run with --only httpx,nuclei"
    return 1
  fi

  sort -u -o "$out" "$out"
  good "$(count_lines "$out") unique URL(s) written to $out"
}

# 6. Fingerprint the live web surface.
stage_httpx() {
  local d="$OUTDIR/06-httpx"
  local urls="$OUTDIR/urls.txt"
  mkdir -p "$d"
  # a missing URL list is a reason to stand down, not to abort the whole run
  if [ "$DRY_RUN" -eq 0 ] && [ ! -s "$urls" ]; then
    warn "no URL list at $urls — run the gowitness and urls stages first,"
    warn "or drop your own list there and re-run with --only httpx,nuclei"
    STAGE_NOTE="skipped (no URLs)"
    return 0
  fi

  run_pipe "cat $(printf '%q' "$urls") \
    | httpx -title -status-code -web-server -vhost -threads ${THREADS} \
      -o $(printf '%q' "$d/httpx.txt")" || return 1
}

# 7. Template scanning against the live hosts.
stage_nuclei() {
  local d="$OUTDIR/07-nuclei"
  local urls="$OUTDIR/urls.txt"
  mkdir -p "$d"
  if [ "$DRY_RUN" -eq 0 ] && [ ! -s "$urls" ]; then
    warn "no URL list at $urls — nothing for nuclei to scan"
    STAGE_NOTE="skipped (no URLs)"
    return 0
  fi

  local tmpl="" a
  for a in "${NUCLEI_TEMPLATES[@]}"; do tmpl="$tmpl $a"; done

  run_pipe "cat $(printf '%q' "$urls") | httpx -silent -threads ${THREADS} \
    | nuclei -ni -o $(printf '%q' "$d/nuclei.out")${tmpl}" || return 1
}

# ---------------------------------- argv ------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    -t|--targets)      TARGETS="${2:?--targets needs a value}"; shift 2 ;;
    -d|--domains)      DOMAINS="${2:?--domains needs a value}"; shift 2 ;;
    -o|--outdir)       OUTDIR="${2:?--outdir needs a value}"; shift 2 ;;
    -r|--resume)       RESUME_DIR="${2:?--resume needs a value}"; shift 2 ;;
    --only)            ONLY="${2:?--only needs a value}"; shift 2 ;;
    --skip)            SKIP="${2:?--skip needs a value}"; shift 2 ;;
    --disc)            DISC_ONLY="${2:?--disc needs a value}"; shift 2 ;;
    --no-disc)         DISC_SKIP="${2:?--no-disc needs a value}"; shift 2 ;;
    --spoonmap)        SPOONMAP_PATH="${2:?--spoonmap needs a value}"; shift 2 ;;
    --spoonmap-args)   SPOONMAP_ARGS="${2:?--spoonmap-args needs a value}"; shift 2 ;;
    --threads)         THREADS="${2:?--threads needs a value}"; shift 2 ;;
    --max-hosts)       MAX_HOSTS="${2:?--max-hosts needs a value}"; shift 2 ;;
    --whois-max)       WHOIS_MAX="${2:?--whois-max needs a value}"; shift 2 ;;
    --gw-threads)      GW_THREADS="${2:?--gw-threads needs a value}"; shift 2 ;;
    --gw-timeout)      GW_TIMEOUT="${2:?--gw-timeout needs a value}"; shift 2 ;;
    --gw-delay)        GW_DELAY="${2:?--gw-delay needs a value}"; shift 2 ;;
    --gw-full)         GW_MODE="full"; shift ;;
    --gw-all-ports)    GW_ALL_PORTS=1; shift ;;
    --gw-trust-spoonmap) GW_TRUST=1; shift ;;
    --no-sudo)         SUDO=0; shift ;;
    --rediscover)      REDISCOVER=1; shift ;;
    --no-body-scrape)  BODY_SCRAPE=0; shift ;;
    --keep-providers)  PROVIDER_FILTER=0; shift ;;
    --halt-on-review)  HALT_ON_REVIEW=1; shift ;;
    --force)           FORCE=1; shift ;;
    --fail-fast)       FAIL_FAST=1; shift ;;
    --dry-run)         DRY_RUN=1; shift ;;
    --list-stages)     printf '%s\n' $ALL_STAGES; exit 0 ;;
    --list-techniques) printf '%s\n' $ALL_TECHNIQUES; exit 0 ;;
    -V|--version)      printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"; exit 0 ;;
    -h|--help)         usage; exit 0 ;;
    *)                 usage >&2; die "unknown option: $1" ;;
  esac
done

for s in $(printf '%s %s' "$ONLY" "$SKIP" | tr ',' ' '); do
  in_list "$s" "$ALL_STAGES" || die "unknown stage '$s' (see --list-stages)"
done
for s in $(printf '%s %s' "$DISC_ONLY" "$DISC_SKIP" | tr ',' ' '); do
  in_list "$s" "$ALL_TECHNIQUES" || die "unknown technique '$s' (see --list-techniques)"
done

check_positive_int() {
  case "$2" in
    ''|*[!0-9]*|0) die "$1 must be a positive integer (got '$2')" ;;
  esac
}
check_positive_int --threads    "$THREADS"
check_positive_int --max-hosts  "$MAX_HOSTS"
check_positive_int --whois-max  "$WHOIS_MAX"
check_positive_int --gw-threads "$GW_THREADS"
check_positive_int --gw-timeout "$GW_TIMEOUT"
case "$GW_DELAY" in ''|*[!0-9]*) die "--gw-delay must be a non-negative integer (got '$GW_DELAY')" ;; esac

# ---------------------------------- setup -----------------------------------

if [ -n "$RESUME_DIR" ]; then
  [ -d "$RESUME_DIR" ] || die "--resume: no such directory: $RESUME_DIR"
  OUTDIR="$RESUME_DIR"
elif [ -z "$OUTDIR" ]; then
  OUTDIR="recon-$(date '+%Y%m%d-%H%M%S')"
fi

[ -f "$TARGETS" ] && TARGETS="$(abspath "$TARGETS")"
[ -f "$DOMAINS" ] && DOMAINS="$(abspath "$DOMAINS")"

mkdir -p "$OUTDIR"
OUTDIR="$(abspath "$OUTDIR")"
STATE_DIR="$OUTDIR/.state"
mkdir -p "$STATE_DIR"
RUNLOG="$OUTDIR/run.log"
: >>"$RUNLOG"

ln -sfn "$OUTDIR" "$(dirname "$OUTDIR")/recon-latest" 2>/dev/null || true

banner "$SCRIPT_NAME $VERSION"
info "output dir : $OUTDIR"
info "targets    : $TARGETS ($(count_lines "$TARGETS") entries)"
if [ -s "$DOMAINS" ]; then
  info "domains    : $DOMAINS ($(count_lines "$DOMAINS") entries)"
else
  info "domains    : $DOMAINS (absent — discovery will propose candidates)"
fi
[ -n "$ONLY" ] && info "only       : $ONLY"
[ -n "$SKIP" ] && info "skip       : $SKIP"
[ "$DRY_RUN" -eq 1 ] && warn "dry run — no commands will be executed"

# preflight: only require binaries for stages that will actually run
MISSING=""
for s in $ALL_STAGES; do
  stage_selected "$s" || continue
  if [ "$FORCE" -eq 0 ] && [ -f "$STATE_DIR/$s.done" ]; then continue; fi
  for bin in $(stage_deps "$s"); do
    have "$bin" || in_list "$bin" "$MISSING" || MISSING="$MISSING $bin"
  done
done
if [ -n "$MISSING" ]; then
  err "missing required tool(s):$MISSING"
  die "install them (or narrow the run with --only/--skip) and try again"
fi
have jq || warn "jq not found — falling back to regex parsing for JSON output"

# Prime sudo up front. bbot and gowitness can run for a long time before
# spoonmap is reached, and an expired credential cache there would leave the
# run blocked on an unattended password prompt.
NEEDS_ROOT=""
stage_pending() {
  stage_selected "$1" || return 1
  [ "$FORCE" -eq 1 ] || [ ! -f "$STATE_DIR/$1.done" ]
}
stage_pending spoonmap && NEEDS_ROOT="$NEEDS_ROOT spoonmap"
if stage_pending discover && tech_selected ike && have ike-scan \
   && { [ ! -s "$DOMAINS" ] || [ "$REDISCOVER" -eq 1 ]; }; then
  NEEDS_ROOT="$NEEDS_ROOT ike-scan"
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$SUDO" -eq 1 ] && [ "$(id -u)" -ne 0 ] \
   && [ -n "$NEEDS_ROOT" ] && have sudo; then
  if ! sudo -n true 2>/dev/null; then
    info "priming sudo now so$NEEDS_ROOT cannot stall on a prompt later"
    sudo -v || die "sudo authentication failed — re-run with --no-sudo to skip elevation"
  fi
fi

# discovery techniques degrade individually rather than failing the run
if stage_selected discover && { [ ! -s "$DOMAINS" ] || [ "$REDISCOVER" -eq 1 ]; }; then
  DISC_MISSING=""
  for bin in dnsx tlsx httpx ike-scan nmap whois naabu; do
    have "$bin" || DISC_MISSING="$DISC_MISSING $bin"
  done
  [ -n "$DISC_MISSING" ] && \
    warn "discovery will skip or downgrade techniques needing:$DISC_MISSING"
fi

# scope inputs, checked up front so we fail before touching the network
if stage_selected spoonmap || stage_selected gowitness || stage_selected discover; then
  need_file "$TARGETS"
fi
if stage_selected bbot || stage_selected dnsx; then
  if [ ! -s "$DOMAINS" ]; then
    if stage_selected discover; then
      info "no $DOMAINS yet — the 'discover' stage will derive candidates from the IP scope"
    else
      warn "no $DOMAINS and discovery is excluded — bbot and dnsx will be skipped"
      NO_DOMAINS=1
    fi
  fi
fi

# ---------------------------------- run -------------------------------------

RUN_START=$SECONDS

for s in $ALL_STAGES; do
  run_stage "$s"
  if [ "$AWAITING_REVIEW" -eq 1 ] && [ "$HALT_ON_REVIEW" -eq 1 ] && [ "$s" = "discover" ]; then
    warn "--halt-on-review: stopping before the target-based stages"
    break
  fi
done

print_summary
[ "$AWAITING_REVIEW" -eq 1 ] && print_review_gate

TOTAL=$((SECONDS - RUN_START))
if [ -n "$FAILED_STAGES" ]; then
  warn "completed in $(fmt_dur "$TOTAL") with failures:$FAILED_STAGES"
  exit 1
fi
if [ "$AWAITING_REVIEW" -eq 1 ]; then
  warn "completed in $(fmt_dur "$TOTAL") — domain enumeration is pending your review"
  exit 2
fi
if [ "$NO_DOMAINS" -eq 1 ]; then
  good "completed in $(fmt_dur "$TOTAL") — target-based stages only, no domains in play"
  exit 0
fi
good "all selected stages completed in $(fmt_dur "$TOTAL")"
