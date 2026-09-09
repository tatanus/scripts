#!/usr/bin/env bash
# Strict mode (manual error handling; no `-e`)
set -uo pipefail
IFS=$'\n\t'
# =============================================================================
# NAME         : scope_lib.sh
# DESCRIPTION  : Scope handling for the unified recon framework. Expands
#                targets.txt (CIDRs, ranges, host:port, URLs) into a flat IP
#                list plus any embedded hostnames, and derives exact
#                scheme://ip:port probe targets from nmap XML for gowitness.
#                Enforces the strict domains<->targets separation model.
# AUTHOR       : Adam Compton
# DATE CREATED : 2026-09-09
# =============================================================================
# EDIT HISTORY:
# DATE       | EDITED BY    | DESCRIPTION OF CHANGE
# -----------|--------------|----------------------------------------
# 2026-09-09 | Adam Compton | Initial creation - ported from recon_new.sh
# =============================================================================

if [[ -z "${SCOPE_LIB_LOADED:-}" ]]; then
    SCOPE_LIB_LOADED=1

    ###########################################################################
    # scope_expand
    # Purpose : Expand a scope file into an IP list and a hostname list.
    #           gowitness's file reader does NOT expand CIDRs, so anything
    #           handed to it must already be one address per line.
    # Args    : $1 scope-file  $2 max-hosts  $3 ip-out  $4 hostname-out
    # Output  : prints "<ips> <hosts> <over-cap> <unparsed>" counts
    ###########################################################################
    function scope_expand() {
        python3 - "${1}" "${2}" "${3}" "${4}" << 'PY'
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

    ###########################################################################
    # scope_web_urls_from_nmap
    # Purpose : Turn nmap XML results into exact scheme://ip:port probe
    #           targets, keeping only web-ish open ports and only hosts inside
    #           targets.txt (unless trust=1). One line == one gowitness probe.
    # Args    : $1 nmap-xml-glob-dir  $2 url-out  $3 targets-file
    #           $4 all-ports(0/1)     $5 drop-out  $6 trust(0/1)
    # Output  : prints "<urls> <hosts> <kept> <dropped> <nonweb> <resolved>"
    ###########################################################################
    function scope_web_urls_from_nmap() {
        python3 - "${1}" "${2}" "${3}" "${4}" "${5}" "${6}" << 'PY'
import glob, ipaddress, os, re, socket, sys
import xml.etree.ElementTree as ET

xmldir, out, targets_file = sys.argv[1], sys.argv[2], sys.argv[3]
all_ports = sys.argv[4] == "1"
dropfile = sys.argv[5]
trust = sys.argv[6] == "1"

WEB_HINTS = ("http", "https", "ssl", "http-proxy", "http-alt", "https-alt",
             "web", "soap", "rest", "tls")
TLS_HINTS = ("https", "ssl", "tls", "https-alt")

# Build the in-scope IP set from targets.txt (best effort; hostnames resolved).
scope = set()
resolved = 0
try:
    with open(targets_file, encoding="utf-8", errors="replace") as fh:
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
                for ip in net:
                    scope.add(str(ip))
                continue
            except ValueError:
                pass
            try:
                for info in socket.getaddrinfo(line, None):
                    scope.add(info[4][0])
                    resolved += 1
            except OSError:
                pass
except OSError:
    pass

urls, kept, dropped, nonweb = [], 0, 0, 0
hosts_seen = set()

for xmlpath in sorted(glob.glob(os.path.join(xmldir, "*.xml"))):
    try:
        tree = ET.parse(xmlpath)
    except ET.ParseError:
        continue
    for host in tree.getroot().iter("host"):
        addr = None
        for a in host.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            if port.get("protocol") != "tcp":
                continue
            pnum = port.get("portid")
            svc = port.find("service")
            name = (svc.get("name") if svc is not None else "") or ""
            tunnel = (svc.get("tunnel") if svc is not None else "") or ""
            is_web = any(h in name for h in WEB_HINTS) or pnum in ("80", "443", "8080", "8443")
            if not is_web and not all_ports:
                nonweb += 1
                continue
            if scope and addr not in scope and not trust:
                dropped += 1
                continue
            secure = tunnel == "ssl" or any(h in name for h in TLS_HINTS) \
                or pnum in ("443", "8443", "9443")
            scheme = "https" if secure else "http"
            urls.append("%s://%s:%s" % (scheme, addr, pnum))
            kept += 1
            hosts_seen.add(addr)

with open(out, "w") as fh:
    fh.write("".join(u + "\n" for u in sorted(set(urls))))
if dropped:
    with open(dropfile, "w") as fh:
        fh.write("see nmap XML; %d open port(s) outside targets.txt\n" % dropped)

print("%d %d %d %d %d %d" % (len(set(urls)), len(hosts_seen), kept, dropped, nonweb, resolved))
PY
    }
fi
