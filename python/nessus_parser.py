#!/usr/bin/env python3
# =============================================================================
# NAME        : nessus_parser.py
# DESCRIPTION : Parses .nessus (XML) reports to extract structured data about
#               hosts, ports, and findings. Supports severity filtering, regex/
#               substring matching, and resolved reference URL extraction.
# AUTHOR      : Adam Compton
# DATE CREATED: 2025-06-05 15:45:00
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY    | DESCRIPTION OF CHANGE
# ---------------------|--------------|----------------------------------------
# 2025-06-05 15:45:00  | Adam Compton | Initial creation.
# 2025-06-27 14:10:00  | Adam Compton | Added --installedver to findings.
# 2025-09-10 14:30:00  | Adam Compton | Python 3.13 update, strict typing,
#                                       error handling, CLI UX, list-ip-ports
#                                       format ip:fqdn:protocol:port.
# =============================================================================

from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Iterable, Iterator, Mapping, Optional, Sequence, Tuple, Dict, Set, List

import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------------------
# Optional import: requests is only needed for --references resolution. We import
# lazily inside the function to keep baseline usage dependency-free.
# --------------------------------------------------------------------------------------

# =============================================================================
# Typing helpers
# =============================================================================

Element = ET.Element  # alias for clarity


class NessusParserError(Exception):
    """Domain-specific fatal error (caught in main() for clean exit)."""


class Severity(StrEnum):
    """Nessus numeric severities mapped to readable strings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @staticmethod
    def to_int(s: str) -> int:
        """Map a severity *name* to Nessus numeric level."""
        table: Dict[str, int] = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        key = s.strip().lower()
        if key not in table:
            msg = f"Unknown severity name: {s!r}. Valid: info, low, medium, high, critical."
            raise argparse.ArgumentTypeError(msg)
        return table[key]


SEVERITY_NAME_FROM_NUM: Final[Dict[int, str]] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


@dataclass(frozen=True)
class Finding:
    """Structured finding extracted from a <ReportItem>."""
    ip: str
    fqdn: str
    port: int
    protocol: str
    severity_num: int
    plugin_name: str
    installed_version: Optional[str]
    element: Element  # original ReportItem (for refs, etc.)


# =============================================================================
# Logging
# =============================================================================

def configure_logging(verbosity: int, quiet: bool) -> None:
    """
    Configure root logger based on verbosity/quiet flags.

    verbosity: 0=INFO (default), 1=DEBUG
    quiet: force WARNING unless verbosity escalates further
    """
    if quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    if verbosity >= 1:
        level = logging.DEBUG

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=level,
    )


# =============================================================================
# CLI converters & validators
# =============================================================================

def existing_file(path_str: str) -> Path:
    """argparse type: ensure file exists and is readable."""
    p = Path(path_str)
    if not p.is_file():
        raise argparse.ArgumentTypeError(f"File not found: {path_str}")
    return p


def port_type(val: str) -> int:
    """Validate port number range (1..65535)."""
    try:
        p = int(val)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid port {val!r}") from exc
    if not (1 <= p <= 65535):
        raise argparse.ArgumentTypeError("Port must be in 1..65535")
    return p


def severity_name_or_num(val: str) -> int:
    """
    Accepts 'low|medium|high|critical|info' or '0..4' and returns numeric int.
    """
    s = val.strip().lower()
    if s.isdigit():
        n = int(s)
        if n not in (0, 1, 2, 3, 4):
            raise argparse.ArgumentTypeError("Numeric severity must be one of 0..4")
        return n
    return Severity.to_int(s)


# =============================================================================
# XML helpers
# =============================================================================

def load_tree(path: Path) -> ET.ElementTree:
    """
    Load and parse a Nessus XML file.

    Raises NessusParserError on error.
    """
    try:
        return ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        raise NessusParserError(f"Failed to parse XML {path}: {exc}") from exc


def get_report_hosts(tree: ET.ElementTree) -> List[Element]:
    """
    Return all <ReportHost> elements.
    """
    root = tree.getroot()
    return list(root.findall(".//ReportHost"))


def host_tags_map(host: Element) -> Dict[str, str]:
    """
    Extract <HostProperties><tag name="...">value</tag> into a dict.
    """
    tags: Dict[str, str] = {}
    hp = host.find("HostProperties")
    if hp is None:
        return tags
    for tag in hp.findall("tag"):
        name = tag.get("name")
        if name is None:
            continue
        value = (tag.text or "").strip()
        tags[name] = value
    return tags


def host_ip_and_fqdn(host: Element) -> Tuple[str, str]:
    """
    Derive (ip, fqdn) from host properties with sensible fallbacks.

    - Prefer tag host-ip for IP, else fall back to @name if it looks like an IP.
    - Prefer tag host-fqdn for FQDN, else try dns-name or netbios-name; if @name
      is not an IP, treat @name as fqdn.
    """
    name_attr = host.get("name", "")
    tags = host_tags_map(host)

    ip = tags.get("host-ip", "")
    fqdn = tags.get("host-fqdn", "") or tags.get("dns-name", "") or tags.get("netbios-name", "")

    is_ip_name = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name_attr))

    if not ip and is_ip_name:
        ip = name_attr
    if not fqdn and name_attr and not is_ip_name:
        fqdn = name_attr

    # Normalize blanks
    return ip, fqdn


def iter_report_items(host: Element) -> Iterator[Element]:
    """Yield all <ReportItem> children for a host."""
    yield from host.findall("ReportItem")


# =============================================================================
# Filters & matching
# =============================================================================

def matches_severity(
    severity_str: Optional[str],
    *,
    min_level: Optional[int] = None,
    exact_level: Optional[int] = None,
) -> bool:
    """
    Check if a Nessus numeric severity string passes filters.

    severity_str: string like '0'..'4' (may be None)
    min_level: include if severity >= min_level
    exact_level: include only if severity == exact_level
    """
    if severity_str is None:
        return False
    try:
        sev = int(severity_str)
    except ValueError:
        return False

    if exact_level is not None:
        return sev == exact_level
    if min_level is not None:
        return sev >= min_level
    return True


def safe_compile_regex(pattern: Optional[str]) -> Optional[re.Pattern[str]]:
    """
    Compile a regex safely; returns None if pattern is None.
    Raises NessusParserError on invalid patterns.
    """
    if pattern is None:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise NessusParserError(f"Invalid regex {pattern!r}: {exc}") from exc


def extract_installed_version(plugin_output_text: str) -> str:
    """
    Extract 'Installed version|build: X' or 'version|build: X' from plugin_output.
    Returns '-' if not found.
    """
    if not plugin_output_text:
        return "-"
    primary = re.compile(r"^\s*(Installed|Reported)\s+(version|build)\s*:\s*(.+)$", re.IGNORECASE)
    secondary = re.compile(r"^\s*(version|build)\s*:\s*(.+)$", re.IGNORECASE)

    for line in plugin_output_text.splitlines():
        m = primary.match(line.strip())
        if m:
            return m.group(3).strip()

    for line in plugin_output_text.splitlines():
        m = secondary.match(line.strip())
        if m:
            return m.group(2).strip()

    return "-"


# =============================================================================
# Reference resolution (lazy requests)
# =============================================================================

def resolve_redirects(
    reference_urls: Set[str],
    *,
    timeout: float,
    verify_tls: bool,
    user_agent: str = "Mozilla/5.0 (compatible; NessusParser/1.0)",
) -> Dict[str, str]:
    """
    Follow redirects for each URL and return mapping original->final.
    - If 'requests' is unavailable or a request fails, fall back to identity.
    """
    try:
        import requests  # type: ignore
    except Exception:
        logging.warning("requests not installed; returning original URLs.")
        return {u: u for u in reference_urls}

    resolved: Dict[str, str] = {}
    headers = {"User-Agent": user_agent}

    for url in reference_urls:
        try:
            with requests.get(url, allow_redirects=True, timeout=timeout, headers=headers, verify=verify_tls, stream=True) as resp:
                resolved[url] = resp.url
        except requests.RequestException as exc:  # type: ignore[attr-defined]
            logging.warning("Failed to resolve %s: %s", url, exc)
            resolved[url] = url
    return resolved


# =============================================================================
# Command implementations
# =============================================================================

def cmd_live_hosts(tree: ET.ElementTree, args: argparse.Namespace) -> int:
    """
    Print IPs for hosts that have at least one ReportItem passing severity filters.
    """
    ips: Set[str] = set()

    for host in get_report_hosts(tree):
        ip, _fqdn = host_ip_and_fqdn(host)
        for ri in iter_report_items(host):
            if matches_severity(
                ri.get("severity"),
                min_level=args.severity_min,
                exact_level=args.severity_exact,
            ):
                if ip:
                    ips.add(ip)
                else:
                    # Fallback to @name if no IP
                    name = host.get("name", "")
                    if name:
                        ips.add(name)
                break

    for ip in sorted(ips):
        print(ip)
    return 0


def cmd_open_ports(tree: ET.ElementTree, args: argparse.Namespace) -> int:
    """
    Print open ports for a single IP, filtered by severity.
    """
    found_host = False
    ports: Set[int] = set()

    for host in get_report_hosts(tree):
        ip, _ = host_ip_and_fqdn(host)
        if ip != args.ip:
            continue
        found_host = True
        for ri in iter_report_items(host):
            if matches_severity(
                ri.get("severity"),
                min_level=args.severity_min,
                exact_level=args.severity_exact,
            ):
                port_attr = ri.get("port")
                if port_attr and port_attr.isdigit():
                    ports.add(int(port_attr))

    if not found_host:
        logging.warning("IP not found: %s", args.ip)
        return 1

    for p in sorted(ports):
        print(p)
    return 0


def cmd_ips_with_port(tree: ET.ElementTree, args: argparse.Namespace) -> int:
    """
    Print IPs that have a given open port (filtered by severity).
    """
    ips: Set[str] = set()
    target_port = str(args.port)

    for host in get_report_hosts(tree):
        ip, _ = host_ip_and_fqdn(host)
        for ri in iter_report_items(host):
            if ri.get("port") == target_port and matches_severity(
                ri.get("severity"),
                min_level=args.severity_min,
                exact_level=args.severity_exact,
            ):
                if ip:
                    ips.add(ip)
                else:
                    name = host.get("name", "")
                    if name:
                        ips.add(name)
                break

    for ip in sorted(ips):
        print(ip)
    return 0


def cmd_list_ip_ports(tree: ET.ElementTree, args: argparse.Namespace) -> int:
    """
    Print 'ip:fqdn:protocol:port' for all ReportItems passing severity filters.
    Empty fields are left blank when unknown.
    """
    lines: Set[str] = set()

    for host in get_report_hosts(tree):
        ip, fqdn = host_ip_and_fqdn(host)
        for ri in iter_report_items(host):
            if not matches_severity(
                ri.get("severity"),
                min_level=args.severity_min,
                exact_level=args.severity_exact,
            ):
                continue

            protocol = (ri.get("protocol") or "").lower()
            port = ri.get("port") or ""

            # Normalize protocol; Nessus typically uses 'tcp'/'udp'
            if protocol not in ("tcp", "udp", ""):
                protocol = protocol.lower()

            # Emit even if ip/fqdn is blank per requirement
            lines.add(f"{ip}:{fqdn}:{protocol}:{port}")

    for line in sorted(lines):
        print(line)
    return 0


def cmd_findings(tree: ET.ElementTree, args: argparse.Namespace) -> int:
    """
    List findings, optionally filtering by exact severity (local to this cmd),
    regex, or substring search. With --references, output resolved references.
    """
    # Local severity filter (over and above global min/exact, if provided)
    local_exact: Optional[int] = None
    if args.severity is not None:
        local_exact = severity_name_or_num(args.severity)

    rx: Optional[re.Pattern[str]] = safe_compile_regex(args.regex)
    substr = (args.search or "").lower()

    findings: List[Finding] = []

    for host in get_report_hosts(tree):
        ip, _fqdn = host_ip_and_fqdn(host)
        for ri in iter_report_items(host):
            sev_str = ri.get("severity")
            if not matches_severity(sev_str, min_level=args.severity_min, exact_level=args.severity_exact):
                continue

            # Apply local exact severity if requested
            if local_exact is not None and sev_str != str(local_exact):
                continue

            port_str = ri.get("port") or "0"
            try:
                port = int(port_str)
            except ValueError:
                port = 0

            protocol = (ri.get("protocol") or "").lower()
            plugin_name = ri.get("pluginName") or ""
            description = (ri.findtext("description") or "")

            if rx is not None and not rx.search(plugin_name):
                continue
            if substr and (substr not in plugin_name.lower()) and (substr not in description.lower()):
                continue

            installed_version: Optional[str] = None
            if args.installedver:
                installed_version = extract_installed_version(ri.findtext("plugin_output") or "")

            try:
                sev_num = int(sev_str or "0")
            except ValueError:
                sev_num = 0

            findings.append(
                Finding(
                    ip=ip or host.get("name", ""),
                    fqdn=_fqdn,
                    port=port,
                    protocol=protocol,
                    severity_num=sev_num,
                    plugin_name=plugin_name,
                    installed_version=installed_version,
                    element=ri,
                )
            )

    if args.references:
        ref_set: Set[str] = set()
        for f in findings:
            for ref in f.element.findall("see_also"):
                if ref.text:
                    for raw_line in ref.text.splitlines():
                        url = raw_line.strip()
                        if url:
                            ref_set.add(url)

        if not ref_set:
            return 0

        resolved = resolve_redirects(
            ref_set,
            timeout=args.http_timeout,
            verify_tls=not args.insecure,
            user_agent=args.user_agent,
        )
        for original in sorted(resolved):
            print(f"{original} -> {resolved[original].strip()}")
        return 0

    # Normal findings output
    for f in sorted(findings, key=lambda x: (x.ip, x.port, x.severity_num, x.plugin_name.lower())):
        sev_txt = SEVERITY_NAME_FROM_NUM.get(f.severity_num, str(f.severity_num))
        if args.installedver:
            print(f"{f.ip}:{f.fqdn}:{f.port}:{sev_txt}:{f.plugin_name}:{f.installed_version or '-'}")
        else:
            print(f"{f.ip}:{f.fqdn}:{f.port}:{sev_txt}:{f.plugin_name}")
    return 0


# =============================================================================
# CLI
# =============================================================================

EXAMPLES: Final[str] = r"""
Examples:
  # List all live hosts with any finding of medium-or-higher severity
  nessus_parser.py report.nessus -m medium live-hosts

  # Open ports for a specific IP (exact severity=high)
  nessus_parser.py report.nessus -e high open-ports -i 10.0.0.5

  # IPs that have tcp/443 (any severity)
  nessus_parser.py report.nessus ips-with-port -p 443

  # All pairs in ip:fqdn:protocol:port format (min severity=low)
  nessus_parser.py report.nessus -m low list-ip-ports

  # Findings with regex on plugin name and resolved references
  nessus_parser.py report.nessus findings -r "(?i)openssl" --references

  # Findings exact local severity (name or number) and include installed version
  nessus_parser.py report.nessus findings --severity medium --installedver
"""


def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI parser with strict types, helpful epilog, and shared filters.
    """
    formatter = lambda prog: argparse.ArgumentDefaultsHelpFormatter(  # noqa: E731
        prog, max_help_position=32
    )
    parser = argparse.ArgumentParser(
        description="Parse Nessus .nessus XML reports for hosts, ports, and findings.",
        epilog=EXAMPLES,
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=32),  # type: ignore[return-value]
    )

    # Add logging controls
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (repeat for more detail).")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only warnings and errors.")

    # Required report path
    parser.add_argument("file", type=existing_file, help="Path to .nessus XML file")

    # Global severity filters
    parser.add_argument(
        "--severity-min", "-m",
        type=severity_name_or_num,
        help="Minimum severity to include (name or 0..4)."
    )
    parser.add_argument(
        "--severity-exact", "-e",
        type=severity_name_or_num,
        help="Only include findings of exactly this severity (name or 0..4)."
    )

    sub = parser.add_subparsers(dest="cmd", title="Commands", required=True)

    # live-hosts
    sub.add_parser("live-hosts", help="List all live host IPs that have at least one matching finding.", formatter_class=formatter)

    # open-ports
    sp = sub.add_parser("open-ports", help="Show open ports for a specific IP.", formatter_class=formatter)
    sp.add_argument("--ip", "-i", required=True, help="IP address to query.")

    # ips-with-port
    sp = sub.add_parser("ips-with-port", help="List IPs that have the specified open port.", formatter_class=formatter)
    sp.add_argument("--port", "-p", required=True, type=port_type, help="Port number to search for.")

    # list-ip-ports
    sub.add_parser("list-ip-ports", help="List 'ip:fqdn:protocol:port' for all matching items.", formatter_class=formatter)

    # findings
    sp = sub.add_parser("findings", help="List findings or resolve their reference URLs.", formatter_class=formatter)
    sp.add_argument("--severity", help="(Local to this command) exact severity for findings (name or 0..4).")
    sp.add_argument("--regex", "-r", help="Regex to match plugin name.")
    sp.add_argument("--search", "-s", help="Substring search in plugin name or description (case-insensitive).")
    sp.add_argument("--references", "-R", action="store_true", help="Output resolved reference URLs only.")
    sp.add_argument("--installedver", action="store_true", help="Include Installed Version from <plugin_output>.")
    sp.add_argument("--http-timeout", type=float, default=10.0, help="Timeout in seconds for reference resolution HTTP requests.")
    sp.add_argument("--insecure", action="store_true", help="Disable TLS verification for reference resolution (NOT recommended).")
    sp.add_argument("--user-agent", default="Mozilla/5.0 (compatible; NessusParser/1.0)", help="User-Agent for reference resolution.")

    return parser


# =============================================================================
# Main
# =============================================================================

def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Entry point: parse args, dispatch subcommands, and handle errors cleanly.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(args.verbose, args.quiet)

    # Sanity: conflicting global severity filters?
    if args.severity_min is not None and args.severity_exact is not None:
        logging.warning("--severity-exact overrides --severity-min when both are set.")

    try:
        tree = load_tree(args.file)
        cmd = args.cmd

        # Pattern matching for dispatch (Python 3.10+)
        match cmd:
            case "live-hosts":
                return cmd_live_hosts(tree, args)
            case "open-ports":
                return cmd_open_ports(tree, args)
            case "ips-with-port":
                return cmd_ips_with_port(tree, args)
            case "list-ip-ports":
                return cmd_list_ip_ports(tree, args)
            case "findings":
                return cmd_findings(tree, args)
            case _:
                raise NessusParserError(f"Unknown command: {cmd!r}")

    except NessusParserError as exc:
        logging.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        logging.error("Interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
