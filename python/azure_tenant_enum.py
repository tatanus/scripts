#!/usr/bin/env python3
# =============================================================================
# NAME        : azure_tenant_enum.py
# DESCRIPTION : Resolve a DNS domain against Azure AD / Entra ID to recover the
#               tenant GUID, the tenant's federation brand / company name, and
#               its namespace type, using public, unauthenticated Microsoft
#               endpoints. Any domains supplied via a file argument are each
#               looked up the same way. Outputs text, JSON, or CSV.
#
#               NOTE: The Autodiscover GetFederationInformation endpoint once
#               returned the full set of domains registered to a tenant, but
#               Microsoft has since curtailed it - it now typically returns only
#               the queried domain. Consequently the tenant-domain list (and the
#               *.onmicrosoft.com tenant name derived from it) is usually just
#               the input domain; the tenant GUID, brand name, and namespace
#               type remain reliable.
# AUTHOR      : Adam Compton
# DATE CREATED: 2026-07-25 00:00:00
# =============================================================================
# EDIT HISTORY:
# DATE                 | EDITED BY    | DESCRIPTION OF CHANGE
# ---------------------|--------------|----------------------------------------
# 2026-07-25 00:00:00  | Adam Compton | Initial creation.
# 2026-08-26 00:00:00  | Claude       | Documented GetFederationInformation
#                      |              | curtailment; output_text now writes to a
#                      |              | stream; removed duplicate primary lookup.
# =============================================================================

import argparse
import csv
import json
import logging
import re
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

import requests

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

# -----------------------------
# Microsoft Endpoint Definitions
# -----------------------------
LOGIN_BASE = "https://login.microsoftonline.com"
USERREALM_URL = f"{LOGIN_BASE}/getuserrealm.srf"
OPENID_URL_TMPL = f"{LOGIN_BASE}/{{domain}}/.well-known/openid-configuration"
AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

# GUID embedded in the openid-configuration issuer URI, e.g.
# https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/
TENANT_GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](-?[A-Za-z0-9])*\.)+[A-Za-z]{2,}$")

# SOAP envelope for Autodiscover GetFederationInformation. Returns every domain
# registered to the tenant that owns {domain}.
SOAP_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request><Domain>{domain}</Domain></Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""

SOAP_ACTION = (
    '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
    'Autodiscover/GetFederationInformation"'
)

# -----------------------------
# Argument Parsing
# -----------------------------
def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Resolve a DNS domain against Azure AD / Entra ID to recover the "
            "tenant name, tenant GUID, and registered domains, then identify "
            "the company name behind each domain."
        )
    )
    parser.add_argument(
        "domain", help="Target domain to resolve against Azure (e.g. example.com)"
    )
    parser.add_argument(
        "-f", "--file", dest="domain_file",
        help="Path to a file of additional domains (one per line) to identify"
    )
    parser.add_argument(
        "-F", "--format", dest="fmt", choices=["text", "json", "csv"],
        default="text", help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output", dest="output",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=float, default=15.0,
        help="Per-request HTTP timeout in seconds (default: 15)"
    )
    args = parser.parse_args()

    if not DOMAIN_RE.match(args.domain):
        parser.error(f"Invalid domain format: {args.domain!r} (e.g. example.com)")

    return args

# -----------------------------
# Input Helpers
# -----------------------------
def load_domain_file(path: str) -> List[str]:
    """Load and validate additional domains from a file.

    Args:
        path (str): Path to a newline-delimited domain list. Blank lines and
            lines beginning with '#' are ignored.

    Returns:
        List[str]: Lowercased, de-duplicated, syntactically valid domains.
    """
    domains: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                entry = raw.strip().lower()
                if not entry or entry.startswith("#"):
                    continue
                if not DOMAIN_RE.match(entry):
                    logging.warning(f"{path}:{lineno}: skipping invalid domain {entry!r}")
                    continue
                domains.append(entry)
    except OSError as exc:
        logging.error(f"Could not read domain file {path}: {exc}")
        return []
    return sorted(set(domains))

# -----------------------------
# Azure / Microsoft Lookups
# -----------------------------
def get_userrealm(session: requests.Session, domain: str, timeout: float) -> Dict[str, str]:
    """Query getuserrealm.srf for a domain.

    The FederationBrandName field is Microsoft's stored display/company name for
    the owning tenant; NameSpaceType distinguishes Managed vs. Federated vs.
    Unknown (i.e. not an Azure AD domain).

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain to query.
        timeout (float): Request timeout in seconds.

    Returns:
        Dict[str, str]: Parsed realm information (possibly empty on error).
    """
    params = {"login": f"user@{domain}", "json": "1"}
    try:
        resp = session.get(USERREALM_URL, params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        logging.error(f"getuserrealm failed for {domain}: {exc}")
    except ValueError as exc:
        logging.error(f"getuserrealm returned invalid JSON for {domain}: {exc}")
    return {}

def get_tenant_id(session: requests.Session, domain: str, timeout: float) -> Optional[str]:
    """Resolve a domain's Azure AD tenant GUID via the OpenID configuration.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain to resolve.
        timeout (float): Request timeout in seconds.

    Returns:
        Optional[str]: Tenant GUID, or None if the domain is not an Azure tenant.
    """
    url = OPENID_URL_TMPL.format(domain=domain)
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            return None
        issuer = resp.json().get("issuer", "")
    except requests.RequestException as exc:
        logging.error(f"openid-configuration failed for {domain}: {exc}")
        return None
    except ValueError as exc:
        logging.error(f"openid-configuration returned invalid JSON for {domain}: {exc}")
        return None

    match = TENANT_GUID_RE.search(issuer)
    return match.group(0) if match else None

def get_tenant_domains(session: requests.Session, domain: str, timeout: float) -> List[str]:
    """Retrieve the domains the tenant owning a domain exposes.

    Uses the unauthenticated Autodiscover GetFederationInformation SOAP call.
    NOTE: Microsoft has curtailed this endpoint; it now typically returns only
    the queried domain rather than the tenant's full domain list.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain whose tenant should be enumerated.
        timeout (float): Request timeout in seconds.

    Returns:
        List[str]: Sorted, de-duplicated list of tenant domains.
    """
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": SOAP_ACTION,
        "User-Agent": "AutodiscoverClient",
    }
    body = SOAP_TEMPLATE.format(domain=domain)
    try:
        resp = session.post(AUTODISCOVER_URL, data=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logging.error(f"GetFederationInformation failed for {domain}: {exc}")
        return []

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as exc:
        logging.error(f"Could not parse Autodiscover response for {domain}: {exc}")
        return []

    # Response namespaces vary; match on the local tag name to stay robust.
    domains = {
        elem.text.strip().lower()
        for elem in root.iter()
        if elem.tag.split("}")[-1] == "Domain" and elem.text and elem.text.strip()
    }
    return sorted(domains)

# -----------------------------
# Derivation Helpers
# -----------------------------
def find_tenant_name(domains: List[str]) -> Optional[str]:
    """Derive the tenant name from its *.onmicrosoft.com domain.

    Args:
        domains (List[str]): Domains registered to the tenant.

    Returns:
        Optional[str]: The tenant name (onmicrosoft prefix), or None if absent.
    """
    for entry in domains:
        if entry.endswith(".onmicrosoft.com") and not entry.endswith(".mail.onmicrosoft.com"):
            return entry.rsplit(".onmicrosoft.com", 1)[0]
    return None

def identify_company(
    session: requests.Session,
    domain: str,
    timeout: float,
    tenant_name_cache: Dict[str, Optional[str]],
) -> Dict[str, Optional[str]]:
    """Identify the company / tenant behind a single domain.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain to identify.
        timeout (float): Request timeout in seconds.
        tenant_name_cache (Dict[str, Optional[str]]): tenant_id -> tenant name,
            populated as tenants are discovered to avoid duplicate SOAP calls.

    Returns:
        Dict[str, Optional[str]]: Company/tenant attributes for the domain.
    """
    realm = get_userrealm(session, domain, timeout)
    namespace = realm.get("NameSpaceType", "Unknown")
    company = realm.get("FederationBrandName") or None
    cloud = realm.get("CloudInstanceName") or None

    tenant_id: Optional[str] = None
    tenant_name: Optional[str] = None
    if namespace in ("Managed", "Federated"):
        tenant_id = get_tenant_id(session, domain, timeout)
        if tenant_id is not None:
            if tenant_id not in tenant_name_cache:
                tenant_domains = get_tenant_domains(session, domain, timeout)
                tenant_name_cache[tenant_id] = find_tenant_name(tenant_domains)
            tenant_name = tenant_name_cache[tenant_id]

    # Fall back to the onmicrosoft tenant name when no brand is published.
    if not company and tenant_name:
        company = tenant_name

    return {
        "domain": domain,
        "company": company,
        "namespace_type": namespace,
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "cloud_instance": cloud,
    }

# -----------------------------
# Output Handlers
# -----------------------------
def output_text(primary: Dict, records: List[Dict], out_stream) -> None:
    """Display results in readable text.

    Args:
        primary (Dict): Primary tenant summary.
        records (List[Dict]): Per-domain company records.
        out_stream: File-like object to write to.
    """
    print("=" * 70, file=out_stream)
    print(f"Primary domain : {primary['domain']}", file=out_stream)
    print(f"Tenant name    : {primary['tenant_name'] or '<unknown>'}", file=out_stream)
    print(f"Tenant GUID    : {primary['tenant_id'] or '<unknown>'}", file=out_stream)
    print(f"Company / brand: {primary['company'] or '<unknown>'}", file=out_stream)
    print(f"Tenant domains : {len(primary['tenant_domains'])} discovered", file=out_stream)
    print("=" * 70, file=out_stream)
    print(file=out_stream)
    for rec in records:
        print(f"[{rec['domain']}]", file=out_stream)
        print(f"    company        : {rec['company'] or '<unknown>'}", file=out_stream)
        print(f"    namespace_type : {rec['namespace_type']}", file=out_stream)
        print(f"    tenant_id      : {rec['tenant_id'] or '<none>'}", file=out_stream)
        print(f"    tenant_name    : {rec['tenant_name'] or '<none>'}", file=out_stream)
        print(f"    cloud_instance : {rec['cloud_instance'] or '<none>'}", file=out_stream)

def output_json(primary: Dict, records: List[Dict], out_stream) -> None:
    """Write results as JSON.

    Args:
        primary (Dict): Primary tenant summary.
        records (List[Dict]): Per-domain company records.
        out_stream: File-like object to write to.
    """
    payload = {"tenant": primary, "domains": records}
    json.dump(payload, out_stream, indent=2)
    out_stream.write("\n")

def output_csv(records: List[Dict], out_stream) -> None:
    """Write per-domain records as CSV.

    Args:
        records (List[Dict]): Per-domain company records.
        out_stream: File-like object to write to.
    """
    fields = ["domain", "company", "namespace_type", "tenant_id", "tenant_name", "cloud_instance"]
    writer = csv.DictWriter(out_stream, fieldnames=fields)
    writer.writeheader()
    for rec in records:
        writer.writerow({key: rec.get(key, "") for key in fields})

# -----------------------------
# Core Orchestration
# -----------------------------
def run(args: argparse.Namespace) -> Tuple[Dict, List[Dict]]:
    """Execute the full enumeration workflow.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        Tuple[Dict, List[Dict]]: (primary_summary, per_domain_records).
    """
    session = requests.Session()
    tenant_name_cache: Dict[str, Optional[str]] = {}

    primary = args.domain.lower()
    logging.info(f"Resolving {primary} against Azure AD ...")

    # Fetch the primary domain's details once and reuse them for both the
    # summary and its per-domain record, avoiding duplicate HTTP lookups.
    primary_realm = get_userrealm(session, primary, args.timeout)
    primary_tenant_id = get_tenant_id(session, primary, args.timeout)
    tenant_domains = get_tenant_domains(session, primary, args.timeout)
    tenant_name = find_tenant_name(tenant_domains)
    if primary_tenant_id is not None:
        tenant_name_cache[primary_tenant_id] = tenant_name

    primary_company = primary_realm.get("FederationBrandName") or tenant_name
    primary_record = {
        "domain": primary,
        "company": primary_company,
        "namespace_type": primary_realm.get("NameSpaceType", "Unknown"),
        "tenant_id": primary_tenant_id,
        "tenant_name": tenant_name,
        "cloud_instance": primary_realm.get("CloudInstanceName") or None,
    }
    primary_summary = {
        "domain": primary,
        "tenant_name": tenant_name,
        "tenant_id": primary_tenant_id,
        "company": primary_company,
        "namespace_type": primary_record["namespace_type"],
        "tenant_domains": tenant_domains,
    }

    # Additional domains to identify: tenant-discovered + file-supplied, with
    # the primary excluded (already processed above).
    others = set(tenant_domains)
    if args.domain_file:
        others.update(load_domain_file(args.domain_file))
    others.discard(primary)

    records = [primary_record]
    for domain in sorted(others):
        logging.info(f"Identifying company for {domain} ...")
        records.append(identify_company(session, domain, args.timeout, tenant_name_cache))

    return primary_summary, records

# -----------------------------
# Main Entry Point
# -----------------------------
def main() -> None:
    """Main execution flow."""
    try:
        args = parse_args()
        primary_summary, records = run(args)

        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                if args.fmt == "json":
                    output_json(primary_summary, records, handle)
                elif args.fmt == "csv":
                    output_csv(records, handle)
                else:
                    output_text(primary_summary, records, handle)
        else:
            if args.fmt == "json":
                output_json(primary_summary, records, sys.stdout)
            elif args.fmt == "csv":
                output_csv(records, sys.stdout)
            else:
                output_text(primary_summary, records, sys.stdout)

    except KeyboardInterrupt:
        logging.error("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logging.exception(f"Fatal error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
