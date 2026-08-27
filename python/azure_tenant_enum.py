#!/usr/bin/env python3
# =============================================================================
# NAME        : azure_tenant_enum.py
# DESCRIPTION : Resolve a DNS domain against Azure AD / Entra ID to recover the
#               tenant GUID, the tenant's federation brand / company name, and
#               its namespace type, using public, unauthenticated Microsoft
#               endpoints. Any domains supplied via a file argument are each
#               looked up the same way. Outputs text, JSON, or CSV.
#
#               For each domain it also reports the identity provider in front
#               of the tenant (auth_provider: Okta, ADFS, Ping, OneLogin,
#               Shibboleth, Duo, Google, or Entra-managed), derived from the
#               federation AuthURL - this is unauthenticated.
#
#               OPTIONAL --mfa-test: assess MFA / authentication posture on a
#               best-effort basis, degrading with the inputs supplied:
#                 * -u USER -p PASS : full ROPC sign-in test across several
#                   first-party clients; the AADSTS result reveals MFA
#                   enforcement (AADSTS50076 = MFA required; a token = no MFA on
#                   that endpoint) and inconsistent coverage (MFASweep).
#                 * -u USER (no password) : unauthenticated GetCredentialType
#                   probe - account existence, federated IdP, Seamless SSO,
#                   has-password. MFA enforcement is NOT determinable this way.
#                 * neither : domain-level posture only (see auth_provider).
#
#               AUTHORIZATION: --mfa-test authenticates against live Microsoft
#               endpoints. Only use it against tenants/accounts you are
#               explicitly authorized to test. It tests ONE account (it is not a
#               password sprayer) and halts on smart-lockout, but attempts can
#               still trigger sign-in alerts or lockout.
#
#               TENANT NAME: The *.onmicrosoft.com name is resolved from several
#               sources, in order: Autodiscover GetFederationInformation (now
#               curtailed by Microsoft - usually only echoes the queried
#               domain), the Azure ACS metadata endpoint (the TeamFiltration
#               technique - authoritative but empty on newer tenants as ACS is
#               retired), and finally a GUID-verified guess (candidate names
#               derived from the domain/brand, accepted only if
#               "<candidate>.onmicrosoft.com" resolves to the same tenant GUID -
#               so a wrong name is never reported). When none succeed the name is
#               left blank; the tenant GUID, brand, and namespace stay reliable.
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
# 2026-08-26 00:00:00  | Claude       | Added identity-provider detection
#                      |              | (auth_provider) and optional --mfa-test
#                      |              | single-account MFA enforcement probe.
# 2026-08-26 00:00:00  | Claude       | --mfa-test made best-effort: works with
#                      |              | username-only (GetCredentialType probe)
#                      |              | or no credentials (domain posture).
# 2026-08-27 00:00:00  | Claude       | Fixed tenant-name resolution: add ACS
#                      |              | metadata lookup + GUID-verified guess
#                      |              | fallback (GetFederationInformation dead).
# =============================================================================

import argparse
import csv
import getpass
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
# Azure Access Control Service (ACS) metadata - accepts a domain OR a tenant
# GUID and lists the tenant's registered domains in allowedAudiences (the
# technique used by TeamFiltration). Being retired by Microsoft, so it is often
# empty on newer tenants, but authoritative when populated.
ACS_METADATA_URL_TMPL = "https://accounts.accesscontrol.windows.net/{identifier}/metadata/json/1"

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
# Identity-Provider Classification
# -----------------------------
# Map substrings found in a federated domain's AuthURL to a friendly IdP name.
# Order matters: more specific patterns first.
IDP_PATTERNS = (
    ("Okta", ("okta.com", "oktapreview.com", "okta-emea.com", "okta.")),
    ("Microsoft ADFS", ("/adfs/ls",)),
    ("Ping", ("pingone.com", "pingidentity.com", "ping-eng.com")),
    ("OneLogin", ("onelogin.com",)),
    ("Duo SSO", ("duosecurity.com",)),
    ("Auth0", ("auth0.com",)),
    ("Google", ("accounts.google.com",)),
    ("CAS", ("/cas/login",)),
    ("Centrify/Idaptive", ("my.centrify.com", "idaptive.app")),
    ("Shibboleth", ("/idp/profile/saml2", "shibboleth")),
)

# -----------------------------
# MFA Test (ROPC) Definitions
# -----------------------------
# Resource Owner Password Credentials sign-in endpoint (v1). A successful token
# means the password alone was sufficient for that client/resource (an MFA gap);
# an AADSTS error can indicate MFA is enforced. Testing several first-party
# clients reveals inconsistent Conditional Access / MFA coverage (MFASweep).
TOKEN_URL = f"{LOGIN_BASE}/common/oauth2/token"

# Unauthenticated credential-type endpoint: reveals whether an account exists,
# its federation redirect (IdP), and Seamless SSO - all without a password.
CREDTYPE_URL = f"{LOGIN_BASE}/common/GetCredentialType"

# (label, client_id, resource) - well-known public first-party clients.
ROPC_CLIENTS = (
    ("Azure AD Graph (AzureAD PowerShell)", "1b730954-1685-4b74-9bfd-dac224a7b894", "https://graph.windows.net"),
    ("Azure Mgmt (Az PowerShell)", "1950a258-227b-4e31-a9cf-717495945fc2", "https://management.core.windows.net/"),
    ("Microsoft Graph (Graph PowerShell)", "14d82eec-204b-4c2f-b7e8-296a70dab67e", "https://graph.microsoft.com"),
    ("Exchange Online (Office)", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "https://outlook.office365.com"),
)

AADSTS_RE = re.compile(r"AADSTS\d+")

# Password correct, but a second factor / strong-auth policy stopped sign-in.
MFA_ENFORCED_CODES = {
    "AADSTS50076": "MFA required for this user",
    "AADSTS50079": "MFA enrollment required",
    "AADSTS50072": "User must enroll in MFA",
    "AADSTS50074": "Strong authentication required",
    "AADSTS50158": "External security challenge (Conditional Access / 3rd-party MFA)",
    "AADSTS53004": "MFA enrollment required (Conditional Access)",
}
# Password correct, but blocked / limited for another reason (creds still valid).
VALID_OTHER_CODES = {
    "AADSTS50055": "Password expired",
    "AADSTS50144": "On-prem password expired",
    "AADSTS65001": "User or admin consent required",
    "AADSTS53003": "Access blocked by Conditional Access policy",
    "AADSTS50131": "Conditional Access (device/network) condition not met",
    "AADSTS530003": "Device policy blocked sign-in",
}
INVALID_CODES = {"AADSTS50126": "Invalid username or password"}
LOCKED_CODES = {"AADSTS50053": "Account locked / too many attempts (smart lockout)"}
DISABLED_CODES = {"AADSTS50057": "Account is disabled"}
NOTFOUND_CODES = {
    "AADSTS50034": "User not found in tenant",
    "AADSTS90002": "Tenant not found",
    "AADSTS700016": "Client application not found in tenant",
}

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
    mfa = parser.add_argument_group("MFA / auth test (best-effort; authorized use only)")
    mfa.add_argument(
        "--mfa-test", dest="mfa_test", action="store_true",
        help="Assess MFA / auth posture. Best-effort: -u+-p runs a real sign-in "
             "(MFA enforcement) test; -u alone runs an unauthenticated account "
             "probe; neither reports domain-level posture only"
    )
    mfa.add_argument(
        "-u", "--username", dest="username",
        help="UPN to assess (e.g. user@example.com)"
    )
    mfa.add_argument(
        "-p", "--password", dest="password",
        help="Password for the full sign-in test (omit for no-password checks; "
             "passing it here exposes it in shell history - prefer --prompt-password)"
    )
    mfa.add_argument(
        "--prompt-password", dest="prompt_password", action="store_true",
        help="Securely prompt for the password (avoids argv exposure) to run the "
             "full sign-in test"
    )
    args = parser.parse_args()

    if not DOMAIN_RE.match(args.domain):
        parser.error(f"Invalid domain format: {args.domain!r} (e.g. example.com)")

    if args.mfa_test:
        if args.prompt_password and not args.password:
            if not args.username:
                parser.error("--prompt-password requires -u/--username")
            try:
                args.password = getpass.getpass(f"Password for {args.username}: ")
            except (EOFError, KeyboardInterrupt):
                parser.error("password entry aborted")
        if args.password and not args.username:
            logging.warning(
                "Password supplied without -u/--username; ignoring it and "
                "running domain-level checks only."
            )

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

def get_acs_domains(session: requests.Session, identifier: str, timeout: float) -> List[str]:
    """List a tenant's domains via the Azure ACS metadata endpoint.

    The identifier may be a domain OR a tenant GUID. Domains are harvested from
    every domain-like token in the allowedAudiences service-principal strings.
    ACS is being retired, so this is often empty on newer tenants, but it is
    authoritative (and includes the *.onmicrosoft.com name) when populated.

    Args:
        session (requests.Session): Shared HTTP session.
        identifier (str): A domain or tenant GUID.
        timeout (float): Request timeout in seconds.

    Returns:
        List[str]: Sorted, de-duplicated domains (may be empty).
    """
    url = ACS_METADATA_URL_TMPL.format(identifier=identifier)
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except requests.RequestException as exc:
        logging.error(f"ACS metadata failed for {identifier}: {exc}")
        return []
    except ValueError:
        return []

    domains = set()
    for audience in data.get("allowedAudiences") or []:
        # Audiences look like "<spn-guid>/<host>@<realm>"; pull every token
        # that parses as a domain (the onmicrosoft name can appear either side).
        for token in re.split(r"[@/]", audience):
            token = token.strip().lower()
            if "." in token and DOMAIN_RE.match(token):
                domains.add(token)
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

def _tenant_name_candidates(domain: str, brand: Optional[str]) -> List[str]:
    """Derive plausible *.onmicrosoft.com prefixes from a domain and brand.

    Args:
        domain (str): The custom domain (e.g. "contoso.com").
        brand (Optional[str]): FederationBrandName, if known.

    Returns:
        List[str]: Ordered, de-duplicated candidate prefixes.
    """
    candidates: List[str] = []
    labels = domain.split(".")
    if labels:
        candidates.append(labels[0])           # contoso.com     -> contoso
    if len(labels) > 1:
        candidates.append("".join(labels[:-1]))  # sub.contoso.com -> subcontoso
    if brand:
        flat = re.sub(r"[^a-z0-9]", "", brand.lower())
        candidates.append(flat)                # "Contoso Ltd"   -> contosoltd
        words = brand.lower().split()
        if words:
            candidates.append(re.sub(r"[^a-z0-9]", "", words[0]))  # -> contoso

    seen: set = set()
    ordered: List[str] = []
    for cand in candidates:
        if cand and cand not in seen:
            seen.add(cand)
            ordered.append(cand)
    return ordered

def resolve_tenant_name(
    session: requests.Session,
    domain: str,
    brand: Optional[str],
    tenant_id: Optional[str],
    timeout: float,
) -> Optional[str]:
    """Recover the *.onmicrosoft.com tenant name by verified candidate matching.

    GetFederationInformation no longer lists a tenant's domains, so the
    onmicrosoft name is derived from the domain/brand and CONFIRMED by checking
    that "<candidate>.onmicrosoft.com" resolves to the same tenant GUID. Only a
    GUID-verified candidate is returned, so a wrong name is never reported.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): The domain being resolved.
        brand (Optional[str]): FederationBrandName, if known.
        tenant_id (Optional[str]): The tenant GUID to match against.
        timeout (float): Request timeout in seconds.

    Returns:
        Optional[str]: The verified tenant name, or None if undetermined.
    """
    if not tenant_id:
        return None
    for candidate in _tenant_name_candidates(domain, brand):
        candidate_id = get_tenant_id(session, f"{candidate}.onmicrosoft.com", timeout)
        if candidate_id and candidate_id.lower() == tenant_id.lower():
            return candidate
    return None

def gather_tenant_domains(
    session: requests.Session,
    domain: str,
    tenant_id: Optional[str],
    timeout: float,
) -> List[str]:
    """Union of a tenant's domains from all available sources.

    Combines GetFederationInformation (mostly the queried domain now) with the
    ACS metadata endpoint queried by domain and, when known, by tenant GUID.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain to enumerate.
        tenant_id (Optional[str]): Tenant GUID, if known.
        timeout (float): Request timeout in seconds.

    Returns:
        List[str]: Sorted, de-duplicated tenant domains.
    """
    domains = set(get_tenant_domains(session, domain, timeout))
    domains.update(get_acs_domains(session, domain, timeout))
    if tenant_id:
        domains.update(get_acs_domains(session, tenant_id, timeout))
    return sorted(domains)

def determine_tenant_name(
    session: requests.Session,
    domain: str,
    brand: Optional[str],
    tenant_id: Optional[str],
    tenant_domains: List[str],
    timeout: float,
) -> Optional[str]:
    """Best-effort tenant name: from discovered domains, else GUID-verified guess.

    Args:
        session (requests.Session): Shared HTTP session.
        domain (str): Domain being resolved.
        brand (Optional[str]): FederationBrandName, if known.
        tenant_id (Optional[str]): Tenant GUID, if known.
        tenant_domains (List[str]): Domains already discovered for the tenant.
        timeout (float): Request timeout in seconds.

    Returns:
        Optional[str]: The tenant name, or None if undetermined.
    """
    return find_tenant_name(tenant_domains) or resolve_tenant_name(
        session, domain, brand, tenant_id, timeout
    )

def classify_auth_provider(namespace: str, auth_url: Optional[str]) -> str:
    """Classify the identity provider fronting a domain's authentication.

    Managed domains authenticate directly against Entra ID; Federated domains
    redirect to an external IdP whose AuthURL reveals the product.

    Args:
        namespace (str): NameSpaceType from getuserrealm (Managed/Federated/...).
        auth_url (Optional[str]): The federation AuthURL, if any.

    Returns:
        str: Friendly provider name (e.g. "Okta", "Microsoft ADFS",
            "Entra (managed)"), or an "Unknown IdP" hint with the host.
    """
    if namespace == "Managed":
        return "Entra (managed)"
    if namespace != "Federated" or not auth_url:
        return "Unknown"

    low = auth_url.lower()
    for name, patterns in IDP_PATTERNS:
        if any(pat in low for pat in patterns):
            return name

    host = re.sub(r"^https?://", "", auth_url).split("/")[0]
    return f"Federated (unknown IdP: {host})"

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
    auth_url = realm.get("AuthURL") or None

    tenant_id: Optional[str] = None
    tenant_name: Optional[str] = None
    if namespace in ("Managed", "Federated"):
        tenant_id = get_tenant_id(session, domain, timeout)
        if tenant_id is not None:
            if tenant_id not in tenant_name_cache:
                tenant_domains = gather_tenant_domains(session, domain, tenant_id, timeout)
                tenant_name_cache[tenant_id] = determine_tenant_name(
                    session, domain, realm.get("FederationBrandName"),
                    tenant_id, tenant_domains, timeout,
                )
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
        "auth_provider": classify_auth_provider(namespace, auth_url),
        "auth_url": auth_url,
    }

# -----------------------------
# MFA Testing (active, authorized use only)
# -----------------------------
def classify_ropc_result(status_code: int, body: Dict) -> Dict[str, Optional[str]]:
    """Interpret a ROPC token response into an MFA-relevant outcome.

    Args:
        status_code (int): HTTP status code of the token response.
        body (Dict): Parsed JSON body (may be empty).

    Returns:
        Dict[str, Optional[str]]: {result, aadsts, detail}.
    """
    if body.get("access_token"):
        return {
            "result": "NO_MFA",
            "aadsts": None,
            "detail": "token issued with password alone (no MFA on this endpoint)",
        }

    desc = body.get("error_description", "") or ""
    match = AADSTS_RE.search(desc)
    code = match.group(0) if match else None
    first_line = desc.splitlines()[0] if desc else (body.get("error") or "")

    if code in MFA_ENFORCED_CODES:
        return {"result": "MFA_ENFORCED", "aadsts": code, "detail": MFA_ENFORCED_CODES[code]}
    if code in VALID_OTHER_CODES:
        return {"result": "VALID_NO_TOKEN", "aadsts": code, "detail": VALID_OTHER_CODES[code]}
    if code in LOCKED_CODES:
        return {"result": "LOCKED", "aadsts": code, "detail": LOCKED_CODES[code]}
    if code in DISABLED_CODES:
        return {"result": "DISABLED", "aadsts": code, "detail": DISABLED_CODES[code]}
    if code in INVALID_CODES:
        return {"result": "INVALID_CREDS", "aadsts": code, "detail": INVALID_CODES[code]}
    if code in NOTFOUND_CODES:
        return {"result": "NOT_FOUND", "aadsts": code, "detail": NOTFOUND_CODES[code]}
    return {"result": "UNKNOWN", "aadsts": code, "detail": first_line[:160]}

def summarize_mfa(results: List[Dict]) -> str:
    """Produce a one-line assessment from per-endpoint MFA results.

    Args:
        results (List[Dict]): Per-endpoint classification results.

    Returns:
        str: Human-readable assessment.
    """
    if any(r["result"] == "LOCKED" for r in results):
        return "Account lockout encountered - results incomplete; stop testing this account."

    no_mfa = [r for r in results if r["result"] == "NO_MFA"]
    enforced = [r for r in results if r["result"] == "MFA_ENFORCED"]
    valid = no_mfa + enforced + [r for r in results if r["result"] == "VALID_NO_TOKEN"]

    if not valid:
        if any(r["result"] == "INVALID_CREDS" for r in results):
            return "Credentials rejected - cannot assess MFA (verify username/password)."
        if any(r["result"] == "DISABLED" for r in results):
            return "Account is disabled - cannot assess MFA."
        return "No conclusive result (user/tenant not found or endpoint errors)."

    if no_mfa and enforced:
        eps = ", ".join(r["endpoint"] for r in no_mfa)
        return f"INCONSISTENT: MFA enforced on some endpoints but NOT on: {eps} (possible bypass)."
    if no_mfa:
        eps = ", ".join(r["endpoint"] for r in no_mfa)
        return f"NO MFA on tested endpoint(s): {eps} - password-only sign-in succeeded."
    return "MFA enforced on all tested endpoints (password alone was insufficient)."

def mfa_test(session: requests.Session, username: str, password: str, timeout: float) -> Dict:
    """Probe MFA enforcement for one account across several ROPC clients.

    Tests a SINGLE account (this is not a password sprayer) and halts on smart
    lockout. Only run against tenants/accounts you are authorized to test.

    Args:
        session (requests.Session): Shared HTTP session.
        username (str): UPN to authenticate as.
        password (str): Password for the account.
        timeout (float): Request timeout in seconds.

    Returns:
        Dict: {username, endpoints: [...], summary}.
    """
    results: List[Dict] = []
    halted = False

    for label, client_id, resource in ROPC_CLIENTS:
        if halted:
            results.append({
                "endpoint": label, "client_id": client_id,
                "result": "SKIPPED", "aadsts": None,
                "detail": "skipped after lockout",
            })
            continue

        data = {
            "grant_type": "password",
            "resource": resource,
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid",
        }
        logging.info(f"MFA test: {label} ...")
        try:
            resp = session.post(TOKEN_URL, data=data, timeout=timeout)
        except requests.RequestException as exc:
            results.append({
                "endpoint": label, "client_id": client_id,
                "result": "ERROR", "aadsts": None, "detail": str(exc),
            })
            continue

        try:
            body = resp.json()
        except ValueError:
            body = {}

        outcome = classify_ropc_result(resp.status_code, body)
        outcome["endpoint"] = label
        outcome["client_id"] = client_id
        results.append(outcome)

        if outcome["result"] == "LOCKED":
            logging.error("Smart lockout detected; halting further MFA attempts.")
            halted = True

    return {
        "mode": "ropc",
        "username": username,
        "endpoints": results,
        "summary": summarize_mfa(results),
    }

def get_credential_type(session: requests.Session, username: str, timeout: float) -> Dict:
    """Query the unauthenticated GetCredentialType endpoint for an account.

    Args:
        session (requests.Session): Shared HTTP session.
        username (str): UPN to look up.
        timeout (float): Request timeout in seconds.

    Returns:
        Dict: Parsed response (possibly empty on error).
    """
    try:
        resp = session.post(CREDTYPE_URL, json={"Username": username}, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        logging.error(f"GetCredentialType failed for {username}: {exc}")
    except ValueError as exc:
        logging.error(f"GetCredentialType returned invalid JSON for {username}: {exc}")
    return {}

def credential_probe(session: requests.Session, username: str, timeout: float) -> Dict:
    """Best-effort, no-password account/auth probe via GetCredentialType.

    Reveals account existence, the federated IdP, Seamless SSO, and whether
    password auth is offered - without submitting a password. MFA enforcement
    is NOT determinable this way.

    Args:
        session (requests.Session): Shared HTTP session.
        username (str): UPN to probe.
        timeout (float): Request timeout in seconds.

    Returns:
        Dict: Probe result (mode "credential-probe").
    """
    data = get_credential_type(session, username, timeout)
    creds = data.get("Credentials") or {}
    ests = data.get("EstsProperties") or {}

    domain = username.split("@")[-1] if "@" in username else ""
    realm = get_userrealm(session, domain, timeout) if domain else {}
    namespace = realm.get("NameSpaceType", "Unknown")
    auth_url = creds.get("FederationRedirectUrl") or realm.get("AuthURL") or None

    # IfExistsResult: 0/6 exist, 1 does not, 5 exists under a different IdP.
    ife = data.get("IfExistsResult")
    exists_map = {
        0: "exists",
        1: "does not exist",
        5: "exists (different identity provider)",
        6: "exists",
    }
    account_exists = exists_map.get(ife, f"unknown ({ife})")
    throttled = bool(data.get("ThrottleStatus"))

    result = {
        "mode": "credential-probe",
        "username": username,
        "account_exists": account_exists,
        "if_exists_result": ife,
        "namespace_type": namespace,
        "auth_provider": classify_auth_provider(namespace, auth_url),
        "has_password": creds.get("HasPassword"),
        "desktop_sso": ests.get("DesktopSsoEnabled"),
        "throttled": throttled,
        "note": "MFA enforcement cannot be determined without a valid password.",
    }

    if not data:
        result["summary"] = "GetCredentialType returned nothing - inconclusive."
    elif throttled:
        result["summary"] = "Account existence is throttled/obfuscated by Microsoft - inconclusive."
    else:
        result["summary"] = (
            f"Account {account_exists}; auth via {result['auth_provider']}. "
            "Provide -p/--prompt-password to test MFA enforcement."
        )
    return result

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
    print(f"Auth provider  : {primary.get('auth_provider') or '<unknown>'}", file=out_stream)
    print(f"Tenant domains : {len(primary['tenant_domains'])} discovered", file=out_stream)
    print("=" * 70, file=out_stream)
    print(file=out_stream)
    for rec in records:
        print(f"[{rec['domain']}]", file=out_stream)
        print(f"    company        : {rec['company'] or '<unknown>'}", file=out_stream)
        print(f"    namespace_type : {rec['namespace_type']}", file=out_stream)
        print(f"    auth_provider  : {rec.get('auth_provider') or '<unknown>'}", file=out_stream)
        print(f"    tenant_id      : {rec['tenant_id'] or '<none>'}", file=out_stream)
        print(f"    tenant_name    : {rec['tenant_name'] or '<none>'}", file=out_stream)
        print(f"    cloud_instance : {rec['cloud_instance'] or '<none>'}", file=out_stream)

def output_mfa_text(mfa: Dict, out_stream) -> None:
    """Display MFA / auth-assessment results in readable text.

    Handles all three best-effort modes: full ROPC sign-in test, no-password
    credential probe, and domain-only posture.

    Args:
        mfa (Dict): Result from run()'s MFA assessment.
        out_stream: File-like object to write to.
    """
    mode = mfa.get("mode")
    print(file=out_stream)
    print("=" * 70, file=out_stream)

    if mode == "domain-only":
        print("MFA / auth test: domain-level only", file=out_stream)
        print("=" * 70, file=out_stream)
        print(mfa.get("note", ""), file=out_stream)
        return

    if mode == "credential-probe":
        print(f"Account probe  : {mfa['username']} (no password)", file=out_stream)
        print("=" * 70, file=out_stream)
        print(f"    account_exists : {mfa['account_exists']}", file=out_stream)
        print(f"    auth_provider  : {mfa['auth_provider']}", file=out_stream)
        print(f"    namespace_type : {mfa['namespace_type']}", file=out_stream)
        print(f"    has_password   : {mfa['has_password']}", file=out_stream)
        print(f"    desktop_sso    : {mfa['desktop_sso']}", file=out_stream)
        print(f"    throttled      : {mfa['throttled']}", file=out_stream)
        print(f"\nAssessment: {mfa['summary']}", file=out_stream)
        print(f"Note: {mfa['note']}", file=out_stream)
        return

    # mode == "ropc"
    print(f"MFA test       : {mfa['username']}", file=out_stream)
    print("=" * 70, file=out_stream)
    for ep in mfa["endpoints"]:
        print(f"[{ep['endpoint']}]", file=out_stream)
        print(f"    result : {ep['result']}", file=out_stream)
        print(f"    aadsts : {ep.get('aadsts') or '<none>'}", file=out_stream)
        print(f"    detail : {ep.get('detail') or ''}", file=out_stream)
    print(f"\nAssessment: {mfa['summary']}", file=out_stream)

def output_json(primary: Dict, records: List[Dict], out_stream, mfa: Optional[Dict] = None) -> None:
    """Write results as JSON.

    Args:
        primary (Dict): Primary tenant summary.
        records (List[Dict]): Per-domain company records.
        out_stream: File-like object to write to.
        mfa (Optional[Dict]): MFA-test result to include, if any.
    """
    payload = {"tenant": primary, "domains": records}
    if mfa is not None:
        payload["mfa_test"] = mfa
    json.dump(payload, out_stream, indent=2)
    out_stream.write("\n")

def output_csv(records: List[Dict], out_stream) -> None:
    """Write per-domain records as CSV.

    Args:
        records (List[Dict]): Per-domain company records.
        out_stream: File-like object to write to.
    """
    fields = [
        "domain", "company", "namespace_type", "auth_provider",
        "tenant_id", "tenant_name", "cloud_instance", "auth_url",
    ]
    writer = csv.DictWriter(out_stream, fieldnames=fields)
    writer.writeheader()
    for rec in records:
        writer.writerow({key: rec.get(key, "") for key in fields})

# -----------------------------
# Core Orchestration
# -----------------------------
def run(args: argparse.Namespace) -> Tuple[Dict, List[Dict], Optional[Dict]]:
    """Execute the full enumeration workflow.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        Tuple[Dict, List[Dict], Optional[Dict]]:
            (primary_summary, per_domain_records, mfa_result_or_None).
    """
    session = requests.Session()
    tenant_name_cache: Dict[str, Optional[str]] = {}

    primary = args.domain.lower()
    logging.info(f"Resolving {primary} against Azure AD ...")

    # Fetch the primary domain's details once and reuse them for both the
    # summary and its per-domain record, avoiding duplicate HTTP lookups.
    primary_realm = get_userrealm(session, primary, args.timeout)
    primary_tenant_id = get_tenant_id(session, primary, args.timeout)
    tenant_domains = gather_tenant_domains(session, primary, primary_tenant_id, args.timeout)
    tenant_name = determine_tenant_name(
        session, primary, primary_realm.get("FederationBrandName"),
        primary_tenant_id, tenant_domains, args.timeout,
    )
    if primary_tenant_id is not None:
        tenant_name_cache[primary_tenant_id] = tenant_name

    primary_namespace = primary_realm.get("NameSpaceType", "Unknown")
    primary_auth_url = primary_realm.get("AuthURL") or None
    primary_company = primary_realm.get("FederationBrandName") or tenant_name
    primary_provider = classify_auth_provider(primary_namespace, primary_auth_url)
    primary_record = {
        "domain": primary,
        "company": primary_company,
        "namespace_type": primary_namespace,
        "tenant_id": primary_tenant_id,
        "tenant_name": tenant_name,
        "cloud_instance": primary_realm.get("CloudInstanceName") or None,
        "auth_provider": primary_provider,
        "auth_url": primary_auth_url,
    }
    primary_summary = {
        "domain": primary,
        "tenant_name": tenant_name,
        "tenant_id": primary_tenant_id,
        "company": primary_company,
        "namespace_type": primary_namespace,
        "auth_provider": primary_provider,
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

    mfa_result: Optional[Dict] = None
    if args.mfa_test:
        if args.username and args.password:
            logging.warning(
                "ACTIVE MFA TEST: authenticating as %s against live Microsoft "
                "endpoints. Authorized use only; attempts may trigger alerts or "
                "smart lockout.", args.username,
            )
            mfa_result = mfa_test(session, args.username, args.password, args.timeout)
        elif args.username:
            logging.info(
                "No password provided; running no-password account probe "
                "(GetCredentialType) for %s.", args.username,
            )
            mfa_result = credential_probe(session, args.username, args.timeout)
        else:
            mfa_result = {
                "mode": "domain-only",
                "note": "Per-account MFA/auth checks require -u USERNAME (and "
                        "-p/--prompt-password for the sign-in test). See "
                        "auth_provider in the tenant summary above.",
            }

    return primary_summary, records, mfa_result

# -----------------------------
# Main Entry Point
# -----------------------------
def emit(fmt: str, primary: Dict, records: List[Dict],
         mfa: Optional[Dict], out_stream) -> None:
    """Write results in the requested format to a stream.

    Args:
        fmt (str): One of "text", "json", "csv".
        primary (Dict): Primary tenant summary.
        records (List[Dict]): Per-domain company records.
        mfa (Optional[Dict]): MFA-test result, if any.
        out_stream: File-like object to write to.
    """
    if fmt == "json":
        output_json(primary, records, out_stream, mfa)
    elif fmt == "csv":
        output_csv(records, out_stream)
        if mfa is not None:
            logging.warning("MFA results are not included in CSV output; use -F json or text.")
    else:
        output_text(primary, records, out_stream)
        if mfa is not None:
            output_mfa_text(mfa, out_stream)

def main() -> None:
    """Main execution flow."""
    try:
        args = parse_args()
        primary_summary, records, mfa_result = run(args)

        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                emit(args.fmt, primary_summary, records, mfa_result, handle)
        else:
            emit(args.fmt, primary_summary, records, mfa_result, sys.stdout)

    except KeyboardInterrupt:
        logging.error("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logging.exception(f"Fatal error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
