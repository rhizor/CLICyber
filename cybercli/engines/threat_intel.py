"""Threat intelligence integration helpers.

This module provides simple wrappers around several public threat intelligence
APIs.  The goal is to centralise indicator lookups so that the CLI can
query IP addresses, domains, file hashes and CVE identifiers and present
aggregated results to the user.  Network access is required for these
functions to succeed; if the necessary API keys are not configured via
environment variables, the functions will return a helpful message.

Supported services:

* Shodan: host information and open ports (IP addresses).
* AbuseIPDB: reputation score and abuse reports (IP addresses).
* VirusTotal: file or URL reputation (hashes or URLs).
* NVD (NIST National Vulnerability Database): CVE details.

The environment variables expected are:

* ``SHODAN_API_KEY`` – API key for the Shodan REST API.
* ``ABUSEIPDB_API_KEY`` – API key for the AbuseIPDB v2 API.
* ``VT_API_KEY`` – API key for VirusTotal v3 API.
* ``NVD_API_KEY`` – API key for the NVD API (optional but recommended).

If a key is missing the corresponding lookup function will return
``{"error": "API key not configured"}``.
"""

from __future__ import annotations

import os
import requests
from typing import Any, Dict, Optional


def _get_api_key(env_name: str) -> Optional[str]:
    """Helper to retrieve an API key from the environment.

    Args:
        env_name: Name of the environment variable.

    Returns:
        The key string if set, otherwise ``None``.
    """
    return os.environ.get(env_name)


def lookup_ip_shodan(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Lookup an IP address on Shodan.

    Args:
        ip: IP address to query.
        api_key: Shodan API key. If omitted, the ``SHODAN_API_KEY`` environment
            variable is used.

    Returns:
        A dictionary containing Shodan host information or an error message.
    """
    key = api_key or _get_api_key("SHODAN_API_KEY")
    if not key:
        return {"error": "SHODAN_API_KEY not configured"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}


def lookup_ip_abuseipdb(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Lookup an IP address on AbuseIPDB.

    Args:
        ip: IP address to query.
        api_key: AbuseIPDB API key. If omitted, the ``ABUSEIPDB_API_KEY``
            environment variable is used.

    Returns:
        A dictionary with abuse report data or an error message.
    """
    key = api_key or _get_api_key("ABUSEIPDB_API_KEY")
    if not key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception as exc:
        return {"error": str(exc)}


def lookup_hash_virustotal(indicator: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Lookup a file hash or URL on VirusTotal.

    Args:
        indicator: The file hash (MD5/SHA1/SHA256) or URL to query.
        api_key: VirusTotal API key. If omitted, the ``VT_API_KEY`` environment
            variable is used.

    Returns:
        A dictionary with analysis results or an error message.
    """
    key = api_key or _get_api_key("VT_API_KEY")
    if not key:
        return {"error": "VT_API_KEY not configured"}
    # Determine whether we are dealing with a hash or a URL
    # Simple heuristic: URLs contain ``://``
    endpoint = "files" if "://" not in indicator else "urls"
    # For URLs, VT requires a base64 encoded (without padding) slug of the URL
    if endpoint == "urls" and indicator:
        import base64
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        resource = url_id
    else:
        resource = indicator
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{resource}"
    headers = {"x-apikey": key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}


def lookup_cve(cve_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Lookup CVE details on the NVD API.

    Args:
        cve_id: The CVE identifier (e.g. ``CVE-2022-12345``).
        api_key: NVD API key. If omitted, the ``NVD_API_KEY`` environment
            variable is used. The NVD API allows unauthenticated access with
            rate limiting, but providing a key increases the quota.

    Returns:
        A dictionary with CVE information or an error message.
    """
    key = api_key or _get_api_key("NVD_API_KEY")
    params = {"cveId": cve_id}
    if key:
        params["apiKey"] = key
    url = "https://services.nvd.nist.gov/rest/json/cve/2.0"
    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # NVD returns lists under 'vulnerabilities'
        vulns = data.get("vulnerabilities", [])
        return vulns[0] if vulns else {}
    except Exception as exc:
        return {"error": str(exc)}


def aggregate_intel(indicator: str) -> Dict[str, Any]:
    """Aggregate threat intelligence for a given indicator.

    If the indicator looks like an IP address it will query IP-based services
    (Shodan and AbuseIPDB).  If it contains a ``://`` it will be treated as a
    URL and sent to VirusTotal.  Otherwise it is assumed to be a file hash and
    will also be sent to VirusTotal.  Users can still call individual lookup
    functions directly if they prefer.

    Args:
        indicator: An IP address, domain, URL or file hash.

    Returns:
        A dictionary combining the results from available lookups.
    """
    result: Dict[str, Any] = {}
    # Rough IP check: digits and dots only
    if all(ch.isdigit() or ch == '.' for ch in indicator):
        result["shodan"] = lookup_ip_shodan(indicator)
        result["abuseipdb"] = lookup_ip_abuseipdb(indicator)
    elif "://" in indicator:
        result["virustotal"] = lookup_hash_virustotal(indicator)
    else:
        result["virustotal"] = lookup_hash_virustotal(indicator)
    # If indicator looks like CVE
    if indicator.lower().startswith("cve-"):
        result["nvd"] = lookup_cve(indicator)
    return result


__all__ = [
    "lookup_ip_shodan",
    "lookup_ip_abuseipdb",
    "lookup_hash_virustotal",
    "lookup_cve",
    "aggregate_intel",
]