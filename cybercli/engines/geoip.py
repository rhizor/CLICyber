"""GeoIP lookup utilities.

This module provides simple functions to look up geographical and ASN
information for IP addresses.  By default it queries the ``ipapi.co``
service over HTTPS without authentication.  Users may supply their own
service URL via the ``GEOIP_SERVICE_URL`` environment variable.  Note that
network access is required and rate limits may apply.
"""

from __future__ import annotations

import os
import requests
from typing import Any, Dict


def lookup_ip(ip: str) -> Dict[str, Any]:
    """Query a GeoIP service for information about an IP address.

    Args:
        ip: IPv4 or IPv6 address to look up.

    Returns:
        A dictionary containing location data or an error message.
    """
    base_url = os.environ.get("GEOIP_SERVICE_URL", "https://ipapi.co/{ip}/json/")
    try:
        url = base_url.format(ip=ip)
    except Exception:
        url = f"https://ipapi.co/{ip}/json/"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}


__all__ = ["lookup_ip"]