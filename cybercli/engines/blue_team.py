"""Modules for Blue Team operations.

This module implements basic vulnerability assessment and log analysis
capabilities suitable for a Blue Team analyst. The functions here are
intentionally lightweight and self-contained, without requiring external
dependency databases or tools. They serve as starting points for more
sophisticated integrations (e.g., linking to NVD feeds or SIEM APIs).

Functions:
    map_ports_to_vulnerabilities: Given a dictionary of open ports, return
        associated common weaknesses and recommended mitigations.
    analyse_log_file: Parse a log file and report statistics on failed
        login attempts and other suspicious patterns.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple


# A static mapping of ports to known vulnerabilities or concerns. This can be
# extended or replaced with data from the NVD or other vulnerability feeds.
PORT_VULN_MAP: Dict[int, List[str]] = {
    22: [
        "Ensure SSH uses strong encryption and disable password authentication.",
        "Rotate host keys regularly and enforce key-based login only.",
    ],
    80: [
        "HTTP traffic is unencrypted; enforce HTTPS with valid certificates.",
        "Regularly patch web server software to mitigate vulnerabilities.",
    ],
    443: [
        "Verify TLS configuration against best practices (no outdated ciphers).",
        "Implement HTTP security headers (HSTS, CSP) to mitigate web attacks.",
    ],
    3306: [
        "MySQL default settings may expose sensitive information; change defaults and restrict access.",
        "Ensure the database has a strong root password and uses encryption at rest.",
    ],
    5432: [
        "PostgreSQL should require authentication and restrict remote connections.",
        "Update PostgreSQL regularly to mitigate CVEs affecting database servers.",
    ],
    8080: [
        "If running a web server, ensure it is configured securely and patched.",
        "Avoid exposing management interfaces on 0.0.0.0; bind to localhost where appropriate.",
    ],
}


def map_ports_to_vulnerabilities(open_ports: Dict[str, Dict[int, str]]) -> Dict[str, List[str]]:
    """Generate vulnerability recommendations based on open ports.

    Args:
        open_ports: Mapping of host addresses to dictionaries of port numbers
            and their protocols (currently unused).

    Returns:
        A dictionary mapping host addresses to lists of vulnerability
        recommendations. Ports without explicit entries in the map will
        generate generic recommendations.
    """
    recommendations: Dict[str, List[str]] = {}
    for host, ports in open_ports.items():
        host_recs: List[str] = []
        for port in ports.keys():
            if port in PORT_VULN_MAP:
                host_recs.extend(PORT_VULN_MAP[port])
            else:
                host_recs.append(
                    f"Port {port} is open; verify the associated service is necessary, patched and securely configured."
                )
        recommendations[host] = host_recs
    return recommendations


def analyse_log_file(log_path: Path) -> Tuple[int, Dict[str, int]]:
    """Analyse a log file for failed login attempts.

    This function scans the specified log file for patterns indicating failed
    authentication attempts (e.g. SSH failures) and returns the total count
    along with a breakdown by source address.

    Args:
        log_path: Path to the log file.

    Returns:
        A tuple consisting of the total number of failed login attempts and
        a dictionary mapping source IPs to counts. If the file cannot be
        opened, returns zeros.
    """
    total = 0
    by_ip: Counter = Counter()
    # Regex to match typical SSH failed login lines, capturing the source IP
    pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    by_ip[ip] += 1
                    total += 1
    except Exception:
        return 0, {}
    return total, dict(by_ip)


__all__ = ["map_ports_to_vulnerabilities", "analyse_log_file"]