"""Threat hunting utilities.

This module provides functions to detect anomalies and calculate risk scores
based on historical scan data. It is designed to work with the history
records saved by the network scanning commands of the CLI. The goal is
to support proactive threat hunting by highlighting changes in the attack
surface and prioritising hosts with high‑risk services.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from .blue_team import PORT_VULN_MAP


def detect_port_anomalies(history: List[dict]) -> Dict[str, Dict[str, List[int]]]:
    """Detect changes in open ports for each host across scans.

    Given a list of history records (each with keys ``target`` and
    ``open_ports``), this function produces a dictionary mapping each host
    address to a dictionary with two lists: ``added`` and ``removed`` ports.

    Args:
        history: List of scan records, ordered chronologically.

    Returns:
        Dictionary of host -> {"added": [ports], "removed": [ports]}.
    """
    anomalies: Dict[str, Dict[str, List[int]]] = {}
    baseline_ports: Dict[str, set] = {}
    for record in history:
        host = record.get("target")
        ports = set(int(p) for p in record.get("open_ports", []))
        if host not in baseline_ports:
            # First occurrence establishes baseline; no anomalies on first scan
            baseline_ports[host] = ports
            anomalies[host] = {"added": [], "removed": []}
            continue
        prev_ports = baseline_ports[host]
        added = sorted(list(ports - prev_ports))
        removed = sorted(list(prev_ports - ports))
        anomalies[host] = {"added": added, "removed": removed}
        # Update baseline for next iteration
        baseline_ports[host] = ports
    return anomalies


def calculate_risk_scores(open_ports: Dict[str, List[int]]) -> Dict[str, float]:
    """Calculate a risk score per host based on open ports.

    Each open port contributes to the risk score. Ports with known
    vulnerabilities (as defined in PORT_VULN_MAP) contribute 1.0 point per
    recommendation; unknown ports contribute 0.5. Scores are summed per host.

    Args:
        open_ports: Mapping of host addresses to lists of open port numbers.

    Returns:
        Dictionary mapping host addresses to floating‑point risk scores.
    """
    scores: Dict[str, float] = {}
    for host, ports in open_ports.items():
        score = 0.0
        for port in ports:
            if port in PORT_VULN_MAP:
                # Each recommendation counts as 1.0 point
                score += len(PORT_VULN_MAP[port])
            else:
                score += 0.5
        scores[host] = score
    return scores


__all__ = ["detect_port_anomalies", "calculate_risk_scores"]