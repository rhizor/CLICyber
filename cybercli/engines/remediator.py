"""Remediation engine for CyberCLI.

This module contains helper functions for mapping findings to remediation
actions and applying those actions.  The functions here are intentionally
conservative: they suggest configuration changes or system commands but do
not execute privileged operations automatically without explicit approval.
In a production deployment these actions might integrate with Ansible,
Puppet or other configuration management tools to apply changes across
multiple hosts.  Here we implement a small subset appropriate for local
machines.

The module exposes two primary functions:

* ``suggest_remediations`` – given a dictionary of vulnerability
  recommendations, produce high‑level remediation steps.
* ``apply_remediation_step`` – execute or simulate a single remediation
  step based on the type of recommendation.
"""

from __future__ import annotations

import subprocess
from typing import Dict, List


def suggest_remediations(vuln_recs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Derive remediation steps from vulnerability recommendations.

    Args:
        vuln_recs: Mapping of host -> list of recommendations produced by the
            Blue Team module.

    Returns:
        Mapping of host -> list of remediation actions (as human‑readable
        commands or guidance).
    """
    actions: Dict[str, List[str]] = {}
    for host, recs in vuln_recs.items():
        host_actions: List[str] = []
        for rec in recs:
            # Very simple keyword-based mapping.  This can be expanded to use
            # structured rule definitions.
            lower = rec.lower()
            if "ssh" in lower and "disable password" in lower:
                host_actions.append(
                    "Edit /etc/ssh/sshd_config: set 'PasswordAuthentication no' and 'PermitRootLogin no', then restart sshd"
                )
            elif "https" in lower or "http" in lower:
                host_actions.append(
                    "Configure TLS using a recognised CA certificate and redirect HTTP to HTTPS"
                )
            elif "database" in lower:
                host_actions.append(
                    "Set strong root passwords for your database, restrict remote connections and enable encryption at rest"
                )
            elif "firewall" in lower:
                host_actions.append(
                    "Add firewall rules via ufw or iptables to permit only necessary ports"
                )
            else:
                # Default: instruct manual review
                host_actions.append(f"Review service on {rec.split()[1]}: ensure patched and securely configured")
        actions[host] = host_actions
    return actions


def apply_remediation_step(step: str, simulate: bool = True) -> None:
    """Apply a remediation step by executing shell commands when safe.

    Args:
        step: A remediation action produced by ``suggest_remediations``.
        simulate: If True, print the command instead of executing it.  If
            False, attempt to run the command using ``subprocess``.

    Note:
        Only very simple commands are supported.  Multi‑step procedures
        (editing files, updating multiple services) should be carried out
        manually or via a configuration management tool.  When simulate=True
        the function just prints the step to stdout.
    """
    if simulate:
        print(f"[SIMULATION] {step}")
        return
    # For demonstration, attempt to run commands separated by '&&' one by one.
    commands = [cmd.strip() for cmd in step.split('&&')]
    for cmd in commands:
        try:
            subprocess.run(cmd, shell=True, check=True)
            print(f"Executed: {cmd}")
        except subprocess.CalledProcessError as exc:
            print(f"Failed to execute '{cmd}': {exc}")


__all__ = ["suggest_remediations", "apply_remediation_step"]