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
import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Patterns of dangerous commands that should NEVER be executed
BLOCKED_PATTERNS = [
    r"rm\s+-rf", r"rm\s+-r\s+/", r"rm\s+-R", r"rm\s+-f\s+/",
    r"dd\s+if=", r"dd\s+of=", r">\s*/dev/", r"mkfs",
    r"chmod\s+777", r"chown\s+-R", r"chmod\s+-R\s+777",
    r"wget\s+.*\|", r"curl\s+.*\|", r"python.*\|",
    r";\s*rm", r"&&\s*rm", r"\|\s*rm", r";\s*fork",
    r"fork\(\)", r":\(\)\{", r"exec\s+exec",
    r"\>\s*/etc/", r"\>\s*/var/", r"\>\s*/root/",
    r"shutdown", r"reboot", r"init\s+0", r"init\s+6",
    r"kill\s+-9\s+1", r"killall",
    r"wget\s+http", r"curl\s+http.*>.*\.sh",
]


def _is_command_safe(cmd: str) -> bool:
    """Check if a command is safe to execute.
    
    Args:
        cmd: Command to validate.
        
    Returns:
        True if command is safe, False if dangerous patterns found.
    """
    cmd_lower = cmd.lower()
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            logger.warning(f"Blocked dangerous pattern: {pattern} in command: {cmd}")
            return False
    return True


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


def apply_remediation_step(step: str, simulate: bool = True) -> Optional[str]:
    """Apply a remediation step by executing shell commands when safe.

    Args:
        step: A remediation action produced by ``suggest_remediations``.
        simulate: If True, print the command instead of executing it.  If
            False, attempt to run the command using ``subprocess``.

    Returns:
        Error message if blocked, None if success.

    Note:
        Only very simple commands are supported.  Multi‑step procedures
        (editing files, updating multiple services) should be carried out
        manually or via a configuration management tool.  When simulate=True
        the function just prints the step to stdout.
        
    Security:
        Implements command blocklisting to prevent command injection attacks.
        Dangerous patterns like rm -rf, fork bombs, and file overwrites
        are blocked regardless of simulate mode.
    """
    # Always verify security, even in simulation mode
    if not _is_command_safe(step):
        error_msg = f"BLOCKED: Command contains dangerous pattern"
        print(f"❌ {error_msg}: {step}")
        logger.error(f"Blocked remediation attempt: {step}")
        return error_msg
    
    if simulate:
        print(f"[SIMULATION] {step}")
        return None
    
    # Execute commands safely
    commands = [cmd.strip() for cmd in step.split('&&')]
    
    for cmd in commands:
        if not _is_command_safe(cmd):
            print(f"❌ BLOCKED: Dangerous command: {cmd}")
            continue
            
        try:
            # Use timeout to prevent indefinite execution
            result = subprocess.run(
                cmd, 
                shell=True, 
                check=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            print(f"✓ Executed: {cmd}")
            if result.stdout:
                logger.info(f"Output: {result.stdout}")
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout executing: {cmd}")
            logger.warning(f"Command timeout: {cmd}")
        except subprocess.CalledProcessError as exc:
            print(f"⚠️ Failed to execute '{cmd}': {exc}")
            logger.warning(f"Command failed: {cmd} - {exc}")
        except Exception as exc:
            print(f"❌ Error executing '{cmd}': {exc}")
            logger.error(f"Command error: {cmd} - {exc}")
    
    return None


__all__ = ["suggest_remediations", "apply_remediation_step"]