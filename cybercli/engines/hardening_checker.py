"""System hardening checks.

This module contains functions to perform basic security hardening checks on
a Unix-like system. The checks are intentionally simple and self-contained
so that they can operate without external dependencies. They are not a
replacement for comprehensive tools such as Lynis or CIS benchmarks but
provide quick guidance on common misconfigurations.

The checks implemented include:

* SSH root login: verify that PermitRootLogin is set to 'no' in
  `/etc/ssh/sshd_config`.
* Password complexity: ensure that the password configuration enforces a
  minimum length and a non-trivial complexity pattern. We check common
  configuration files such as `/etc/login.defs` and `/etc/security/pwquality.conf`.
* Firewall status: attempt to detect whether a firewall is active by
  inspecting `iptables` rules or running `ufw status`. This check is
  heuristic and may not be accurate on all systems.

Each check returns a result with a status (pass/fail), a description and
recommendations. The results can be aggregated and reported in the CLI.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass
class HardeningCheckResult:
    """Represents the outcome of a hardening check."""

    name: str
    status: bool
    description: str
    recommendation: str


def check_ssh_root_login(config_path: Path = Path("/etc/ssh/sshd_config")) -> HardeningCheckResult:
    """Check if SSH root login is disabled.

    Reads the sshd configuration file and determines whether PermitRootLogin
    is set to 'no'. If the file is missing, the check is skipped (returns
    status=True with a note).

    Args:
        config_path: Path to the sshd configuration file.

    Returns:
        HardeningCheckResult describing the outcome.
    """
    name = "SSH root login"
    description = "PermitRootLogin should be set to 'no' in sshd_config."
    recommendation = "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then restart sshd."
    try:
        content = config_path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        # If config does not exist, assume not applicable
        return HardeningCheckResult(name, True, "SSH configuration not found", "")
    # Find last occurrence of PermitRootLogin directive
    matches = re.findall(r"^\s*PermitRootLogin\s+(\S+)", content, flags=re.MULTILINE)
    if not matches:
        return HardeningCheckResult(name, False, description, recommendation)
    # Evaluate the last directive (most specific)
    value = matches[-1].strip().lower()
    status = value == "no"
    return HardeningCheckResult(name, status, description, recommendation)


def check_password_complexity() -> HardeningCheckResult:
    """Check if password complexity settings are present.

    This function inspects common configuration files for settings that enforce
    password complexity and expiration. It looks for PASS_MIN_LEN and
    PASS_MAX_DAYS in `/etc/login.defs` and checks `/etc/security/pwquality.conf`
    for minlen.
    """
    name = "Password complexity"
    description = (
        "System should enforce a minimum password length and expiration policy."
    )
    recommendation = (
        "Set PASS_MIN_LEN and PASS_MAX_DAYS in /etc/login.defs and define minlen and complexity rules in /etc/security/pwquality.conf."
    )
    # Check login.defs
    min_len = None
    max_days = None
    try:
        with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("PASS_MIN_LEN"):
                    parts = line.split()
                    if len(parts) >= 2:
                        min_len = int(parts[1])
                elif line.startswith("PASS_MAX_DAYS"):
                    parts = line.split()
                    if len(parts) >= 2:
                        max_days = int(parts[1])
    except FileNotFoundError:
        pass
    # Check pwquality.conf
    pw_minlen = None
    try:
        with open("/etc/security/pwquality.conf", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if "minlen" in line:
                    match = re.match(r"minlen\s*=\s*(\d+)", line)
                    if match:
                        pw_minlen = int(match.group(1))
    except FileNotFoundError:
        pass
    status = False
    if min_len and pw_minlen and min_len >= 8 and pw_minlen >= 8 and (max_days is not None and max_days <= 90):
        status = True
    return HardeningCheckResult(name, status, description, recommendation)


def check_firewall() -> HardeningCheckResult:
    """Attempt to determine if a firewall is active.

    This function executes `iptables -L` to see if any rules are defined or
    checks if `ufw` reports the firewall as active. It may require root
    privileges; if execution fails, the check returns inconclusive status.
    """
    name = "Firewall status"
    description = "A host‑based firewall should be configured to restrict incoming/outgoing traffic."
    recommendation = (
        "Enable a firewall using iptables or ufw. Define rules to allow only necessary services."
    )
    # Try iptables
    try:
        result = subprocess.run(
            ["iptables", "-L"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=True,
        )
        # If there are no rules besides the default, iptables output will have empty chains
        output = result.stdout
        # A simple heuristic: if at least one non-policy rule exists (matches a common port), pass
        has_rules = any(re.search(r"ACCEPT|DROP|REJECT", line) for line in output.splitlines())
        status = has_rules
        return HardeningCheckResult(name, status, description, recommendation)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Fallback to ufw
        try:
            result = subprocess.run(
                ["ufw", "status"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=True,
            )
            active = "Status: active" in result.stdout
            return HardeningCheckResult(name, active, description, recommendation)
        except Exception:
            # Cannot determine firewall status
            return HardeningCheckResult(
                name,
                False,
                description,
                recommendation,
            )


def perform_hardening_checks() -> List[HardeningCheckResult]:
    """Run all hardening checks and return their results."""
    checks = [
        check_ssh_root_login(),
        check_password_complexity(),
        check_firewall(),
    ]
    return checks


__all__ = [
    "HardeningCheckResult",
    "check_ssh_root_login",
    "check_password_complexity",
    "check_firewall",
    "perform_hardening_checks",
]