"""Authentication log analysis utilities.

This module parses authentication logs (e.g., SSH logs) to identify login
behaviour patterns and flag potentially suspicious activity. It focuses on
detecting logins occurring outside typical working hours and summarising
failed versus successful attempts per user or IP address. It can be extended
to support different log formats by adjusting the regular expressions.
"""

from __future__ import annotations

import datetime
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple


def analyse_auth_log(log_path: Path, working_hours: Tuple[int, int] = (8, 18)) -> Dict[str, Dict[str, int]]:
    """Analyse an authentication log file for suspicious login times.

    Args:
        log_path: Path to the log file (e.g., /var/log/auth.log).
        working_hours: Tuple of (start_hour, end_hour) defining normal working
            hours in 24‑hour format. Logins outside this range are considered
            unusual.

    Returns:
        A dictionary with keys 'unusual_logins' and 'failed_logins'. The
        'unusual_logins' value is a dictionary mapping user/IP identifiers
        (depending on the log format) to counts of logins outside working hours.
        The 'failed_logins' value is a dictionary mapping IPs to counts of
        failed authentication attempts.
    """
    # Patterns for parsing SSH logs
    # Example line for successful login:
    # "Feb  1 13:45:02 host sshd[123]: Accepted password for user from 192.168.1.1 port 22"
    success_pattern = re.compile(
        r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*sshd\[\d+\]:\s+Accepted .* for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    )
    # Example line for failed login:
    # "Feb  1 13:45:02 host sshd[123]: Failed password for invalid user test from 192.168.1.1 port 22"
    failed_pattern = re.compile(
        r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    )
    unusual_logins: Dict[str, int] = defaultdict(int)
    failed_logins: Dict[str, int] = defaultdict(int)
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # Check for failed logins
                fm = failed_pattern.search(line)
                if fm:
                    ip = fm.group(1)
                    failed_logins[ip] += 1
                    continue
                # Check for successful logins
                sm = success_pattern.search(line)
                if sm:
                    timestamp_str, user, ip = sm.groups()
                    # Parse timestamp: assume current year
                    try:
                        timestamp = datetime.datetime.strptime(
                            f"{timestamp_str} {datetime.datetime.now().year}", "%b %d %H:%M:%S %Y"
                        )
                        hour = timestamp.hour
                        start, end = working_hours
                        if hour < start or hour > end:
                            key = f"{user}@{ip}"
                            unusual_logins[key] += 1
                    except Exception:
                        continue
    except Exception:
        return {"unusual_logins": {}, "failed_logins": {}}
    return {"unusual_logins": dict(unusual_logins), "failed_logins": dict(failed_logins)}


__all__ = ["analyse_auth_log"]