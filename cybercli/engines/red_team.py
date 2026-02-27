"""Modules for Red Team operations.

This module provides basic functionality to assist Red Team analysts in
exploiting vulnerabilities within controlled environments. The functions
here are deliberately constrained to avoid accidental misuse on production
systems. They focus on working with the CTF lab environments created by the
`ctf` commands and can be extended to integrate real exploitation frameworks
if run in an appropriate environment.

Currently implemented features:

* Exploit demonstration: iterate through lab challenge directories and
  attempt to read `flag.txt` files by simulating exploitation. This is a
  harmless example that demonstrates how a Red Team command might operate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List


def exploit_lab(lab_path: Path) -> Dict[str, str]:
    """Simulate exploitation of a CTF lab by reading flags.

    For each challenge in the given lab directory, this function attempts to
    read the `flag.txt` file. It returns a mapping of challenge names to
    discovered flags. This is a simple and safe example; real exploitation
    would involve running payloads or exploit scripts.

    Args:
        lab_path: Path to the lab directory created by the `ctf create`
            command.

    Returns:
        A dictionary mapping challenge directory names to the contents of
        `flag.txt` if found; missing or unreadable flags are represented as
        empty strings.
    """
    results: Dict[str, str] = {}
    if not lab_path.exists() or not lab_path.is_dir():
        return results
    for challenge_dir in lab_path.iterdir():
        if not challenge_dir.is_dir():
            continue
        flag_file = challenge_dir / "flag.txt"
        try:
            flag_contents = flag_file.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception:
            flag_contents = ""
        results[challenge_dir.name] = flag_contents
    return results


__all__ = ["exploit_lab"]