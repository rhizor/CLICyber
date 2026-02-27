"""
CyberAgent CLI package.

This package provides a command‑line interface (CLI) that mirrors the
functionality of the CyberAgent platform. It uses `typer` to create
user‑friendly commands and subcommands suitable for both junior and
senior security analysts. The CLI includes placeholders for network
scanning, threat intelligence queries, remediations, rollback, report
generation, ISO 27001 compliance checks, AI‑assisted analysis and
automated CTF lab provisioning.
"""

from .cli import app

__all__ = ["app"]