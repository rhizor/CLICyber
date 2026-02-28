"""Alerting utilities for CyberCLI.

This module implements simple mechanisms for sending alerts via email,
Slack and Telegram.  These functions are wrappers around standard
protocols/APIs and require the relevant environment variables to be set.

* Email alerts use SMTP credentials defined by ``SMTP_SERVER``,
  ``SMTP_PORT``, ``SMTP_USER`` and ``SMTP_PASSWORD``.  TLS is
  automatically enabled on ports 465 and 587.
* Slack alerts send a message to a Slack incoming webhook defined by
  ``SLACK_WEBHOOK_URL``.
* Telegram alerts send a message to a chat via the Bot API using
  ``TELEGRAM_TOKEN`` and ``TELEGRAM_CHAT_ID``.

If the required configuration is missing or a request fails, the
functions return a dictionary with an 'error' key describing the issue.
Otherwise they return a dictionary with a 'success' message.
"""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, Optional

import requests


def send_email_alert(
    to_address: str,
    subject: str,
    body: str,
    server: Optional[str] = None,
    port: Optional[int] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """Send an email alert via SMTP.

    Args:
        to_address: Recipient email address.
        subject: Email subject line.
        body: Email body (plain text).
        server: SMTP server hostname; falls back to ``SMTP_SERVER`` env.
        port: SMTP port; falls back to ``SMTP_PORT`` env (defaults to 587).
        user: SMTP username; falls back to ``SMTP_USER`` env.
        password: SMTP password; falls back to ``SMTP_PASSWORD`` env.

    Returns:
        A dictionary indicating success or containing an error message.
    """
    host = server or os.environ.get("SMTP_SERVER")
    port = int(port or os.environ.get("SMTP_PORT", 587))
    username = user or os.environ.get("SMTP_USER")
    pwd = password or os.environ.get("SMTP_PASSWORD")
    if not (host and username and pwd):
        return {"error": "SMTP credentials not fully configured"}
    msg = EmailMessage()
    msg["From"] = username
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        # Use SSL for port 465, starttls otherwise
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as smtp:
                smtp.login(username, pwd)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls()
                smtp.login(username, pwd)
                smtp.send_message(msg)
        return {"success": f"Email sent to {to_address}"}
    except Exception as exc:
        return {"error": str(exc)}


def send_slack_alert(message: str, webhook_url: Optional[str] = None) -> Dict[str, Any]:
    """Send an alert message to Slack via an incoming webhook.

    Args:
        message: Text of the Slack message.
        webhook_url: Slack webhook URL; falls back to ``SLACK_WEBHOOK_URL`` env.

    Returns:
        A dictionary indicating success or an error.
    """
    url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return {"error": "SLACK_WEBHOOK_URL not configured"}
    payload = {"text": message}
    try:
        # Verify SSL certificates by default for security
        resp = requests.post(url, json=payload, timeout=10, verify=True)
        resp.raise_for_status()
        return {"success": "Message sent to Slack"}
    except Exception as exc:
        return {"error": str(exc)}


def send_telegram_alert(message: str, token: Optional[str] = None, chat_id: Optional[str] = None) -> Dict[str, Any]:
    """Send an alert message via Telegram Bot API.

    Args:
        message: Text of the alert.
        token: Telegram bot token; falls back to ``TELEGRAM_TOKEN`` env.
        chat_id: Chat ID to send the message to; falls back to ``TELEGRAM_CHAT_ID`` env.

    Returns:
        A dictionary indicating success or an error.
    """
    token = token or os.environ.get("TELEGRAM_TOKEN")
    chat = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat):
        return {"error": "TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not configured"}
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat, "text": message}
    try:
        # Verify SSL certificates by default for security
        resp = requests.post(url, json=payload, timeout=10, verify=True)
        resp.raise_for_status()
        return {"success": "Message sent to Telegram"}
    except Exception as exc:
        return {"error": str(exc)}


__all__ = [
    "send_email_alert",
    "send_slack_alert",
    "send_telegram_alert",
]