"""
SIEM-Lite — Alerting Module
Dispatches ThreatAlerts via Slack webhook, SMTP email, and/or a generic
HTTP webhook. Configure through environment variables.
"""

import json
import logging
import os
import smtplib
import urllib.request
from email.message import EmailMessage
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.engine import ThreatAlert

log = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "info":     "🔵",
    "low":      "🟡",
    "medium":   "🟠",
    "high":     "🔴",
    "critical": "🚨",
}


# ─── Individual alerters ──────────────────────────────────────────────────────

class SlackAlerter:
    """Posts a formatted message to a Slack Incoming Webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: "ThreatAlert") -> None:
        emoji = SEVERITY_EMOJI.get(alert.severity, "⚪")
        payload = {
            "text": f"{emoji} *{alert.title}* [{alert.severity.upper()}]",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text",
                             "text": f"{emoji} {alert.title}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.upper()}"},
                        {"type": "mrkdwn", "text": f"*Rule:*\n{alert.rule_id}"},
                        {"type": "mrkdwn", "text": f"*MITRE Tactic:*\n{alert.mitre_tactic}"},
                        {"type": "mrkdwn", "text": f"*Technique:*\n{alert.mitre_technique}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn",
                             "text": f"*Description:*\n{alert.description}"},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn",
                         "text": f"🕐 {alert.timestamp}  |  context: `{json.dumps(alert.context)}`"},
                    ],
                },
            ],
        }
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            self.webhook_url, data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.info("Slack alert sent (%s)", resp.status)
        except Exception as exc:
            log.error("Slack alert failed: %s", exc)


class EmailAlerter:
    """Sends an alert email via SMTP (supports TLS on port 587)."""

    def __init__(self, smtp_host: str, smtp_port: int,
                 username: str, password: str,
                 from_addr: str, to_addrs: list[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username  = username
        self.password  = password
        self.from_addr = from_addr
        self.to_addrs  = to_addrs

    def send(self, alert: "ThreatAlert") -> None:
        emoji = SEVERITY_EMOJI.get(alert.severity, "")
        msg   = EmailMessage()
        msg["Subject"] = f"[SIEM-Lite] {emoji} {alert.severity.upper()} — {alert.title}"
        msg["From"]    = self.from_addr
        msg["To"]      = ", ".join(self.to_addrs)
        msg.set_content(f"""
SIEM-Lite Threat Alert
══════════════════════════════════════════════

Rule ID   : {alert.rule_id}
Title     : {alert.title}
Severity  : {alert.severity.upper()}
Timestamp : {alert.timestamp}

MITRE ATT&CK
  Tactic    : {alert.mitre_tactic}
  Technique : {alert.mitre_technique}

Description
  {alert.description}

Context
  {json.dumps(alert.context, indent=2)}

Raw Event
  {alert.event.get("raw", "(none)")}

──────────────────────────────────────────────
SIEM-Lite — automated security event platform
""")
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            log.info("Email alert sent to %s", self.to_addrs)
        except Exception as exc:
            log.error("Email alert failed: %s", exc)


class WebhookAlerter:
    """POSTs alert JSON to any generic HTTP endpoint (e.g. PagerDuty, custom API)."""

    def __init__(self, url: str, headers: dict | None = None):
        self.url     = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def send(self, alert: "ThreatAlert") -> None:
        data = json.dumps(alert.to_dict()).encode()
        req  = urllib.request.Request(self.url, data=data, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.info("Webhook alert sent (%s)", resp.status)
        except Exception as exc:
            log.error("Webhook alert failed: %s", exc)


# ─── Alert dispatcher ─────────────────────────────────────────────────────────

class AlertDispatcher:
    """
    Builds alerters from environment variables and fans out
    every ThreatAlert to all configured channels.
    """

    def __init__(self):
        self._alerters = []
        self._setup()

    def _setup(self) -> None:
        # Slack
        slack_url = os.getenv("SLACK_WEBHOOK_URL")
        if slack_url:
            self._alerters.append(SlackAlerter(slack_url))
            log.info("Slack alerter enabled")

        # Email
        smtp_host = os.getenv("SMTP_HOST")
        if smtp_host:
            self._alerters.append(EmailAlerter(
                smtp_host=smtp_host,
                smtp_port=int(os.getenv("SMTP_PORT", "587")),
                username=os.getenv("SMTP_USER", ""),
                password=os.getenv("SMTP_PASS", ""),
                from_addr=os.getenv("SMTP_FROM", "siem@localhost"),
                to_addrs=os.getenv("ALERT_EMAIL", "").split(","),
            ))
            log.info("Email alerter enabled")

        # Generic webhook
        webhook_url = os.getenv("WEBHOOK_URL")
        if webhook_url:
            self._alerters.append(WebhookAlerter(webhook_url))
            log.info("Webhook alerter enabled")

        if not self._alerters:
            log.warning("No alerters configured — alerts will only appear in logs")

    def dispatch(self, alert: "ThreatAlert") -> None:
        log.warning(
            "THREAT | %s | %s | %s | %s",
            alert.severity.upper(), alert.rule_id,
            alert.title, alert.description,
        )
        for alerter in self._alerters:
            alerter.send(alert)
