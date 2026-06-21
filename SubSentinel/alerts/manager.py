"""
alerts/manager.py - Real-time alerting system for findings
"""

import asyncio
import json
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, List

import aiohttp

from core.config import ScanConfig
from core.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_THRESHOLD = {
    "info": 0,
    "low": 20,
    "medium": 40,
    "high": 65,
    "critical": 85,
}


class AlertManager:
    """Send alerts to configured channels for high-confidence findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.min_score = SEVERITY_THRESHOLD.get(config.min_alert_severity, 40)

    async def send_alert(self, finding: Finding) -> None:
        """Send alerts to all configured channels."""
        if finding.confidence.score < self.min_score:
            return

        tasks = []

        if self.config.telegram_token and self.config.telegram_chat_id:
            tasks.append(self._telegram(finding))

        if self.config.discord_webhook:
            tasks.append(self._discord(finding))

        if self.config.slack_webhook:
            tasks.append(self._slack(finding))

        if self.config.generic_webhook:
            tasks.append(self._webhook(finding))

        if self.config.alert_email and self.config.smtp_host:
            tasks.append(self._email(finding))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.debug(f"Alert delivery error: {r}")

    def _build_alert_payload(self, finding: Finding) -> dict:
        """Build standardized alert payload."""
        return {
            "subdomain": finding.subdomain,
            "provider": finding.provider,
            "severity": finding.confidence.severity.upper(),
            "confidence": finding.confidence.score,
            "cname": finding.cname,
            "fingerprint": finding.fingerprint_matched,
            "http_status": finding.http_status,
            "claimable": finding.claimability.is_claimable if finding.claimability else None,
            "evidence": (finding.claimability.evidence if finding.claimability else
                         finding.fingerprint_matched or "Dangling CNAME"),
            "screenshot": str(finding.screenshot_path) if finding.screenshot_path else None,
            "timestamp": finding.timestamp.isoformat(),
            "confidence_reasons": finding.confidence.reasons,
        }

    def _format_message(self, finding: Finding) -> str:
        """Format alert message."""
        sev_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪"
        }
        sev = finding.confidence.severity.upper()
        emoji = sev_emoji.get(sev, "⚠️")

        claimable_text = ""
        if finding.claimability:
            claimable_text = f"\n✅ Claimable: {finding.claimability.is_claimable}"
            if finding.claimability.evidence:
                claimable_text += f"\n📋 Evidence: {finding.claimability.evidence}"

        return (
            f"{emoji} **SubSentinel Alert** {emoji}\n\n"
            f"**Subdomain:** `{finding.subdomain}`\n"
            f"**Provider:** {finding.provider}\n"
            f"**Severity:** {sev}\n"
            f"**Confidence:** {finding.confidence.score}%\n"
            f"**CNAME:** `{finding.cname or 'N/A'}`\n"
            f"**HTTP Status:** {finding.http_status or 'N/A'}\n"
            f"**Fingerprint:** `{finding.fingerprint_matched or 'N/A'}`"
            f"{claimable_text}\n"
            f"**Time:** {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )

    async def _telegram(self, finding: Finding) -> None:
        """Send Telegram alert."""
        url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendMessage"
        message = self._format_message(finding).replace("**", "*")

        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    logger.info(f"Telegram alert sent for {finding.subdomain}")
                else:
                    body = await resp.text()
                    logger.warning(f"Telegram alert failed: {resp.status} - {body}")

                # Send screenshot if available
                if finding.screenshot_path and self.config.telegram_token:
                    await self._telegram_photo(finding.screenshot_path)

    async def _telegram_photo(self, screenshot_path: str) -> None:
        """Send screenshot via Telegram."""
        from pathlib import Path
        path = Path(screenshot_path)
        if not path.exists():
            return

        url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendPhoto"
        async with aiohttp.ClientSession() as session:
            with open(path, "rb") as f:
                data = aiohttp.FormData()
                data.add_field("chat_id", str(self.config.telegram_chat_id))
                data.add_field("photo", f, filename=path.name, content_type="image/png")
                data.add_field("caption", "📸 Screenshot of vulnerable subdomain")
                await session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=30))

    async def _discord(self, finding: Finding) -> None:
        """Send Discord webhook alert."""
        sev_colors = {
            "CRITICAL": 0xFF0000,
            "HIGH": 0xFF6600,
            "MEDIUM": 0xFFFF00,
            "LOW": 0x0099FF,
            "INFO": 0x808080,
        }
        sev = finding.confidence.severity.upper()

        payload = {
            "username": "SubSentinel",
            "embeds": [{
                "title": f"🚨 Subdomain Takeover: {finding.subdomain}",
                "color": sev_colors.get(sev, 0xFF0000),
                "fields": [
                    {"name": "Provider", "value": finding.provider, "inline": True},
                    {"name": "Severity", "value": sev, "inline": True},
                    {"name": "Confidence", "value": f"{finding.confidence.score}%", "inline": True},
                    {"name": "CNAME", "value": f"`{finding.cname or 'N/A'}`", "inline": False},
                    {"name": "HTTP Status", "value": str(finding.http_status or "N/A"), "inline": True},
                    {"name": "Fingerprint", "value": f"`{finding.fingerprint_matched or 'N/A'}`", "inline": False},
                    {"name": "Claimable", "value": str(finding.claimability.is_claimable if finding.claimability else "Unknown"), "inline": True},
                ],
                "footer": {"text": f"SubSentinel v2.0 | {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"},
                "timestamp": finding.timestamp.isoformat(),
            }]
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.discord_webhook,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status in (200, 204):
                    logger.info(f"Discord alert sent for {finding.subdomain}")
                else:
                    logger.warning(f"Discord alert failed: {resp.status}")

    async def _slack(self, finding: Finding) -> None:
        """Send Slack webhook alert."""
        sev = finding.confidence.severity.upper()
        payload = {
            "text": f"🚨 Subdomain Takeover Detected: `{finding.subdomain}`",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*🚨 Subdomain Takeover Detected*\n"
                            f"*Subdomain:* `{finding.subdomain}`\n"
                            f"*Provider:* {finding.provider}\n"
                            f"*Severity:* {sev}\n"
                            f"*Confidence:* {finding.confidence.score}%\n"
                            f"*CNAME:* `{finding.cname or 'N/A'}`\n"
                            f"*Fingerprint:* `{finding.fingerprint_matched or 'N/A'}`"
                        )
                    }
                }
            ]
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.slack_webhook,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    logger.info(f"Slack alert sent for {finding.subdomain}")
                else:
                    logger.warning(f"Slack alert failed: {resp.status}")

    async def _webhook(self, finding: Finding) -> None:
        """Send to generic webhook."""
        payload = self._build_alert_payload(finding)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.generic_webhook,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status in (200, 201, 204):
                    logger.info(f"Webhook alert sent for {finding.subdomain}")
                else:
                    logger.warning(f"Webhook alert failed: {resp.status}")

    async def _email(self, finding: Finding) -> None:
        """Send email alert."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SubSentinel] {finding.confidence.severity.upper()} - {finding.subdomain}"
            msg["From"] = f"subsentinel@{self.config.domain or 'scanner.local'}"
            msg["To"] = self.config.alert_email

            payload = self._build_alert_payload(finding)
            text_body = json.dumps(payload, indent=2)
            html_body = f"""
<html><body>
<h2>🚨 Subdomain Takeover Detected</h2>
<table border="1" cellpadding="8">
  <tr><th>Subdomain</th><td><code>{finding.subdomain}</code></td></tr>
  <tr><th>Provider</th><td>{finding.provider}</td></tr>
  <tr><th>Severity</th><td><b>{finding.confidence.severity.upper()}</b></td></tr>
  <tr><th>Confidence</th><td>{finding.confidence.score}%</td></tr>
  <tr><th>CNAME</th><td><code>{finding.cname or 'N/A'}</code></td></tr>
  <tr><th>Fingerprint</th><td><code>{finding.fingerprint_matched or 'N/A'}</code></td></tr>
  <tr><th>HTTP Status</th><td>{finding.http_status or 'N/A'}</td></tr>
  <tr><th>Claimable</th><td>{finding.claimability.is_claimable if finding.claimability else 'Unknown'}</td></tr>
  <tr><th>Timestamp</th><td>{finding.timestamp.isoformat()}</td></tr>
</table>
<h3>Evidence</h3>
<pre>{json.dumps(payload, indent=2)}</pre>
</body></html>"""

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_email_sync, msg)
            logger.info(f"Email alert sent for {finding.subdomain}")
        except Exception as e:
            logger.warning(f"Email alert failed: {e}")

    def _send_email_sync(self, msg: MIMEMultipart) -> None:
        """Synchronous email send (runs in executor)."""
        with smtplib.SMTP(self.config.smtp_host or "localhost") as server:
            server.send_message(msg)
