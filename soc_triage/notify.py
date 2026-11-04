"""Optional chat notification (Slack / Discord incoming webhook, or generic JSON POST)."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from . import USER_AGENT
from .config import Config
from .models import Incident
from .report import title
from .sanitize import clean_text

log = logging.getLogger("soc_triage.notify")


def _slack_escape(text: str) -> str:
    # Slack treats <...> as links/mentions (e.g. <!channel>); escaping stops log text pinging people.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _discord_escape(text: str) -> str:
    return text.replace("@everyone", "@․everyone").replace("@here", "@․here").replace("<@", "<․@")


def build_message(inc: Incident) -> str:
    summary = clean_text(inc.analysis.summary, 400)
    text = (f"[{inc.severity.upper()} {inc.final_score}/100] {title(inc)}\n"
            f"{inc.incident_id}: {summary}")
    if inc.ticket and inc.ticket.get("url"):
        text += f"\nTicket: {inc.ticket['url']}"
    return text


def notify(cfg: Config, inc: Incident) -> bool:
    if not cfg.webhook_url:
        return False
    text = build_message(inc)
    if cfg.webhook_type == "slack":
        payload = {"text": _slack_escape(text)}
    elif cfg.webhook_type == "discord":
        payload = {"content": _discord_escape(text)[:1900], "allowed_mentions": {"parse": []}}
    else:
        payload = inc.to_dict()
    request = urllib.request.Request(
        cfg.webhook_url, data=json.dumps(payload, default=str).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10):
            return True
    except (urllib.error.URLError, OSError) as exc:
        log.warning("Webhook notification failed: %s", exc)
        return False
