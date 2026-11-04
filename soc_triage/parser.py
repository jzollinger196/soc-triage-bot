"""Turn raw Wazuh alert JSON into a normalised Alert.

Wazuh decoders name fields differently depending on the log source (sshd uses
data.srcip, Suricata uses data.src_ip, Windows uses data.win.eventdata.ipAddress),
so every field is looked up from a list of candidate paths.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from .models import Alert

_EMPTY = {"", "-", "(null)", "null", "none", "n/a"}

SRC_IP_PATHS = ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress",
                "data.win.eventdata.sourceAddress"]
SRC_PORT_PATHS = ["data.srcport", "data.src_port", "data.win.eventdata.ipPort"]
DST_IP_PATHS = ["data.dstip", "data.dest_ip", "data.win.eventdata.destinationAddress"]
DST_PORT_PATHS = ["data.dstport", "data.dest_port", "data.win.eventdata.destinationPort"]
USER_PATHS = ["data.dstuser", "data.srcuser", "data.user",
              "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName"]
URL_PATHS = ["data.url", "data.http.url"]


def _get(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(raw: dict, paths: list) -> Optional[str]:
    for path in paths:
        value = _get(raw, path)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value is None:
            continue
        text = str(value).strip()
        if text.lower() not in _EMPTY:
            return text
    return None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def valid_ip(value: Optional[str]) -> Optional[str]:
    """Return a normalised IP string, or None if the value is not an IP address."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:  # Windows often logs ::ffff:1.2.3.4
        ip = ip.ipv4_mapped
    return str(ip)


def parse_timestamp(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip().replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ValueError(f"Unrecognised timestamp: {value!r}")


# Wazuh rules that already correlate "several failed logins, then a success from the same
# source" (e.g. 40112). The successful login is reported under these instead of 5715.
COMPROMISE_RULE_IDS = {"40112"}


def classify(groups: list, level: int, description: str, raw: dict, rule_id: str = "") -> str:
    """Map Wazuh rule groups to the bot's incident categories."""
    g = {x.lower() for x in groups}
    desc = description.lower()
    ids_category = str(_get(raw, "data.alert.category") or "").lower()

    if rule_id in COMPROMISE_RULE_IDS or "failures followed by a success" in desc:
        return "account_compromise"
    if "authentication_success" in g:
        return "auth_success"
    if g & {"dos", "ddos"} or "denial of service" in ids_category or "denial of service" in desc \
            or "flood" in desc:
        return "dos"
    if g & {"authentication_failures", "brute_force"} or ("authentication_failed" in g and level >= 10):
        return "brute_force"
    if g & {"authentication_failed", "invalid_login"}:
        return "auth_failure"
    if (g & {"web", "accesslog"}) and (g & {"attack", "sql_injection", "web_scan", "recon", "xss"}):
        return "web_attack"
    if g & {"ids", "suricata"}:
        return "ids_alert"
    return "other"


def parse_wazuh_alert(raw: dict) -> Alert:
    if not isinstance(raw, dict):
        raise ValueError("Alert must be a JSON object")
    rule = raw.get("rule") or {}
    if not rule.get("id"):
        raise ValueError("Alert has no rule.id - is this a Wazuh alert?")

    level = int(rule.get("level", 0))
    groups = _as_list(rule.get("groups"))
    description = str(rule.get("description", ""))
    mitre = rule.get("mitre") or {}
    agent = raw.get("agent") or {}
    timestamp = parse_timestamp(raw.get("timestamp"))

    frequency = rule.get("frequency")
    try:
        frequency = int(frequency) if frequency is not None else None
    except (TypeError, ValueError):
        frequency = None

    return Alert(
        alert_id=str(raw.get("id") or f"{rule['id']}-{timestamp.timestamp():.0f}"),
        timestamp=timestamp,
        rule_id=str(rule["id"]),
        rule_level=level,
        rule_description=description,
        groups=groups,
        mitre_ids=_as_list(mitre.get("id")),
        mitre_tactics=_as_list(mitre.get("tactic")),
        mitre_techniques=_as_list(mitre.get("technique")),
        agent_name=str(agent.get("name") or "unknown-agent"),
        agent_ip=valid_ip(agent.get("ip")),
        src_ip=valid_ip(_first(raw, SRC_IP_PATHS)),
        src_port=_first(raw, SRC_PORT_PATHS),
        dst_ip=valid_ip(_first(raw, DST_IP_PATHS)) or valid_ip(agent.get("ip")),
        dst_port=_first(raw, DST_PORT_PATHS),
        user=_first(raw, USER_PATHS),
        url=_first(raw, URL_PATHS),
        category=classify(groups, level, description, raw, str(rule["id"])),
        frequency=frequency,
        full_log=str(raw.get("full_log") or ""),
        previous_output=str(raw.get("previous_output") or ""),
        location=str(raw.get("location") or ""),
        raw=raw,
        agent_id=str(agent.get("id") or ""),
    )
