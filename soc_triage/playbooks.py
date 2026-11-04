"""Category labels, template summaries and standard response playbooks.

Used when the LLM is unavailable (fallback) and by the mock provider, so the bot
always produces a usable report even with no model running.
"""
from __future__ import annotations

from .models import Alert, Enrichment
from .sanitize import clean_text

CATEGORY_LABELS = {
    "brute_force": "Brute-force login attempt",
    "auth_failure": "Failed login",
    "account_compromise": "Possible account compromise (login after brute force)",
    "dos": "Denial-of-service flood",
    "web_attack": "Web attack or scanning",
    "ids_alert": "IDS alert",
    "auth_success": "Successful login",
    "other": "Security alert",
}

PLAYBOOKS = {
    "brute_force": [
        "Block the source IP at the host firewall or perimeter and confirm the attempts stop.",
        "Check whether any login from this source succeeded (Wazuh query: "
        "rule.groups:authentication_success AND data.srcip:<source IP>).",
        "Confirm whether the targeted accounts exist; reset passwords on any that do and enforce MFA.",
        "Harden SSH: disable password authentication and root login, and enable fail2ban or "
        "Wazuh active response.",
    ],
    "auth_failure": [
        "Confirm with the account owner whether the failed login was theirs.",
        "Watch for repeat failures from the same source before escalating.",
    ],
    "account_compromise": [
        "Treat the account as compromised: disable it or reset its credentials and end its active sessions.",
        "Isolate the host from the network if the login was not authorised.",
        "Review activity after the login (shell history, auditd, Wazuh file-integrity changes) and look "
        "for persistence such as new users, cron jobs or authorized_keys entries.",
        "Block the source IP and search for the same source on other hosts.",
        "Preserve logs and other evidence before remediation.",
    ],
    "dos": [
        "Confirm service impact on the target (latency, dropped connections, CPU or connection-table load).",
        "Rate-limit or block the source at the edge and make sure SYN cookies are enabled "
        "(net.ipv4.tcp_syncookies=1).",
        "If the traffic is spoofed or distributed, escalate for upstream filtering.",
    ],
    "web_attack": [
        "Block the source IP at the web server or WAF.",
        "Check the web logs for successful (2xx) responses to the probed paths.",
        "Verify the targeted application is patched against what was being probed.",
    ],
    "ids_alert": [
        "Review the IDS signature and the matching traffic to decide whether it is malicious.",
        "Block the source if the traffic is confirmed hostile.",
    ],
    "other": [
        "Review the raw log and the Wazuh rule to decide whether escalation is needed.",
    ],
}


def _src(alert: Alert) -> str:
    return alert.src_ip or "an unknown source"


def _user(alert: Alert) -> str:
    return f" targeting account '{clean_text(alert.user, 64)}'" if alert.user else ""


def describe(alert: Alert, enr: Enrichment) -> str:
    """One-paragraph factual summary built only from parsed fields."""
    cat = alert.category
    if cat == "brute_force":
        text = f"Wazuh detected a brute-force login attempt against {alert.agent_name} from {_src(alert)}{_user(alert)}."
    elif cat == "account_compromise":
        who = f" as '{clean_text(alert.user, 64)}'" if alert.user else ""
        before = (f"{enr.prior_failures} failed-login alert(s)" if enr.prior_failures
                  else f"multiple failed logins (correlated by Wazuh rule {alert.rule_id})")
        text = (f"A successful login{who} on {alert.agent_name} from {_src(alert)} followed "
                f"{before} from the same source. The account may be compromised.")
    elif cat == "dos":
        port = f":{alert.dst_port}" if alert.dst_port else ""
        text = f"A possible flood against {alert.dst_ip or alert.agent_name}{port} from {_src(alert)} was detected."
    elif cat == "web_attack":
        text = f"{clean_text(alert.rule_description, 200).rstrip('.')} on {alert.agent_name}, from {_src(alert)}."
    else:
        text = (f"Wazuh rule {alert.rule_id} ({clean_text(alert.rule_description, 200).rstrip('.')}) fired on "
                f"{alert.agent_name}" + (f" with source {alert.src_ip}." if alert.src_ip else "."))
    if enr.related_events and cat != "account_compromise":
        text += f" {enr.related_events} earlier alert(s) came from the same source in the correlation window."
    return text


def playbook(category: str) -> list:
    return list(PLAYBOOKS.get(category, PLAYBOOKS["other"]))
