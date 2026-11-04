"""Open a ticket for an incident in GitHub Issues, Jira or TheHive.

Ticket bodies contain attacker-controlled log text, so:
* GitHub @mentions are neutralised (a log line can't ping your teammates),
* Jira evidence goes in a code block / {noformat} that can't be closed early,
* everything is length-capped. Use a PRIVATE GitHub repo: reports contain IPs and usernames.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from .config import Config
from .history import History
from .httpjson import HTTPError, basic_auth, env_value, request
from .playbooks import CATEGORY_LABELS
from .sanitize import clean_text

log = logging.getLogger("soc_triage.ticketing")

THEHIVE_SEVERITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class TicketError(Exception):
    pass


def ticket_title(inc: dict) -> str:
    a = inc["alert"]
    label = CATEGORY_LABELS.get(a["category"], "Security alert")
    src = f" from {a['src_ip']}" if a.get("src_ip") else ""
    title = f"[{inc['severity']} {inc['final_score']}] {label} on {a['agent_name']}{src} ({inc['incident_id']})"
    return clean_text(title, 240).replace("\n", " ")


def _labels(inc: dict, base: list) -> list:
    return list(dict.fromkeys([*base, f"severity-{inc['severity'].lower()}", inc["alert"]["category"]]))


def _call(method, url, cfg, *, payload=None, headers=None, verify=True, ca_cert=""):
    try:
        return request(method, url, payload=payload, headers=headers, verify=verify, ca_cert=ca_cert,
                       timeout=cfg.ticketing.timeout_seconds)[1]
    except HTTPError as exc:
        raise TicketError(str(exc)) from exc


# --------------------------------------------------------------------------- GitHub
class GitHubTicketer:
    name = "github"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.gh = cfg.ticketing.github
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", self.gh.repo or ""):
            raise TicketError("ticketing.github.repo must look like owner/name")

    def _headers(self):
        return {"Authorization": f"Bearer {env_value(self.gh.token_env)}",
                "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    @staticmethod
    def neutralise(text: str) -> str:
        # Insert a zero-width space after "@" so "@user" and "@org/team" never notify anyone.
        return re.sub(r"@(?=[A-Za-z0-9_-])", "@​", text)

    def create(self, inc: dict, markdown: str) -> dict:
        body = self.neutralise(markdown[:60000])
        data = _call("POST", f"{self.gh.api_url.rstrip('/')}/repos/{self.gh.repo}/issues", self.cfg,
                     payload={"title": ticket_title(inc), "body": body,
                              "labels": _labels(inc, self.gh.labels)},
                     headers=self._headers())
        return {"system": "github", "id": str(data["number"]), "url": data.get("html_url")}


    def check(self) -> str:
        data = _call("GET", f"{self.gh.api_url.rstrip('/')}/repos/{self.gh.repo}", self.cfg,
                     headers=self._headers())
        visibility = "PRIVATE" if data.get("private") else "PUBLIC - consider a private repo"
        return f"GitHub repo {self.gh.repo} reachable ({visibility})."


# --------------------------------------------------------------------------- Jira
def _adf_text(text: str) -> dict:
    return {"type": "text", "text": text or "-"}


def _adf_para(text: str) -> dict:
    return {"type": "paragraph", "content": [_adf_text(text)]}


def _adf_heading(text: str) -> dict:
    return {"type": "heading", "attrs": {"level": 3}, "content": [_adf_text(text)]}


def _adf_list(items: list, ordered: bool = False) -> dict:
    return {"type": "orderedList" if ordered else "bulletList",
            "content": [{"type": "listItem", "content": [_adf_para(i)]} for i in items or ["-"]]}


def _facts(inc: dict) -> list:
    a, s = inc["alert"], inc["score"]
    facts = [
        f"Severity: {inc['severity']} ({inc['final_score']}/100, base {s['base_score']})",
        f"Category: {CATEGORY_LABELS.get(a['category'], a['category'])}",
        f"Wazuh rule {a['rule_id']} (level {a['rule_level']}): {clean_text(a['rule_description'], 200)}",
        f"Agent: {a['agent_name']} ({a.get('agent_ip') or '-'})",
        f"Source: {a.get('src_ip') or '-'}",
        f"Alert time: {a['timestamp']}",
    ]
    if a.get("user"):
        facts.append(f"Account: {clean_text(a['user'], 100)}")
    mitre = inc["analysis"].get("mitre_techniques") or a.get("mitre_ids") or []
    if mitre:
        facts.append("MITRE ATT&CK: " + ", ".join(mitre))
    if inc["enrichment"].get("injection_flags"):
        facts.append("Prompt-injection text detected in log: " + ", ".join(inc["enrichment"]["injection_flags"]))
    return facts


class JiraTicketer:
    name = "jira"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.j = cfg.ticketing.jira
        if not self.j.url or not self.j.project_key:
            raise TicketError("ticketing.jira.url and project_key are required")
        self.api = f"{self.j.url.rstrip('/')}/rest/api/{int(self.j.api_version)}"

    def _headers(self):
        token = env_value(self.j.token_env)
        email = os.environ.get(self.j.email_env, "")
        auth = basic_auth(email, token) if email else f"Bearer {token}"
        return {"Authorization": auth}

    def _evidence(self, inc: dict) -> str:
        return clean_text(inc["alert"].get("full_log") or "(no raw log)", 5000)

    def description(self, inc: dict):
        an = inc["analysis"]
        if int(self.j.api_version) == 3:   # Atlassian Document Format
            content = [
                _adf_para("Preliminary AI-assisted triage. An analyst must review before acting."),
                _adf_heading("Summary"), _adf_para(clean_text(an["summary"], 1200)),
                _adf_heading("Key facts"), _adf_list(_facts(inc)),
                _adf_heading("Recommended actions"),
                _adf_list([clean_text(x, 300) for x in an["recommended_actions"]], ordered=True),
            ]
            content += [_adf_heading("Raw evidence"),
                        {"type": "codeBlock", "attrs": {"language": "text"},
                         "content": [_adf_text(self._evidence(inc))]},
                        _adf_para(f"Incident {inc['incident_id']} - full report on the SOC triage server.")]
            return {"type": "doc", "version": 1, "content": content}
        # API v2 (Server/Data Center): wiki markup; neutralise {noformat} inside the evidence
        evidence = self._evidence(inc).replace("{noformat}", "{ noformat }")
        lines = ["_Preliminary AI-assisted triage. An analyst must review before acting._", "",
                 "h3. Summary", clean_text(an["summary"], 1200), "", "h3. Key facts"]
        lines += [f"* {f}" for f in _facts(inc)]
        lines += ["", "h3. Recommended actions"]
        lines += [f"# {clean_text(x, 300)}" for x in an["recommended_actions"]]
        lines += ["", "h3. Raw evidence", "{noformat}", evidence, "{noformat}"]
        return "\n".join(lines)

    def create(self, inc: dict, markdown: str) -> dict:
        labels = [re.sub(r"\s+", "-", l) for l in _labels(inc, self.j.labels)]
        data = _call("POST", f"{self.api}/issue", self.cfg, headers=self._headers(), payload={
            "fields": {
                "project": {"key": self.j.project_key},
                "summary": ticket_title(inc)[:250],
                "description": self.description(inc),
                "issuetype": {"name": self.j.issue_type},
                "labels": labels,
            }})
        return {"system": "jira", "id": data["key"], "url": f"{self.j.url.rstrip('/')}/browse/{data['key']}"}


    def check(self) -> str:
        me = _call("GET", f"{self.api}/myself", self.cfg, headers=self._headers())
        return f"Jira reachable; authenticated as {me.get('displayName') or me.get('name')}."


# --------------------------------------------------------------------------- TheHive
class TheHiveTicketer:
    name = "thehive"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.h = cfg.ticketing.thehive
        if not self.h.url:
            raise TicketError("ticketing.thehive.url is required")
        self.api = f"{self.h.url.rstrip('/')}/api/v1"

    def _kw(self):
        return {"headers": {"Authorization": f"Bearer {env_value(self.h.key_env)}"},
                "verify": self.h.verify_tls, "ca_cert": self.h.ca_cert}

    def create(self, inc: dict, markdown: str) -> dict:
        a = inc["alert"]
        tags = list(dict.fromkeys(["soc-triage", a["category"], f"wazuh-rule:{a['rule_id']}",
                                   *(inc["analysis"].get("mitre_techniques") or [])]))
        case = _call("POST", f"{self.api}/case", self.cfg, payload={
            "title": ticket_title(inc),
            "description": markdown[:60000],
            "severity": THEHIVE_SEVERITY.get(inc["severity"], 2),
            "tlp": self.h.tlp, "pap": self.h.pap,
            "tags": tags,
        }, **self._kw())
        case_id = case["_id"]
        observables = []
        if a.get("src_ip"):
            observables.append({"dataType": "ip", "data": a["src_ip"], "ioc": True,
                                "message": "Source of the activity", "tags": ["attacker"]})
        observables.append({"dataType": "hostname", "data": a["agent_name"], "message": "Targeted host"})
        for obs in observables:
            try:
                _call("POST", f"{self.api}/case/{quote(case_id)}/observable", self.cfg,
                      payload={**obs, "tlp": self.h.tlp, "pap": self.h.pap}, **self._kw())
            except TicketError as exc:   # the case exists; don't fail the whole ticket
                log.warning("Could not add observable %s to case %s: %s", obs["data"], case_id, exc)
        number = case.get("number")
        return {"system": "thehive", "id": case_id,
                "url": f"{self.h.url.rstrip('/')}/cases/{case_id}/details",
                **({"number": number} if number is not None else {})}


    def check(self) -> str:
        me = _call("GET", f"{self.api}/user/current", self.cfg, **self._kw())
        return f"TheHive reachable; authenticated as {me.get('login', '?')}."


TICKETERS = {"github": GitHubTicketer, "jira": JiraTicketer, "thehive": TheHiveTicketer}


def make_ticketer(cfg: Config):
    if cfg.ticketing.system == "none":
        return None
    return TICKETERS[cfg.ticketing.system](cfg)


class TicketManager:
    """Creates at most one ticket per incident."""

    def __init__(self, cfg: Config, history: History, ticketer=None):
        self.cfg = cfg
        self.history = history
        self._ticketer = ticketer

    @property
    def ticketer(self):
        if self._ticketer is None:
            self._ticketer = make_ticketer(self.cfg)
        return self._ticketer

    def maybe_create(self, inc: dict, markdown: str, force: bool = False) -> Optional[dict]:
        if self.cfg.ticketing.system == "none":
            return None
        existing = self.history.get_ticket(inc["incident_id"])
        if existing:
            return existing
        if not force and inc["severity"] not in self.cfg.ticketing.auto_severities:
            return None
        try:
            ticket = self.ticketer.create(inc, markdown)
        except (TicketError, HTTPError, KeyError) as exc:
            log.warning("Ticket creation failed for %s: %s", inc["incident_id"], exc)
            if force:
                raise TicketError(str(exc)) from exc
            return None
        self.history.add_ticket(inc["incident_id"], ticket,
                                datetime.now(timezone.utc).isoformat(timespec="seconds"))
        log.info("Opened %s ticket %s for %s", ticket["system"], ticket["id"], inc["incident_id"])
        return ticket
