"""The triage pipeline: parse -> enrich -> score -> analyse -> report."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .config import Config
from .history import History
from .llm import analyze
from .models import Alert, Enrichment, Incident, LLMAnalysis
from .notify import notify
from .parser import parse_wazuh_alert
from .playbooks import CATEGORY_LABELS, describe, playbook
from .indexer import Indexer, IndexerError
from .report import render_markdown, write_report
from .sanitize import clean_text, detect_injection
from .scoring import apply_llm_adjustment, compute_base_score, severity_for
from .ticketing import TicketManager

log = logging.getLogger("soc_triage.pipeline")


class Pipeline:
    def __init__(self, cfg: Config, history: Optional[History] = None,
                 tickets: Optional[TicketManager] = None, indexer: Optional[Indexer] = None):
        self.cfg = cfg
        self.history = history or History(cfg.db_path)
        self.internal = [ipaddress.ip_network(n, strict=False) for n in cfg.internal_networks]
        self.privileged = {p.lower() for p in cfg.privileged_accounts}
        self.tickets = tickets or TicketManager(cfg, self.history)
        self.indexer = indexer or (Indexer(cfg.indexer) if cfg.indexer.enabled else None)

    # ------------------------------------------------------------------ enrichment
    def is_external(self, ip: Optional[str]) -> Optional[bool]:
        if not ip:
            return None
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in self.internal if net.version == addr.version)

    def enrich(self, alert: Alert) -> Enrichment:
        past = self.history.lookback(alert, self.cfg.correlation_window_minutes)
        users = set(past["users"])
        if alert.user:
            users.add(alert.user.lower())
        agents = set(past["agents"]) | {alert.agent_name}
        first_seen = past["first_seen"]
        return Enrichment(
            related_events=past["related"],
            distinct_users=len(users),
            distinct_agents=len(agents),
            prior_failures=past["failures_same_agent"],
            success_after_failures=alert.category == "auth_success" and past["failures_same_agent"] > 0,
            src_is_external=self.is_external(alert.src_ip),
            privileged_target=bool(alert.user) and alert.user.lower() in self.privileged,
            asset_criticality=self.cfg.asset_criticality.get(alert.agent_name, "unknown"),
            first_seen=datetime.fromtimestamp(first_seen, alert.timestamp.tzinfo or timezone.utc).isoformat()
            if first_seen else None,
            injection_flags=detect_injection(alert.full_log, alert.previous_output, alert.user, alert.url),
        )

    # ------------------------------------------------------------------ LLM context
    @staticmethod
    def build_context(alert: Alert, enr: Enrichment, base: int, breakdown: list) -> dict:
        trusted = {
            "alert": {
                "wazuh_alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "rule_id": alert.rule_id,
                "rule_level": alert.rule_level,
                "rule_description": clean_text(alert.rule_description, 300),
                "rule_groups": alert.groups,
                "rule_frequency": alert.frequency,
                "category": alert.category,
                "category_label": CATEGORY_LABELS.get(alert.category, alert.category),
                "wazuh_mitre_ids": alert.mitre_ids,
                "wazuh_mitre_tactics": alert.mitre_tactics,
                "agent_name": alert.agent_name,
                "agent_ip": alert.agent_ip,
                "source_ip": alert.src_ip,
                "source_port": alert.src_port,
                "destination_ip": alert.dst_ip,
                "destination_port": alert.dst_port,
                "log_location": alert.location,
            },
            "enrichment": asdict(enr),
            "deterministic_score": {
                "base_score": base,
                "severity": severity_for(base),
                "breakdown": breakdown,
            },
            "template_summary": describe(alert, enr),
        }
        # Anything an attacker can type goes here, never in the trusted block.
        untrusted = {
            "account_name": clean_text(alert.user, 200) or None,
            "url": clean_text(alert.url, 500) or None,
            "full_log": clean_text(alert.full_log, 3000),
            "previous_output": clean_text(alert.previous_output, 3000),
        }
        return {"trusted": trusted, "untrusted": untrusted}

    @staticmethod
    def fallback_analysis(alert: Alert, enr: Enrichment) -> LLMAnalysis:
        indicators = [f"Source IP {alert.src_ip}"] if alert.src_ip else []
        if enr.injection_flags:
            indicators.append("Prompt-injection text in log: " + ", ".join(enr.injection_flags))
        return LLMAnalysis(
            summary=describe(alert, enr),
            attack_type=CATEGORY_LABELS.get(alert.category, "Security alert"),
            mitre_techniques=list(alert.mitre_ids),
            risk_adjustment=0,
            adjustment_rationale="",
            likely_false_positive=False,
            false_positive_reasoning="Not assessed (no model available).",
            indicators=indicators,
            recommended_actions=playbook(alert.category),
            confidence="low",
            source="fallback",
        )

    # ------------------------------------------------------------------ main entry
    def process(self, raw: dict, force: bool = False) -> Optional[Incident]:
        """Triage one alert. Returns None if the alert is recorded but not an incident."""
        alert = parse_wazuh_alert(raw)
        enr = self.enrich(alert)
        self.history.record(alert)

        if alert.category == "auth_success":
            if not enr.success_after_failures:
                if alert.src_ip:
                    log.info("Recorded login success %s from %s (no prior failures; not an incident)",
                             alert.alert_id, alert.src_ip)
                else:  # e.g. "PAM: Login session opened" for local sudo sessions
                    log.debug("Ignored local session alert %s (rule %s, no source IP)",
                              alert.alert_id, alert.rule_id)
                return None
            alert.category = "account_compromise"
        elif alert.rule_level < self.cfg.min_level and not force:
            log.info("Skipping alert %s: level %d below min_level %d",
                     alert.alert_id, alert.rule_level, self.cfg.min_level)
            return None

        score = compute_base_score(alert, enr, self.cfg)
        context = self.build_context(alert, enr, score.base_score, score.breakdown)
        analysis = analyze(self.cfg.llm, context, lambda: self.fallback_analysis(alert, enr))

        applied = apply_llm_adjustment(analysis.risk_adjustment, self.cfg.max_llm_raise)
        final = min(100, score.base_score + applied)
        digest = hashlib.sha1(alert.alert_id.encode("utf-8")).hexdigest()[:8]
        return Incident(
            incident_id=f"INC-{alert.timestamp:%Y%m%d}-{digest}",
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            alert=alert,
            enrichment=enr,
            score=score,
            analysis=analysis,
            applied_adjustment=applied,
            final_score=final,
            severity=severity_for(final),
        )

    def handle(self, raw: dict, force: bool = False, write: bool = True,
               send: bool = True) -> Optional[tuple]:
        """Process an alert end to end. Returns (incident, markdown_path).

        send=False skips everything that talks to other systems (ticket, indexer, webhook),
        which is what replay/eval use.
        """
        incident = self.process(raw, force=force)
        if incident is None:
            return None
        if send:
            incident.ticket = self.tickets.maybe_create(incident.to_dict(), render_markdown(incident))
        md_path = None
        if write:
            md_path, _ = write_report(incident, self.cfg.reports_dir)
        log.info("%s %s score=%d (%s) report=%s", incident.incident_id, incident.severity,
                 incident.final_score, incident.analysis.source, md_path)
        if send:
            if self.indexer:
                try:
                    self.indexer.index(incident.to_dict())
                except IndexerError as exc:
                    log.warning("Indexing %s failed: %s", incident.incident_id, exc)
            notify(self.cfg, incident)
        return incident, md_path
