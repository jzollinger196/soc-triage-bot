"""Index incidents into the Wazuh indexer (OpenSearch) for dashboards.

Incidents go to their own index (default `soc-triage-incidents`), not Wazuh's
`wazuh-alerts-*`, so Wazuh upgrades and index lifecycle policies are unaffected.
Documents use the incident ID as their _id, so re-indexing is idempotent.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import quote

from .config import IndexerConfig
from .httpjson import HTTPError, basic_auth, env_value, request
from .playbooks import CATEGORY_LABELS
from .scoring import SEVERITY_ORDER

log = logging.getLogger("soc_triage.indexer")

INDEX_SETTINGS = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},  # single-node lab
    "mappings": {
        "dynamic": False,
        "properties": {
            "@timestamp": {"type": "date"},
            "created_at": {"type": "date"},
            "incident_id": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "severity_rank": {"type": "integer"},
            "final_score": {"type": "integer"},
            "base_score": {"type": "integer"},
            "ai_adjustment_applied": {"type": "integer"},
            "ai_adjustment_proposed": {"type": "integer"},
            "category": {"type": "keyword"},
            "category_label": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_level": {"type": "integer"},
            "rule_description": {"type": "text"},
            "agent_id": {"type": "keyword"},
            "agent_name": {"type": "keyword"},
            "src_ip": {"type": "ip"},
            "dst_ip": {"type": "ip"},
            "user": {"type": "keyword", "ignore_above": 256},
            "mitre_techniques": {"type": "keyword"},
            "related_events": {"type": "integer"},
            "success_after_failures": {"type": "boolean"},
            "src_is_external": {"type": "boolean"},
            "injection_detected": {"type": "boolean"},
            "injection_flags": {"type": "keyword"},
            "likely_false_positive": {"type": "boolean"},
            "ai_source": {"type": "keyword"},
            "ai_fallback": {"type": "boolean"},
            "ai_confidence": {"type": "keyword"},
            "summary": {"type": "text"},
            "ticket_system": {"type": "keyword"},
            "ticket_url": {"type": "keyword"},
        },
    },
}


def incident_document(inc: dict) -> dict:
    """Flatten an incident dict (Incident.to_dict or report JSON) into an index document."""
    a, e, s, an = inc["alert"], inc["enrichment"], inc["score"], inc["analysis"]
    ticket = inc.get("ticket") or {}
    return {
        "@timestamp": a["timestamp"],
        "created_at": inc["created_at"],
        "incident_id": inc["incident_id"],
        "severity": inc["severity"],
        "severity_rank": SEVERITY_ORDER.index(inc["severity"]) + 1,
        "final_score": inc["final_score"],
        "base_score": s["base_score"],
        "ai_adjustment_applied": inc["applied_adjustment"],
        "ai_adjustment_proposed": an["risk_adjustment"],
        "category": a["category"],
        "category_label": CATEGORY_LABELS.get(a["category"], a["category"]),
        "rule_id": a["rule_id"],
        "rule_level": a["rule_level"],
        "rule_description": a["rule_description"],
        "agent_id": a.get("agent_id") or None,
        "agent_name": a["agent_name"],
        "src_ip": a.get("src_ip"),
        "dst_ip": a.get("dst_ip"),
        "user": a.get("user"),
        "mitre_techniques": an.get("mitre_techniques") or a.get("mitre_ids") or [],
        "related_events": e["related_events"],
        "success_after_failures": e["success_after_failures"],
        "src_is_external": e.get("src_is_external"),
        "injection_detected": bool(e["injection_flags"]),
        "injection_flags": e["injection_flags"],
        "likely_false_positive": an["likely_false_positive"],
        "ai_source": an["source"],
        "ai_fallback": an["source"] == "fallback",
        "ai_confidence": an["confidence"],
        "summary": an["summary"],
        "ticket_system": ticket.get("system"),
        "ticket_url": ticket.get("url"),
    }


class IndexerError(Exception):
    pass


class Indexer:
    def __init__(self, cfg: IndexerConfig):
        self.cfg = cfg
        self.base = cfg.url.rstrip("/")
        self.index_name = quote(cfg.index)
        self._ready = False

    def _call(self, method, path, payload=None):
        try:
            headers = {"Authorization": basic_auth(env_value(self.cfg.user_env),
                                                   env_value(self.cfg.password_env))}
            return request(method, self.base + path, payload=payload, headers=headers,
                           verify=self.cfg.verify_tls, ca_cert=self.cfg.ca_cert,
                           timeout=self.cfg.timeout_seconds)[1]
        except HTTPError as exc:
            raise IndexerError(str(exc)) from exc

    def ensure_index(self) -> bool:
        """Create the index with its mapping if missing. Returns True if it was created."""
        if self._ready:
            return False
        try:
            self._call("HEAD", f"/{self.index_name}")
            created = False
        except IndexerError as exc:
            if "HTTP 404" not in str(exc):
                raise
            try:
                self._call("PUT", f"/{self.index_name}", INDEX_SETTINGS)
                created = True
            except IndexerError as exc2:   # another process created it first
                if "resource_already_exists" not in str(exc2):
                    raise
                created = False
        self._ready = True
        return created

    def index(self, inc: dict) -> None:
        self.ensure_index()
        self._call("PUT", f"/{self.index_name}/_doc/{quote(inc['incident_id'])}", incident_document(inc))

    def update(self, incident_id: str, fields: dict) -> None:
        self.ensure_index()
        self._call("POST", f"/{self.index_name}/_update/{quote(incident_id)}", {"doc": fields})

    def backfill(self, reports_dir: str) -> int:
        count = 0
        for path in sorted(Path(reports_dir).rglob("INC-*.json")):
            self.index(json.loads(path.read_text(encoding="utf-8")))
            count += 1
        return count

    def check(self) -> str:
        info = self._call("GET", "/")
        version = (info or {}).get("version", {}).get("number", "?") if isinstance(info, dict) else "?"
        return f"Indexer reachable at {self.base} (version {version}); credentials work."
