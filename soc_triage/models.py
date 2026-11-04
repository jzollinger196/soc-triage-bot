"""Data structures passed between pipeline stages."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Alert:
    """A Wazuh alert normalised into the fields the bot cares about."""

    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    groups: list
    mitre_ids: list
    mitre_tactics: list
    mitre_techniques: list
    agent_name: str
    agent_ip: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[str]
    user: Optional[str]          # attacker-influenced
    url: Optional[str]           # attacker-influenced
    category: str
    frequency: Optional[int]
    full_log: str                # attacker-influenced
    previous_output: str         # attacker-influenced
    location: str
    raw: dict = field(repr=False, default_factory=dict)
    agent_id: str = ""


@dataclass
class Enrichment:
    """Context gathered from earlier alerts and local configuration."""

    related_events: int = 0          # earlier alerts from the same source IP in the window
    distinct_users: int = 0
    distinct_agents: int = 0
    prior_failures: int = 0          # earlier failed-login alerts from same source to same host
    success_after_failures: bool = False
    src_is_external: Optional[bool] = None
    privileged_target: bool = False
    asset_criticality: str = "unknown"
    first_seen: Optional[str] = None
    injection_flags: list = field(default_factory=list)


@dataclass
class ScoreResult:
    base_score: int
    breakdown: list  # [[reason, points], ...]


@dataclass
class LLMAnalysis:
    summary: str
    attack_type: str
    mitre_techniques: list
    risk_adjustment: int             # what the model proposed (-15..15)
    adjustment_rationale: str
    likely_false_positive: bool
    false_positive_reasoning: str
    indicators: list
    recommended_actions: list
    confidence: str                  # low | medium | high
    source: str                      # "ollama:llama3.1:8b", "mock", "fallback", ...
    error: Optional[str] = None


@dataclass
class Incident:
    incident_id: str
    created_at: str
    alert: Alert
    enrichment: Enrichment
    score: ScoreResult
    analysis: LLMAnalysis
    applied_adjustment: int
    final_score: int
    severity: str
    ticket: Optional[dict] = None            # {"system", "id", "url"}

    def to_dict(self) -> dict:
        data = asdict(self)
        data["alert"]["timestamp"] = self.alert.timestamp.isoformat()
        data["alert"].pop("raw", None)
        return data
