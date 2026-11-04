"""Deterministic, explainable risk scoring (0-100).

The LLM never sets the score. It may propose an adjustment, but only increases are
applied (capped at Config.max_llm_raise), so this score is a floor that prompt
injection or a hallucinating model cannot lower.
"""
from __future__ import annotations

from .config import Config
from .models import Alert, Enrichment, ScoreResult

SEVERITY_BANDS = [(80, "Critical"), (55, "High"), (30, "Medium"), (0, "Low")]
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
CRITICALITY_POINTS = {"high": 15, "medium": 8, "low": 0}


def severity_for(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Low"


def compute_base_score(alert: Alert, enr: Enrichment, cfg: Config) -> ScoreResult:
    breakdown = []

    def add(reason: str, points: int) -> None:
        if points:
            breakdown.append([reason, int(points)])

    add(f"Wazuh rule {alert.rule_id} at level {alert.rule_level}", min(60, alert.rule_level * 4))
    if alert.frequency and alert.frequency > 1:
        add(f"Rule only fires after {alert.frequency}+ matching events", min(10, alert.frequency))
    if enr.related_events:
        add(f"{enr.related_events} earlier alert(s) from the same source in the last "
            f"{cfg.correlation_window_minutes} min", min(15, 3 * enr.related_events))
    if enr.distinct_users >= 3:
        add(f"{enr.distinct_users} different accounts targeted (password-spraying pattern)", 5)
    if enr.distinct_agents >= 2:
        add(f"{enr.distinct_agents} different hosts targeted by the same source", 5)
    if enr.privileged_target:
        add("A privileged account was targeted", 10)
    if enr.success_after_failures:
        add(f"Successful login after {enr.prior_failures} failed-login alert(s) from the same source",
            45)
    elif alert.category == "account_compromise":
        add(f"Wazuh rule {alert.rule_id} correlated failed logins followed by a success from the same source",
            45)
    if enr.src_is_external:
        add("Source IP is outside the internal networks", 10)
    add(f"Asset criticality of {alert.agent_name}: {enr.asset_criticality}",
        CRITICALITY_POINTS.get(enr.asset_criticality, 0))
    if enr.injection_flags:
        add("Log text appears crafted to manipulate an AI analyst ("
            + ", ".join(enr.injection_flags) + ")", 10)

    total = max(0, min(100, sum(points for _, points in breakdown)))
    return ScoreResult(base_score=total, breakdown=breakdown)


def apply_llm_adjustment(proposed: int, max_raise: int) -> int:
    """Only positive adjustments are applied, capped at max_raise."""
    return max(0, min(int(max_raise), int(proposed)))
