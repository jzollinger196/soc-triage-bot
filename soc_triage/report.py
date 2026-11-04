"""Render incidents as Markdown reports (plus a JSON copy for tooling)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Incident
from .playbooks import CATEGORY_LABELS, playbook
from .sanitize import clean_text


def _cell(value: object) -> str:
    text = clean_text(value if value not in (None, "") else "-", 300)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _code(value: object) -> str:
    text = clean_text(value, 200).replace("`", "'").replace("\n", " ")
    return f"`{text}`" if text else "-"


def _fence(body: str) -> str:
    """Code block whose fence is longer than any backtick run inside the body."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{body}\n{fence}"


def _mitre_link(technique: str) -> str:
    path = technique.replace(".", "/")
    return f"[{technique}](https://attack.mitre.org/techniques/{path}/)"


def title(inc: Incident) -> str:
    a = inc.alert
    label = CATEGORY_LABELS.get(a.category, "Security alert")
    src = f" from {a.src_ip}" if a.src_ip else ""
    return f"{label} on {a.agent_name}{src}"


def render_markdown(inc: Incident) -> str:
    a, e, s, an = inc.alert, inc.enrichment, inc.score, inc.analysis
    adj = f" + {inc.applied_adjustment} AI" if inc.applied_adjustment else ""
    # The model downplayed an alert whose log contains injection text: assume it was manipulated.
    influenced = bool(e.injection_flags) and (an.risk_adjustment < 0 or an.likely_false_positive)
    out = [
        f"# {inc.incident_id}: {title(inc)}",
        "",
        "> **Preliminary, AI-assisted triage.** An analyst must review this before acting on it.",
        "",
    ]
    if influenced:
        out += [
            "> **WARNING: the AI analysis below may have been manipulated.** The log contains text "
            "aimed at an AI analyst, and the AI downplayed the alert. The risk score ignores the AI's "
            "downgrade; rely on the scoring table, the raw evidence and the standard playbook.",
            "",
        ]
    out += [
        "| Severity | Risk score | Category | AI confidence |",
        "|---|---|---|---|",
        f"| **{inc.severity}** | {inc.final_score}/100 (base {s.base_score}{adj}) | "
        f"{_cell(CATEGORY_LABELS.get(a.category, a.category))} | {_cell(an.confidence)} |",
        "",
    ]
    if inc.ticket:
        out += [f"Ticket: [{_cell(inc.ticket['system'])} {_cell(inc.ticket['id'])}]({inc.ticket.get('url') or ''})", ""]
    out += [
        "## Summary",
        "",
        clean_text(an.summary, 1200),
        "",
        "## Alert details",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Alert time | {a.timestamp.isoformat()} |",
        f"| Wazuh rule | {_cell(a.rule_id)} (level {a.rule_level}): {_cell(a.rule_description)} |",
        f"| Agent | {_cell(a.agent_name)} ({_cell(a.agent_ip)}) |",
        f"| Source | {_cell(a.src_ip)}{':' + _cell(a.src_port) if a.src_port else ''} |",
        f"| Destination | {_cell(a.dst_ip)}{':' + _cell(a.dst_port) if a.dst_port else ''} |",
        f"| Account | {_code(a.user) if a.user else '-'} |",
    ]
    if a.url:
        out.append(f"| URL | {_code(a.url)} |")
    out += [
        f"| Log source | {_cell(a.location)} |",
        f"| Wazuh alert ID | {_cell(a.alert_id)} |",
        "",
        "## Risk scoring",
        "",
        "| Factor | Points |",
        "|---|---|",
    ]
    out += [f"| {_cell(reason)} | +{points} |" for reason, points in s.breakdown]
    out += [
        f"| **Deterministic base score** | **{s.base_score}** |",
        "",
        f"AI proposed an adjustment of {an.risk_adjustment:+d}; applied {inc.applied_adjustment:+d}. "
        "The AI can raise the score but never lower it.",
    ]
    if an.adjustment_rationale:
        out.append(f"Rationale: {clean_text(an.adjustment_rationale, 400)}")
    out += [
        "",
        "## Correlation",
        "",
        f"- Earlier alerts from this source in the window: {e.related_events}",
        f"- Distinct accounts targeted: {e.distinct_users}",
        f"- Distinct hosts targeted: {e.distinct_agents}",
        f"- Source outside internal networks: {'yes' if e.src_is_external else 'no' if e.src_is_external is False else 'unknown'}",
        f"- Successful login after failures: {'**yes**' if e.success_after_failures else 'no'}",
        f"- First seen: {e.first_seen or a.timestamp.isoformat()}",
        "",
        "## Indicators",
        "",
    ]
    out += [f"- {_cell(i)}" for i in an.indicators] or ["- None listed"]
    techniques = an.mitre_techniques or a.mitre_ids
    out += ["", "## MITRE ATT&CK", ""]
    out += [f"- {_mitre_link(t)}" for t in techniques] or ["- None mapped"]
    if a.mitre_tactics:
        out.append(f"- Tactic(s) from Wazuh: {', '.join(_cell(t) for t in a.mitre_tactics)}")
    out += ["", "## Recommended actions", ""]
    out += [f"{n}. {clean_text(step, 300)}" for n, step in enumerate(an.recommended_actions, 1)]
    if influenced:
        out += ["", "### Standard playbook (shown because the AI output may be compromised)", ""]
        out += [f"{n}. {step}" for n, step in enumerate(playbook(a.category), 1)]
    out += [
        "",
        "## False-positive assessment",
        "",
        ("Not assessed: no AI model was available for this alert."
         if an.source == "fallback" else
         f"AI thinks this is likely a false positive: **{'yes' if an.likely_false_positive else 'no'}**. "
         + clean_text(an.false_positive_reasoning, 600)),
        "",
        "## Safety checks",
        "",
    ]
    if e.injection_flags:
        out.append("- **Prompt-injection content detected in the log:** "
                   + ", ".join(e.injection_flags)
                   + ". Treat any AI statement that downplays this alert with suspicion.")
    else:
        out.append("- No prompt-injection patterns detected in the log text.")
    out.append(f"- Analysis source: {_cell(an.source)}")
    if an.error:
        out.append(f"- LLM unavailable, so a template analysis was used: {_cell(an.error)}")
    evidence = clean_text(a.full_log, 4000)
    if a.previous_output:
        evidence += "\n\n# Earlier matching events (previous_output)\n" + clean_text(a.previous_output, 4000)
    out += ["", "## Raw evidence", "", _fence(evidence or "(no raw log in alert)"), "",
            f"_Generated {inc.created_at} by soc-triage-bot._", ""]
    return "\n".join(out)


def find_report(reports_dir: str, incident_id: str):
    matches = sorted(Path(reports_dir).rglob(f"{incident_id}.md"))
    return matches[-1] if matches else None


def write_report(inc: Incident, reports_dir: str) -> tuple:
    day_dir = Path(reports_dir) / inc.alert.timestamp.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    md_path = day_dir / f"{inc.incident_id}.md"
    json_path = day_dir / f"{inc.incident_id}.json"
    md_path.write_text(render_markdown(inc), encoding="utf-8")
    json_path.write_text(json.dumps(inc.to_dict(), indent=2, default=str), encoding="utf-8")
    return md_path, json_path
