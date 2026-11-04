"""Command-line interface.

    python -m soc_triage triage alert.json        # one alert -> report on stdout + file
    python -m soc_triage replay samples/          # all sample alerts, in time order
    python -m soc_triage eval samples/ --labels samples/labels.json
    python -m soc_triage check                    # can we reach the LLM, indexer, ticketing?
    python -m soc_triage worker                   # long-running service (systemd)
    python -m soc_triage ticket INC-...           # open a ticket for an existing report
    python -m soc_triage index                    # create the index and (re)index all reports
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import PROVIDERS, load_config
from .history import History
from .httpjson import HTTPError
from .indexer import Indexer, IndexerError
from .llm import LLMError, make_backend
from .parser import parse_timestamp
from .pipeline import Pipeline
from .report import find_report, render_markdown
from .scoring import SEVERITY_ORDER
from .ticketing import TicketError, TicketManager, make_ticketer
from .worker import SpoolWorker


def _load_alerts(path: str) -> list:
    """Read one JSON alert, or a JSON-Lines file of alerts (like Wazuh's alerts.json)."""
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    text = text.strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def _sample_files(directory: str) -> list:
    alerts = []
    for path in sorted(Path(directory).glob("*.json")):
        if path.name == "labels.json":
            continue
        for raw in _load_alerts(str(path)):
            alerts.append((path.name, raw))
    alerts.sort(key=lambda item: parse_timestamp(item[1].get("timestamp")))
    return alerts


def cmd_triage(args, cfg) -> int:
    pipeline = Pipeline(cfg)
    status = 0
    for raw in _load_alerts(args.file):
        result = pipeline.handle(raw, force=True, write=not args.no_write, send=not args.no_notify)
        if result is None:
            print("Alert recorded for correlation; it is not an incident on its own.", file=sys.stderr)
            continue
        incident, path = result
        print(json.dumps(incident.to_dict(), indent=2, default=str) if args.json
              else render_markdown(incident))
        if path:
            print(f"\nReport written to {path}", file=sys.stderr)
    return status


def _run_samples(directory: str, cfg, keep_history: bool, write: bool = True):
    history = History(cfg.db_path) if keep_history else History(":memory:")
    pipeline = Pipeline(cfg, history=history)
    rows = []
    for name, raw in _sample_files(directory):
        result = pipeline.handle(raw, force=True, write=write, send=False)
        rows.append((name, raw, result))
    return rows


def cmd_replay(args, cfg) -> int:
    rows = _run_samples(args.directory, cfg, args.keep_history)
    print(f"{'Sample':<44} {'Rule':>6} {'Base':>5} {'AI':>4} {'Final':>6}  {'Severity':<9} Source")
    for name, raw, result in rows:
        rule = raw.get("rule", {}).get("id", "?")
        if result is None:
            print(f"{name:<44} {rule:>6} {'-':>5} {'-':>4} {'-':>6}  {'(recorded only)':<9}")
            continue
        inc, _ = result
        print(f"{name:<44} {rule:>6} {inc.score.base_score:>5} {inc.applied_adjustment:>+4} "
              f"{inc.final_score:>6}  {inc.severity:<9} {inc.analysis.source}")
    print(f"\nReports written under {cfg.reports_dir}/")
    return 0


def cmd_eval(args, cfg) -> int:
    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    rows = _run_samples(args.directory, cfg, keep_history=False, write=False)
    exact = near = total = 0
    print(f"{'Sample':<44} {'Expected':<9} {'Got':<9} {'Score':>5}  Result")
    for name, _raw, result in rows:
        if name not in labels:
            continue
        expected = labels[name]
        got = result[0].severity if result else "None"
        score = result[0].final_score if result else 0
        total += 1
        if got == expected:
            exact += 1
            verdict = "match"
        elif got in SEVERITY_ORDER and expected in SEVERITY_ORDER and \
                abs(SEVERITY_ORDER.index(got) - SEVERITY_ORDER.index(expected)) == 1:
            near += 1
            verdict = "one band off"
        else:
            verdict = "MISS"
        print(f"{name:<44} {expected:<9} {got:<9} {score:>5}  {verdict}")
    if total:
        print(f"\nExact severity match: {exact}/{total} ({100 * exact / total:.0f}%)")
        print(f"Within one band:      {exact + near}/{total} ({100 * (exact + near) / total:.0f}%)")
    return 0


def cmd_check(_args, cfg) -> int:
    checks = []
    if cfg.llm.provider.startswith("mock"):
        checks.append(("LLM", lambda: f"provider '{cfg.llm.provider}'; no model needed"))
    else:
        checks.append(("LLM", lambda: make_backend(cfg.llm).check()))
    if cfg.indexer.enabled:
        checks.append(("Indexer", lambda: Indexer(cfg.indexer).check()))
    if cfg.ticketing.system != "none":
        checks.append((f"Ticketing ({cfg.ticketing.system})", lambda: make_ticketer(cfg).check()))
    failed = 0
    for name, fn in checks:
        try:
            print(f"[ OK ] {name}: {fn()}")
        except (LLMError, HTTPError, IndexerError, TicketError, KeyError) as exc:
            failed += 1
            print(f"[FAIL] {name}: {exc}")
    for name, enabled in [("Indexer", cfg.indexer.enabled),
                          ("Ticketing", cfg.ticketing.system != "none")]:
        if not enabled:
            print(f"[ -- ] {name}: disabled in config")
    return 1 if failed else 0


def cmd_worker(_args, cfg) -> int:
    SpoolWorker(cfg, Pipeline(cfg)).run_forever()
    return 0


def _load_incident(cfg, incident_id: str):
    md = find_report(cfg.reports_dir, incident_id)
    if not md:
        raise SystemExit(f"No report found for {incident_id} under {cfg.reports_dir}")
    return json.loads(md.with_suffix(".json").read_text(encoding="utf-8")), md.read_text(encoding="utf-8")


def cmd_ticket(args, cfg) -> int:
    if cfg.ticketing.system == "none":
        print("Set ticketing.system in the config first (github, jira or thehive).", file=sys.stderr)
        return 1
    inc, markdown = _load_incident(cfg, args.incident_id)
    try:
        ticket = TicketManager(cfg, History(cfg.db_path)).maybe_create(inc, markdown, force=True)
    except TicketError as exc:
        print(f"Ticket failed: {exc}", file=sys.stderr)
        return 1
    print(f"{ticket['system']} ticket {ticket['id']}: {ticket.get('url')}")
    if cfg.indexer.enabled:
        try:
            Indexer(cfg.indexer).update(inc["incident_id"], {"ticket_system": ticket["system"],
                                                             "ticket_url": ticket.get("url")})
        except IndexerError as exc:
            print(f"Warning: dashboard not updated: {exc}", file=sys.stderr)
    return 0


def cmd_index(args, cfg) -> int:
    indexer = Indexer(cfg.indexer)
    try:
        created = indexer.ensure_index()
        print(f"Index '{cfg.indexer.index}' {'created' if created else 'already exists'}.")
        if not args.setup_only:
            print(f"Indexed {indexer.backfill(cfg.reports_dir)} report(s) from {cfg.reports_dir}.")
    except (IndexerError, HTTPError) as exc:
        print(f"Indexer error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="soc_triage", description="AI-assisted Wazuh alert triage")
    parser.add_argument("--config", help="Path to config JSON (or set SOC_TRIAGE_CONFIG)")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), help="Override llm.provider")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("triage", help="Triage an alert file (JSON or JSON Lines; '-' for stdin)")
    p.add_argument("file")
    p.add_argument("--json", action="store_true", help="Print the incident as JSON")
    p.add_argument("--no-write", action="store_true", help="Don't save a report file")
    p.add_argument("--no-notify", action="store_true", help="Don't send the webhook")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("replay", help="Triage every alert in a folder, in timestamp order")
    p.add_argument("directory")
    p.add_argument("--keep-history", action="store_true",
                   help="Use the real history DB instead of a fresh in-memory one")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("eval", help="Compare the bot's severities with your labels")
    p.add_argument("directory")
    p.add_argument("--labels", required=True, help="JSON mapping sample filename -> expected severity")
    p.set_defaults(func=cmd_eval)

    sub.add_parser("check", help="Check the LLM and every enabled integration").set_defaults(func=cmd_check)
    sub.add_parser("worker", help="Run the spool worker (used by systemd)").set_defaults(func=cmd_worker)

    p = sub.add_parser("ticket", help="Open a ticket for an existing incident report")
    p.add_argument("incident_id")
    p.set_defaults(func=cmd_ticket)

    p = sub.add_parser("index", help="Create the dashboard index and index all saved reports")
    p.add_argument("--setup-only", action="store_true", help="Only create the index")
    p.set_defaults(func=cmd_index)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        cfg = load_config(args.config, provider=args.provider)
    except (OSError, ValueError) as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    return args.func(args, cfg)
