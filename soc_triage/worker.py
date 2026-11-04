"""Spool-directory worker.

The Wazuh integration script only drops alert files into the spool directory (it has
to return fast). This long-running service picks them up, triages them, and moves
each file to done/ or failed/. Files are claimed with an atomic rename, so a crash
never loses an alert: anything left in processing/ is re-queued on start-up.
"""
from __future__ import annotations

import json
import logging
import signal
import time
from pathlib import Path

from .config import Config
from .pipeline import Pipeline

log = logging.getLogger("soc_triage.worker")


class SpoolWorker:
    def __init__(self, cfg: Config, pipeline: Pipeline):
        self.cfg = cfg
        self.pipeline = pipeline
        self.spool = Path(cfg.spool_dir)
        self.processing = self.spool / "processing"
        self.done = self.spool / "done"
        self.failed = self.spool / "failed"
        for d in (self.spool, self.processing, self.done, self.failed):
            d.mkdir(parents=True, exist_ok=True)
        self._stop = False
        self._last_cleanup = 0.0

    def requeue_stuck(self) -> None:
        for path in self.processing.glob("*.json"):
            path.rename(self.spool / path.name)
            log.warning("Re-queued %s left over from a previous run", path.name)

    def run_once(self) -> int:
        handled = 0
        for path in sorted(self.spool.glob("*.json")):
            if self._stop:
                break
            claimed = self.processing / path.name
            try:
                path.rename(claimed)
            except FileNotFoundError:
                continue
            try:
                raw = json.loads(claimed.read_text(encoding="utf-8"))
                self.pipeline.handle(raw)
                claimed.rename(self.done / path.name)
            except Exception:  # keep the worker alive whatever one alert does
                log.exception("Failed to triage %s; moved to failed/", path.name)
                claimed.rename(self.failed / path.name)
            handled += 1
        return handled

    def cleanup(self) -> None:
        cutoff = time.time() - self.cfg.done_retention_days * 86400
        for path in self.done.glob("*.json"):
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
        self.pipeline.history.prune(older_than_days=30)

    def stop(self, *_args) -> None:
        log.info("Stopping after the current alert")
        self._stop = True

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.requeue_stuck()
        log.info("Watching %s (LLM provider: %s, model: %s)", self.spool,
                 self.cfg.llm.provider, self.cfg.llm.model)
        while not self._stop:
            if self.run_once() == 0:
                time.sleep(self.cfg.poll_interval_seconds)
            if time.time() - self._last_cleanup > 3600:
                self.cleanup()
                self._last_cleanup = time.time()
