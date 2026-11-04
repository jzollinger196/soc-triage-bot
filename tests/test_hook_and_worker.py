"""End to end: Wazuh hook script -> spool directory -> worker -> report."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from soc_triage.config import load_config
from soc_triage.history import History
from soc_triage.pipeline import Pipeline
from soc_triage.worker import SpoolWorker

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "wazuh" / "custom-soc-triage.py"


class HookAndWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.spool = self.tmp / "spool"
        self.spool.mkdir()
        self.env = {**os.environ, "SOC_TRIAGE_SPOOL_DIR": str(self.spool),
                    "SOC_TRIAGE_HOOK_LOG": str(self.tmp / "integrations.log")}

    def run_hook(self, alert_path):
        # Wazuh passes: <alert file> <api_key> <hook_url>
        return subprocess.run([sys.executable, str(HOOK), str(alert_path), "", ""],
                              env=self.env, capture_output=True, text=True)

    def test_hook_spools_alert_and_worker_triages_it(self):
        result = self.run_hook(ROOT / "samples" / "02_ssh_root_bruteforce.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        spooled = list(self.spool.glob("*.json"))
        self.assertEqual(len(spooled), 1)
        if os.name == "posix":  # Unix permissions don't exist on Windows
            self.assertEqual(oct(spooled[0].stat().st_mode & 0o777), "0o660")

        cfg = load_config(str(ROOT / "config.dev.json"), provider="mock")
        cfg.spool_dir = str(self.spool)
        cfg.reports_dir = str(self.tmp / "reports")
        worker = SpoolWorker(cfg, Pipeline(cfg, history=History(":memory:")))
        self.assertEqual(worker.run_once(), 1)
        self.assertEqual(len(list((self.spool / "done").glob("*.json"))), 1)
        self.assertEqual(len(list((self.tmp / "reports").rglob("INC-*.md"))), 1)

    def test_hook_rejects_non_alert(self):
        bad = self.tmp / "bad.alert"
        bad.write_text("not json")
        self.assertEqual(self.run_hook(bad).returncode, 1)
        self.assertEqual(list(self.spool.glob("*.json")), [])
        self.assertIn("cannot read alert", (self.tmp / "integrations.log").read_text(encoding="utf-8"))

    def test_worker_moves_broken_alert_to_failed(self):
        (self.spool / "1-broken.json").write_text(json.dumps({"rule": {}}))
        cfg = load_config(str(ROOT / "config.dev.json"), provider="mock")
        cfg.spool_dir = str(self.spool)
        cfg.reports_dir = str(self.tmp / "reports")
        worker = SpoolWorker(cfg, Pipeline(cfg, history=History(":memory:")))
        worker.run_once()
        self.assertTrue((self.spool / "failed" / "1-broken.json").exists())

    def test_requeues_files_left_in_processing(self):
        cfg = load_config(str(ROOT / "config.dev.json"), provider="mock")
        cfg.spool_dir = str(self.spool)
        worker = SpoolWorker(cfg, Pipeline(cfg, history=History(":memory:")))
        (self.spool / "processing" / "2-stuck.json").write_text("{}")
        worker.requeue_stuck()
        self.assertTrue((self.spool / "2-stuck.json").exists())


if __name__ == "__main__":
    unittest.main()
