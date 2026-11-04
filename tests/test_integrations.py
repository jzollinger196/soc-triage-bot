"""Ticketing, indexer and dashboard, each against a fake service."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from soc_triage.cli import main as cli_main
from soc_triage.config import load_config
from soc_triage.history import History
from soc_triage.indexer import INDEX_SETTINGS, Indexer, incident_document
from soc_triage.pipeline import Pipeline
from soc_triage.ticketing import GitHubTicketer

from tests.fakes import FakeService

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
ORDER = ["06_benign_single_failed_login.json", "01_ssh_invalid_user_bruteforce.json",
         "02_ssh_root_bruteforce.json", "03_ssh_login_success_after_bruteforce.json",
         "04_suricata_syn_flood.json", "05_web_scan_with_prompt_injection.json",
         "07_windows_rdp_bruteforce_external.json"]

SECRETS = {
    "SOC_TRIAGE_GITHUB_TOKEN": "ghp_test", "SOC_TRIAGE_JIRA_EMAIL": "me@example.com",
    "SOC_TRIAGE_JIRA_TOKEN": "jt", "SOC_TRIAGE_THEHIVE_KEY": "hk",
    "SOC_TRIAGE_INDEXER_USER": "admin", "SOC_TRIAGE_INDEXER_PASSWORD": "ipw",
}


def load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


class Base(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        os.environ.update(SECRETS)
        self.tmp = Path(tempfile.mkdtemp())
        self.fake = FakeService()
        self.cfg = load_config(str(ROOT / "config.dev.json"), provider="mock")
        self.cfg.reports_dir = str(self.tmp / "reports")
        self.cfg.db_path = str(self.tmp / "history.db")
        self.cfg_path = self.tmp / "config.json"

    def tearDown(self):
        self.fake.close()
        os.environ.clear()
        os.environ.update(self._env)

    def write_cfg(self):
        """Persist the in-memory config so CLI commands see the same settings."""
        from dataclasses import asdict
        self.cfg_path.write_text(json.dumps(asdict(self.cfg)))
        return str(self.cfg_path)

    def run_samples(self, send=True):
        pipeline = Pipeline(self.cfg, history=History(self.cfg.db_path))
        return {n: pipeline.handle(load(n), force=True, send=send) for n in ORDER}


class ConfigTests(Base):
    def test_lab_config_and_wazuh_blocks_are_valid(self):
        import xml.dom.minidom
        cfg = load_config(str(ROOT / "config.lab.json"))
        self.assertEqual(cfg.llm.provider, "openai")
        self.assertEqual(cfg.asset_criticality, {"wazuh-lab": "high"})
        self.assertIn("labadmin", cfg.privileged_accounts)
        for name in ["ossec-integration-block.xml", "ossec-authlog-block.xml"]:
            xml.dom.minidom.parseString((ROOT / "wazuh" / name).read_text(encoding="utf-8"))

    def test_removed_settings_are_ignored(self):
        old = {"active_response": {"enabled": True}, "wazuh_api": {"url": "x"}, "audit_log": "a.log"}
        self.cfg_path.write_text(json.dumps(old))
        with self.assertLogs("soc_triage.config", level="WARNING") as logs:
            load_config(str(self.cfg_path))
        self.assertEqual(len(logs.output), 3)


class TicketingTests(Base):
    def test_github_issue_created_once_with_mentions_neutralised(self):
        self.cfg.ticketing.system = "github"
        self.cfg.ticketing.github.repo = "me/soc-lab"
        self.cfg.ticketing.github.api_url = self.fake.url
        self.fake.route("POST", "/repos/me/soc-lab/issues", lambda p, b: (
            201, {"number": 7, "html_url": "https://github.com/me/soc-lab/issues/7"}))
        raw = load("07_windows_rdp_bruteforce_external.json")
        raw["full_log"] += " ping @security-team"
        pipeline = Pipeline(self.cfg, history=History(self.cfg.db_path))
        inc, md_path = pipeline.handle(raw)
        self.assertEqual(inc.ticket["url"], "https://github.com/me/soc-lab/issues/7")
        req = self.fake.calls("POST", "/repos/me/soc-lab/issues")[0]
        self.assertEqual(req["headers"]["Authorization"], "Bearer ghp_test")
        self.assertIn("severity-critical", req["body"]["labels"])
        self.assertIn("@​security-team", req["body"]["body"])
        self.assertNotIn("@security-team", req["body"]["body"])
        self.assertIn("Ticket: [github 7]", md_path.read_text(encoding="utf-8"))
        pipeline.handle(raw)  # same incident again -> no second issue
        self.assertEqual(len(self.fake.calls("POST", "/repos/me/soc-lab/issues")), 1)

    def test_low_severity_not_auto_ticketed(self):
        self.cfg.ticketing.system = "github"
        self.cfg.ticketing.github.repo = "me/soc-lab"
        self.cfg.ticketing.github.api_url = self.fake.url
        Pipeline(self.cfg, history=History(self.cfg.db_path)).handle(
            load("06_benign_single_failed_login.json"), force=True)
        self.assertEqual(self.fake.requests, [])

    def test_jira_cloud_adf(self):
        self.cfg.ticketing.system = "jira"
        self.cfg.ticketing.jira.url = self.fake.url
        self.cfg.ticketing.jira.project_key = "SOC"
        self.fake.route("POST", "/rest/api/3/issue", (201, {"id": "10001", "key": "SOC-12"}))
        inc, _ = Pipeline(self.cfg, history=History(self.cfg.db_path)).handle(
            load("07_windows_rdp_bruteforce_external.json"))
        self.assertEqual(inc.ticket["url"], f"{self.fake.url}/browse/SOC-12")
        req = self.fake.calls("POST", "/rest/api/3/issue")[0]
        fields = req["body"]["fields"]
        self.assertEqual(fields["project"], {"key": "SOC"})
        self.assertEqual(fields["description"]["type"], "doc")
        kinds = [n["type"] for n in fields["description"]["content"]]
        self.assertIn("codeBlock", kinds)
        self.assertTrue(all(" " not in label for label in fields["labels"]))
        self.assertEqual(req["headers"]["Authorization"],
                         "Basic " + base64.b64encode(b"me@example.com:jt").decode())

    def test_jira_server_v2_wiki_markup(self):
        self.cfg.ticketing.system = "jira"
        self.cfg.ticketing.jira.url = self.fake.url
        self.cfg.ticketing.jira.project_key = "SOC"
        self.cfg.ticketing.jira.api_version = 2
        os.environ.pop("SOC_TRIAGE_JIRA_EMAIL")
        self.fake.route("POST", "/rest/api/2/issue", (201, {"key": "SOC-3"}))
        raw = load("02_ssh_root_bruteforce.json")
        raw["full_log"] += " {noformat} h1. injected"
        Pipeline(self.cfg, history=History(self.cfg.db_path)).handle(raw)
        req = self.fake.calls("POST", "/rest/api/2/issue")[0]
        desc = req["body"]["fields"]["description"]
        self.assertEqual(desc.count("{noformat}"), 2)
        self.assertEqual(req["headers"]["Authorization"], "Bearer jt")

    def test_thehive_case_with_observables(self):
        self.cfg.ticketing.system = "thehive"
        self.cfg.ticketing.thehive.url = self.fake.url
        self.fake.route("POST", "/api/v1/case/~4096/observable", (201, [{"_id": "~1"}]))
        self.fake.route("POST", "/api/v1/case", (201, {"_id": "~4096", "number": 12}))
        self.run_samples()
        case = self.fake.calls("POST", "/api/v1/case")[0]
        self.assertEqual(case["headers"]["Authorization"], "Bearer hk")
        severities = [c["body"]["severity"] for c in self.fake.calls("POST", "/api/v1/case")
                      if c["path"] == "/api/v1/case"]
        self.assertIn(4, severities)
        obs = [c["body"] for c in self.fake.calls("POST", "/api/v1/case/~4096/observable")]
        self.assertIn({"dataType": "ip", "data": "192.168.56.10", "ioc": True,
                       "message": "Source of the activity", "tags": ["attacker"], "tlp": 2, "pap": 2},
                      obs)

    def test_ticket_failure_does_not_break_triage(self):
        self.cfg.ticketing.system = "github"
        self.cfg.ticketing.github.repo = "me/soc-lab"
        self.cfg.ticketing.github.api_url = self.fake.url
        self.fake.route("POST", "/repos", (500, {"message": "boom"}))
        inc, md = Pipeline(self.cfg, history=History(self.cfg.db_path)).handle(
            load("07_windows_rdp_bruteforce_external.json"))
        self.assertIsNone(inc.ticket)
        self.assertTrue(md.exists())

    def test_github_neutralise(self):
        self.assertEqual(GitHubTicketer.neutralise("hi @bob and a@b.c"), "hi @​bob and a@​b.c")


class IndexerTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg.indexer.enabled = True
        self.cfg.indexer.url = self.fake.url
        self.cfg.indexer.ca_cert = ""
        self.fake.route("HEAD", "/soc-triage-incidents", (404, None))
        self.fake.route("PUT", "/soc-triage-incidents/_doc/", (201, {"result": "created"}))
        self.fake.route("PUT", "/soc-triage-incidents", (200, {"acknowledged": True}))
        self.fake.route("POST", "/soc-triage-incidents/_update/", (200, {"result": "updated"}))

    def test_index_created_then_documents_indexed(self):
        self.run_samples()
        create = [c for c in self.fake.calls("PUT") if c["path"] == "/soc-triage-incidents"]
        self.assertEqual(len(create), 1)
        self.assertEqual(create[0]["body"]["mappings"]["properties"]["src_ip"], {"type": "ip"})
        docs = self.fake.calls("PUT", "/soc-triage-incidents/_doc/")
        self.assertEqual(len(docs), 7)
        compromise = [d["body"] for d in docs if d["body"]["category"] == "account_compromise"][0]
        self.assertEqual(compromise["severity_rank"], 4)
        self.assertTrue(docs[0]["headers"]["Authorization"].startswith("Basic "))

    def test_backfill_via_cli(self):
        self.run_samples(send=False)
        self.assertEqual(cli_main(["--config", self.write_cfg(), "index"]), 0)
        self.assertEqual(len(self.fake.calls("PUT", "/soc-triage-incidents/_doc/")), 7)

    def test_manual_ticket_updates_dashboard(self):
        self.cfg.ticketing.system = "github"
        self.cfg.ticketing.github.repo = "me/soc-lab"
        self.cfg.ticketing.github.api_url = self.fake.url
        self.fake.route("POST", "/repos/me/soc-lab/issues", (201, {"number": 3, "html_url": "https://gh/3"}))
        results = self.run_samples(send=False)
        low = results["06_benign_single_failed_login.json"][0]
        self.assertEqual(cli_main(["--config", self.write_cfg(), "ticket", low.incident_id]), 0)
        upd = self.fake.calls("POST", "/soc-triage-incidents/_update/")[0]
        self.assertEqual(upd["body"], {"doc": {"ticket_system": "github", "ticket_url": "https://gh/3"}})

    def test_indexer_down_does_not_break_triage(self):
        self.cfg.indexer.url = "http://127.0.0.1:9"
        inc, md = Pipeline(self.cfg, history=History(self.cfg.db_path)).handle(
            load("02_ssh_root_bruteforce.json"))
        self.assertTrue(md.exists())

    def test_document_fields_are_all_mapped(self):
        inc, _ = Pipeline(self.cfg, history=History(":memory:")).handle(
            load("02_ssh_root_bruteforce.json"), send=False)
        doc = incident_document(inc.to_dict())
        mapped = set(INDEX_SETTINGS["mappings"]["properties"])
        self.assertEqual(set(doc) - mapped, set())


class DashboardTests(unittest.TestCase):
    def test_saved_objects_are_consistent(self):
        lines = (ROOT / "dashboard" / "soc-triage-dashboard.ndjson").read_text(encoding="utf-8").splitlines()
        objs = [json.loads(l) for l in lines]
        ids = {(o["type"], o["id"]) for o in objs}
        mapped = set(INDEX_SETTINGS["mappings"]["properties"])
        for o in objs:
            for ref in o["references"]:
                self.assertIn((ref["type"], ref["id"]), ids, f"{o['id']} -> {ref}")
            if o["type"] == "visualization":
                vis = json.loads(o["attributes"]["visState"])
                for agg in vis["aggs"]:
                    field = agg["params"].get("field")
                    if field:
                        self.assertIn(field, mapped, f"{o['id']} uses unmapped field {field}")
                json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            if o["type"] == "dashboard":
                panels = json.loads(o["attributes"]["panelsJSON"])
                self.assertEqual(len(panels), len(o["references"]))
            if o["type"] == "search":
                for col in o["attributes"]["columns"]:
                    self.assertIn(col, mapped)

    def test_ndjson_is_up_to_date(self):
        import subprocess, sys
        before = (ROOT / "dashboard" / "soc-triage-dashboard.ndjson").read_text(encoding="utf-8")
        subprocess.run([sys.executable, str(ROOT / "dashboard" / "build_dashboard.py")],
                       check=True, capture_output=True)
        self.assertEqual(before, (ROOT / "dashboard" / "soc-triage-dashboard.ndjson").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
