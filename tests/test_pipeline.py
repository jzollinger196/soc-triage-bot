import json
import tempfile
import unittest
from pathlib import Path

from soc_triage.config import load_config
from soc_triage.history import History
from soc_triage.llm import LLMError, validate_analysis
from soc_triage.pipeline import Pipeline
from soc_triage.report import render_markdown
from soc_triage.scoring import apply_llm_adjustment, severity_for

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def make_pipeline(provider="mock"):
    tmp = tempfile.mkdtemp()
    cfg = load_config(str(ROOT / "config.dev.json"), provider=provider)
    cfg.reports_dir = str(Path(tmp) / "reports")
    return Pipeline(cfg, history=History(":memory:")), cfg


class ScoringTests(unittest.TestCase):
    def test_llm_can_only_raise(self):
        self.assertEqual(apply_llm_adjustment(-15, 15), 0)
        self.assertEqual(apply_llm_adjustment(10, 15), 10)
        self.assertEqual(apply_llm_adjustment(40, 15), 15)

    def test_severity_bands(self):
        self.assertEqual([severity_for(s) for s in (0, 29, 30, 54, 55, 79, 80, 100)],
                         ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"])


class ValidationTests(unittest.TestCase):
    GOOD = {
        "summary": "SSH brute force.", "attack_type": "SSH brute force",
        "mitre_techniques": ["T1110.001", "t1021.004", "T99", "made-up", "T1110.001"],
        "risk_adjustment": 99, "adjustment_rationale": "x", "likely_false_positive": "false",
        "false_positive_reasoning": "y", "indicators": ["192.168.56.10"],
        "recommended_actions": ["Block the IP"], "confidence": "VERY HIGH",
    }

    def test_cleans_and_clamps(self):
        an = validate_analysis("```json\n" + json.dumps(self.GOOD) + "\n```", "test")
        self.assertEqual(an.mitre_techniques, ["T1110.001", "T1021.004"])
        self.assertEqual(an.risk_adjustment, 15)
        self.assertFalse(an.likely_false_positive)
        self.assertEqual(an.confidence, "low")

    def test_rejects_bad_output(self):
        for bad in ["I think this is bad", "[1,2]", json.dumps({**self.GOOD, "summary": ""}),
                    json.dumps({**self.GOOD, "recommended_actions": []}),
                    json.dumps({**self.GOOD, "risk_adjustment": "lots"})]:
            with self.assertRaises(LLMError):
                validate_analysis(bad, "test")


class PipelineTests(unittest.TestCase):
    def run_all(self, provider="mock"):
        pipeline, _ = make_pipeline(provider)
        names = ["06_benign_single_failed_login.json", "01_ssh_invalid_user_bruteforce.json",
                 "02_ssh_root_bruteforce.json", "03_ssh_login_success_after_bruteforce.json",
                 "04_suricata_syn_flood.json", "05_web_scan_with_prompt_injection.json",
                 "07_windows_rdp_bruteforce_external.json"]
        return {n: pipeline.process(load(n), force=True) for n in names}

    def test_success_after_bruteforce_is_critical(self):
        inc = self.run_all()["03_ssh_login_success_after_bruteforce.json"]
        self.assertEqual(inc.alert.category, "account_compromise")
        self.assertTrue(inc.enrichment.success_after_failures)
        self.assertEqual(inc.enrichment.prior_failures, 2)
        self.assertEqual(inc.severity, "Critical")

    def test_wazuh_40112_is_critical_account_compromise(self):
        pipeline, _ = make_pipeline()
        raw = load("03_ssh_login_success_after_bruteforce.json")
        raw["rule"].update({"id": "40112", "level": 12, "groups": ["syslog", "attacks"],
                            "description": "Multiple authentication failures followed by a success."})
        raw["id"] = "wazuh-40112"
        inc = pipeline.process(raw)  # no earlier alerts in history: relies on Wazuh's correlation
        self.assertEqual(inc.alert.category, "account_compromise")
        self.assertEqual(inc.severity, "Critical")
        self.assertIn("correlated by Wazuh rule 40112", inc.analysis.summary)
        self.assertTrue(any("40112 correlated" in r for r, _ in inc.score.breakdown))

    def test_lone_login_success_is_not_an_incident(self):
        pipeline, _ = make_pipeline()
        self.assertIsNone(pipeline.process(load("03_ssh_login_success_after_bruteforce.json")))

    def test_low_level_skipped_unless_forced(self):
        pipeline, _ = make_pipeline()
        self.assertIsNone(pipeline.process(load("06_benign_single_failed_login.json")))
        self.assertEqual(pipeline.process(load("06_benign_single_failed_login.json"), force=True).severity, "Low")

    def test_external_source_and_privileged_account(self):
        inc = self.run_all()["07_windows_rdp_bruteforce_external.json"]
        self.assertTrue(inc.enrichment.src_is_external)
        self.assertTrue(inc.enrichment.privileged_target)

    def test_prompt_injection_cannot_lower_score(self):
        honest = self.run_all("mock")["05_web_scan_with_prompt_injection.json"]
        fooled = self.run_all("mock-gullible")["05_web_scan_with_prompt_injection.json"]
        self.assertEqual(fooled.analysis.risk_adjustment, -15)
        self.assertTrue(fooled.analysis.likely_false_positive)
        self.assertEqual(fooled.final_score, honest.score.base_score)
        self.assertEqual(fooled.severity, "High")
        md = render_markdown(fooled)
        self.assertIn("may have been manipulated", md)
        self.assertIn("Standard playbook", md)

    def test_report_and_json_written(self):
        pipeline, cfg = make_pipeline()
        inc, md_path = pipeline.handle(load("02_ssh_root_bruteforce.json"), send=False)
        self.assertTrue(md_path.exists())
        data = json.loads(md_path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(data["incident_id"], inc.incident_id)
        self.assertNotIn("raw", data["alert"])

    def test_markdown_fence_cannot_be_broken(self):
        pipeline, _ = make_pipeline()
        raw = load("02_ssh_root_bruteforce.json")
        raw["full_log"] = "evil ```\n# Fake heading\n```"
        md = render_markdown(pipeline.process(raw))
        self.assertIn("````text", md)


if __name__ == "__main__":
    unittest.main()
