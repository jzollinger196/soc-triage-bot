"""Exercise the Ollama backend against a fake local HTTP server."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from soc_triage.config import LLMConfig
from soc_triage.llm import analyze
from soc_triage.models import LLMAnalysis
from soc_triage.pipeline import Pipeline
from soc_triage.history import History
from soc_triage.config import load_config
from soc_triage.parser import parse_wazuh_alert

ROOT = Path(__file__).resolve().parent.parent

GOOD_REPLY = {
    "summary": "Brute force against root from 192.168.56.10.", "attack_type": "SSH brute force",
    "mitre_techniques": ["T1110.001"], "risk_adjustment": 4, "adjustment_rationale": "root targeted",
    "likely_false_positive": False, "false_positive_reasoning": "Many rapid failures.",
    "indicators": ["192.168.56.10"], "recommended_actions": ["Block 192.168.56.10"], "confidence": "high",
}


class FakeOllama(BaseHTTPRequestHandler):
    reply = GOOD_REPLY
    requests = []
    headers = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOllama.requests.append((self.path, body))
        FakeOllama.headers.append(dict(self.headers))
        content = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        data = json.dumps({"message": {"role": "assistant", "content": content}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        data = json.dumps({"models": [{"name": "llama3.1:8b"}]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def fallback():
    return LLMAnalysis("fallback summary", "x", [], 0, "", False, "", [], ["playbook step"], "low", "fallback")


class OllamaBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeOllama.requests.clear()
        FakeOllama.headers.clear()
        FakeOllama.reply = GOOD_REPLY
        cfg = load_config(str(ROOT / "config.dev.json"), provider="mock")
        raw = json.loads((ROOT / "samples" / "05_web_scan_with_prompt_injection.json").read_text(encoding="utf-8"))
        alert = parse_wazuh_alert(raw)
        p = Pipeline(cfg, history=History(":memory:"))
        enr = p.enrich(alert)
        self.context = p.build_context(alert, enr, 75, [])
        self.cfg = LLMConfig(provider="ollama", model="llama3.1:8b", base_url=self.url, timeout_seconds=5)

    def test_good_reply_is_used(self):
        an = analyze(self.cfg, self.context, fallback)
        self.assertEqual(an.source, "ollama:llama3.1:8b")
        self.assertEqual(an.risk_adjustment, 4)
        path, body = FakeOllama.requests[0]
        self.assertEqual(path, "/api/chat")
        self.assertEqual(body["format"]["type"], "object")   # structured output schema sent
        self.assertFalse(body["stream"])
        user_prompt = body["messages"][1]["content"]
        # Attacker text is inside the untrusted block only, and cannot contain raw < or >.
        untrusted = user_prompt.split("<untrusted_log_data>")[1].split("</untrusted_log_data>")[0]
        self.assertIn("Ignore all previous instructions", untrusted)
        self.assertNotIn("<", untrusted)
        trusted = user_prompt.split("<trusted_context>")[1].split("</trusted_context>")[0]
        self.assertNotIn("Ignore all previous instructions", trusted)

    def test_garbage_reply_retries_then_falls_back(self):
        FakeOllama.reply = "Sure! This alert looks bad."
        an = analyze(self.cfg, self.context, fallback)
        self.assertEqual(an.source, "fallback")
        self.assertIn("no JSON object", an.error)
        self.assertEqual(len(FakeOllama.requests), 2)  # first try + 1 retry

    def test_unreachable_server_falls_back_without_retry(self):
        cfg = LLMConfig(provider="ollama", base_url="http://127.0.0.1:9", timeout_seconds=2)
        an = analyze(cfg, self.context, fallback)
        self.assertEqual(an.source, "fallback")
        self.assertIn("Could not reach", an.error)

    def test_requests_send_a_user_agent(self):
        # Cloudflare-fronted APIs (e.g. Groq) return HTTP 403 / error 1010 for Python's default agent
        analyze(self.cfg, self.context, fallback)
        from tests.fakes import FakeService
        from soc_triage.httpjson import request
        svc = FakeService()
        svc.route("GET", "/", (200, {"ok": True}))
        try:
            request("GET", svc.url + "/")
            self.assertTrue(svc.requests[0]["headers"]["User-Agent"].startswith("soc-triage-bot/"))
        finally:
            svc.close()
        self.assertTrue(FakeOllama.headers[0]["User-Agent"].startswith("soc-triage-bot/"))

    def test_check_reports_installed_model(self):
        from soc_triage.llm import OllamaBackend, LLMError
        self.assertIn("installed", OllamaBackend(self.cfg).check())
        missing = LLMConfig(provider="ollama", model="mistral", base_url=self.url)
        with self.assertRaises(LLMError):
            OllamaBackend(missing).check()


if __name__ == "__main__":
    unittest.main()
