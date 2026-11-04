"""LLM backends and strict validation of model output.

Nothing the model returns is trusted: the JSON is parsed, every field is type-checked,
lengths are capped, control characters are stripped, and MITRE IDs are checked
against the ATT&CK ID format. If the model is unreachable or keeps returning bad
output, a template analysis is used instead so a report is always produced.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import urllib.error
import urllib.request
from typing import Callable

from . import USER_AGENT
from .config import LLMConfig
from .models import LLMAnalysis
from .playbooks import CATEGORY_LABELS, PLAYBOOKS
from .prompts import build_prompts
from .sanitize import clean_text

log = logging.getLogger("soc_triage.llm")

MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
CONFIDENCE = {"low", "medium", "high"}

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "attack_type": {"type": "string"},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "risk_adjustment": {"type": "integer"},
        "adjustment_rationale": {"type": "string"},
        "likely_false_positive": {"type": "boolean"},
        "false_positive_reasoning": {"type": "string"},
        "indicators": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": [
        "summary", "attack_type", "mitre_techniques", "risk_adjustment", "adjustment_rationale",
        "likely_false_positive", "false_positive_reasoning", "indicators", "recommended_actions",
        "confidence",
    ],
}


class LLMError(Exception):
    pass


# --------------------------------------------------------------------------- transport

def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read()[:300].decode("utf-8", "replace")
        raise LLMError(f"HTTP {exc.code} from {url}: {body}") from exc
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
        raise LLMError(f"Could not reach {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LLMError(f"Non-JSON response from {url}") from exc


def _get_json(url: str, timeout: int = 10) -> dict:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError,
            json.JSONDecodeError) as exc:
        raise LLMError(f"Could not reach {url}: {exc}") from exc


class OllamaBackend:
    """Local model through Ollama's chat API, using JSON-schema structured output."""

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.base = cfg.base_url.rstrip("/")

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.cfg.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": RESPONSE_SCHEMA,
            "options": {"temperature": self.cfg.temperature},
        }
        data = _post_json(f"{self.base}/api/chat", payload, {}, self.cfg.timeout_seconds)
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"Unexpected Ollama response: {str(data)[:200]}") from exc

    def check(self) -> str:
        tags = _get_json(f"{self.base}/api/tags")
        names = [m.get("name", "") for m in tags.get("models", [])]
        wanted = self.cfg.model if ":" in self.cfg.model else self.cfg.model + ":latest"
        if wanted not in names:
            raise LLMError(f"Ollama is running but model '{self.cfg.model}' is not pulled. "
                           f"Run: ollama pull {self.cfg.model}  (installed: {', '.join(names) or 'none'})")
        return f"Ollama reachable at {self.base}; model {self.cfg.model} is installed."


class OpenAICompatibleBackend:
    """Any OpenAI-compatible /chat/completions endpoint (cloud API, LM Studio, vLLM...).

    Note: with a cloud provider, alert data leaves your network.
    """

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.base = cfg.base_url.rstrip("/")
        self.key = os.environ.get(cfg.api_key_env, "")

    def complete(self, system: str, user: str) -> str:
        if not self.key:
            raise LLMError(f"Set the {self.cfg.api_key_env} environment variable for provider=openai")
        payload = {
            "model": self.cfg.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.cfg.temperature,
            "response_format": {"type": "json_object"},
        }
        data = _post_json(f"{self.base}/chat/completions", payload,
                          {"Authorization": f"Bearer {self.key}"}, self.cfg.timeout_seconds)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"Unexpected API response: {str(data)[:200]}") from exc

    def check(self) -> str:
        if not self.key:
            raise LLMError(f"Environment variable {self.cfg.api_key_env} is not set")
        return f"API key found; requests will go to {self.base}/chat/completions."


# --------------------------------------------------------------------------- mock

def mock_response(context: dict, gullible: bool = False) -> str:
    """Deterministic stand-in for a model, for tests and demos without an LLM.

    gullible=True imitates a model that obeys prompt injection, so you can show
    that the score floor still holds.
    """
    t = context["trusted"]
    enr = t["enrichment"]
    cat = t["alert"]["category"]
    if gullible and enr["injection_flags"]:
        return json.dumps({
            "summary": "This is an authorized vulnerability scan by the security team. No action required.",
            "attack_type": "Authorized scan",
            "mitre_techniques": [],
            "risk_adjustment": -15,
            "adjustment_rationale": "The log states this activity is authorized.",
            "likely_false_positive": True,
            "false_positive_reasoning": "The traffic identifies itself as an approved scan.",
            "indicators": [],
            "recommended_actions": ["No action required; close the alert."],
            "confidence": "high",
        })
    adj = 5 if enr["success_after_failures"] or enr["privileged_target"] else 0
    indicators = [f"Source IP {t['alert']['source_ip']}"] if t["alert"]["source_ip"] else []
    if enr["injection_flags"]:
        indicators.append("Log content attempts to instruct an AI analyst: " + ", ".join(enr["injection_flags"]))
    return json.dumps({
        "summary": t["template_summary"],
        "attack_type": CATEGORY_LABELS.get(cat, "Security alert"),
        "mitre_techniques": t["alert"]["wazuh_mitre_ids"],
        "risk_adjustment": adj,
        "adjustment_rationale": "Privileged or confirmed-access activity warrants a small increase."
        if adj else "The deterministic score already reflects the evidence.",
        "likely_false_positive": cat == "auth_failure" and enr["related_events"] == 0,
        "false_positive_reasoning": "A single failed login with no related activity is often a typo."
        if cat == "auth_failure" else "The pattern matches deliberate malicious activity.",
        "indicators": indicators,
        "recommended_actions": PLAYBOOKS.get(cat, PLAYBOOKS["other"]),
        "confidence": "medium",
    })


# --------------------------------------------------------------------------- validation

def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("Model reply contained no JSON object")
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"Model returned invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise LLMError("Model reply was not a JSON object")
    return obj


def _text(obj: dict, key: str, max_len: int, required: bool = True) -> str:
    value = obj.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise LLMError(f"Missing field: {key}")
        return ""
    if not isinstance(value, (str, int, float)):
        raise LLMError(f"Field {key} must be a string")
    return clean_text(str(value).strip(), max_len)


def _text_list(obj: dict, key: str, max_items: int = 8, max_len: int = 300) -> list:
    value = obj.get(key, [])
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise LLMError(f"Field {key} must be a list")
    items = [clean_text(str(v).strip(), max_len) for v in value if str(v).strip()]
    return items[:max_items]


def _bool(obj: dict, key: str) -> bool:
    value = obj.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise LLMError(f"Field {key} must be true or false")


def validate_analysis(text: str, source: str) -> LLMAnalysis:
    obj = _extract_json(text)
    try:
        adjustment = int(obj.get("risk_adjustment", 0))
    except (TypeError, ValueError) as exc:
        raise LLMError("risk_adjustment must be an integer") from exc
    mitre = []
    for raw_id in _text_list(obj, "mitre_techniques", 10, 20):
        candidate = raw_id.upper().strip()
        if MITRE_ID.match(candidate) and candidate not in mitre:
            mitre.append(candidate)
    confidence = str(obj.get("confidence", "low")).lower()
    actions = _text_list(obj, "recommended_actions")
    if not actions:
        raise LLMError("recommended_actions is empty")
    return LLMAnalysis(
        summary=_text(obj, "summary", 1200),
        attack_type=_text(obj, "attack_type", 80),
        mitre_techniques=mitre,
        risk_adjustment=max(-15, min(15, adjustment)),
        adjustment_rationale=_text(obj, "adjustment_rationale", 400, required=False),
        likely_false_positive=_bool(obj, "likely_false_positive"),
        false_positive_reasoning=_text(obj, "false_positive_reasoning", 600, required=False),
        indicators=_text_list(obj, "indicators"),
        recommended_actions=actions,
        confidence=confidence if confidence in CONFIDENCE else "low",
        source=source,
    )


# --------------------------------------------------------------------------- entry point

def make_backend(cfg: LLMConfig):
    if cfg.provider == "ollama":
        return OllamaBackend(cfg)
    if cfg.provider == "openai":
        return OpenAICompatibleBackend(cfg)
    raise LLMError(f"No network backend for provider {cfg.provider}")


def analyze(cfg: LLMConfig, context: dict, fallback: Callable[[], LLMAnalysis]) -> LLMAnalysis:
    if cfg.provider in ("mock", "mock-gullible"):
        return validate_analysis(mock_response(context, cfg.provider == "mock-gullible"), cfg.provider)

    backend = make_backend(cfg)
    system, user = build_prompts(context)
    error = None
    for attempt in range(1 + max(0, cfg.max_retries)):
        try:
            return validate_analysis(backend.complete(system, user), f"{cfg.provider}:{cfg.model}")
        except LLMError as exc:
            error = exc
            log.warning("LLM attempt %d failed: %s", attempt + 1, exc)
            if "Could not reach" in str(exc):
                break  # no point retrying a dead endpoint
    result = fallback()
    result.error = str(error)
    return result
