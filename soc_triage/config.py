"""Configuration: defaults, JSON config file, secrets file and environment overrides."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Optional

DEFAULT_INTERNAL_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
]

PROVIDERS = {"ollama", "openai", "mock", "mock-gullible"}
CRITICALITY_LEVELS = {"low", "medium", "high"}
WEBHOOK_TYPES = {"slack", "discord", "generic"}
TICKET_SYSTEMS = {"none", "github", "jira", "thehive"}
SEVERITIES = {"Low", "Medium", "High", "Critical"}


@dataclass
class LLMConfig:
    # ollama        -> local model via Ollama's /api/chat (logs never leave your lab)
    # openai        -> any OpenAI-compatible /chat/completions endpoint (cloud, LM Studio, vLLM...)
    # mock          -> no model; deterministic canned analysis (for testing the pipeline)
    # mock-gullible -> a "model" that obeys prompt injection, to demo that the score floor holds
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    base_url: str = "http://127.0.0.1:11434"
    api_key_env: str = "SOC_TRIAGE_API_KEY"  # env var holding the key (provider=openai only)
    timeout_seconds: int = 120
    temperature: float = 0.1
    max_retries: int = 1


@dataclass
class GitHubConfig:
    repo: str = ""                    # "owner/name" - use a PRIVATE repo
    api_url: str = "https://api.github.com"
    labels: list = field(default_factory=lambda: ["soc-triage"])
    token_env: str = "SOC_TRIAGE_GITHUB_TOKEN"


@dataclass
class JiraConfig:
    url: str = ""                     # e.g. https://yourname.atlassian.net
    project_key: str = ""
    issue_type: str = "Task"
    api_version: int = 3              # 3 = Jira Cloud; 2 = Jira Server/Data Center
    labels: list = field(default_factory=lambda: ["soc-triage"])
    email_env: str = "SOC_TRIAGE_JIRA_EMAIL"    # Cloud: email + API token (basic auth)
    token_env: str = "SOC_TRIAGE_JIRA_TOKEN"    # Server/DC: personal access token only


@dataclass
class TheHiveConfig:
    url: str = ""                     # e.g. http://192.168.56.100:9000
    tlp: int = 2
    pap: int = 2
    verify_tls: bool = True
    ca_cert: str = ""
    key_env: str = "SOC_TRIAGE_THEHIVE_KEY"


@dataclass
class TicketingConfig:
    system: str = "none"              # none | github | jira | thehive
    auto_severities: list = field(default_factory=lambda: ["High", "Critical"])
    timeout_seconds: int = 15
    github: GitHubConfig = field(default_factory=GitHubConfig)
    jira: JiraConfig = field(default_factory=JiraConfig)
    thehive: TheHiveConfig = field(default_factory=TheHiveConfig)


@dataclass
class IndexerConfig:
    enabled: bool = False
    url: str = "https://127.0.0.1:9200"
    index: str = "soc-triage-incidents"
    verify_tls: bool = True
    ca_cert: str = "/etc/soc-triage/indexer-root-ca.pem"
    user_env: str = "SOC_TRIAGE_INDEXER_USER"
    password_env: str = "SOC_TRIAGE_INDEXER_PASSWORD"
    timeout_seconds: int = 15


@dataclass
class Config:
    spool_dir: str = "data/spool"
    reports_dir: str = "data/reports"
    db_path: str = "data/history.db"
    secrets_file: str = "/etc/soc-triage/secrets.env"
    min_level: int = 10                     # worker ignores alerts below this level
    correlation_window_minutes: int = 15
    max_llm_raise: int = 15                 # the LLM may raise the score by at most this much
    poll_interval_seconds: float = 2.0
    done_retention_days: int = 7            # processed spool files are kept this long
    internal_networks: list = field(default_factory=lambda: list(DEFAULT_INTERNAL_NETWORKS))
    privileged_accounts: list = field(
        default_factory=lambda: ["root", "admin", "administrator", "ubuntu", "pi"]
    )
    asset_criticality: dict = field(default_factory=dict)  # agent name -> low|medium|high
    webhook_url: str = ""
    webhook_type: str = "slack"
    llm: LLMConfig = field(default_factory=LLMConfig)
    ticketing: TicketingConfig = field(default_factory=TicketingConfig)
    indexer: IndexerConfig = field(default_factory=IndexerConfig)


ENV_OVERRIDES = {
    "SOC_TRIAGE_LLM_PROVIDER": ("llm", "provider"),
    "SOC_TRIAGE_LLM_MODEL": ("llm", "model"),
    "SOC_TRIAGE_LLM_URL": ("llm", "base_url"),
    "SOC_TRIAGE_WEBHOOK_URL": (None, "webhook_url"),
    "SOC_TRIAGE_SPOOL_DIR": (None, "spool_dir"),
    "SOC_TRIAGE_REPORTS_DIR": (None, "reports_dir"),
    "SOC_TRIAGE_DB_PATH": (None, "db_path"),
}


# Settings from features that were removed from the project; ignored if still in a config file.
REMOVED_KEYS = {"active_response", "wazuh_api", "audit_log"}


def _merge(target, data: dict, prefix: str = "") -> None:
    known = {f.name for f in fields(target)}
    for key, value in data.items():
        if key.startswith("_"):  # allows "_comment" keys in JSON
            continue
        if not prefix and key in REMOVED_KEYS:
            logging.getLogger("soc_triage.config").warning(
                "Ignoring config key %r (that feature was removed); you can delete it", key)
            continue
        if key not in known:
            raise ValueError(f"Unknown config key: {prefix}{key}")
        current = getattr(target, key)
        if is_dataclass(current) and isinstance(value, dict):
            _merge(current, value, prefix=f"{prefix}{key}.")
        else:
            setattr(target, key, value)


def load_secrets(path: str) -> None:
    """Load KEY=VALUE lines into the environment (existing variables win)."""
    if not path or not os.path.isfile(path) or not os.access(path, os.R_OK):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            value = value.strip().strip('"').strip("'")
            if key and value:
                os.environ.setdefault(key, value)


def validate(cfg: Config) -> None:
    if cfg.llm.provider not in PROVIDERS:
        raise ValueError(f"llm.provider must be one of {sorted(PROVIDERS)}")
    if not 0 <= int(cfg.max_llm_raise) <= 50:
        raise ValueError("max_llm_raise must be between 0 and 50")
    if cfg.webhook_type not in WEBHOOK_TYPES:
        raise ValueError(f"webhook_type must be one of {sorted(WEBHOOK_TYPES)}")
    for agent, level in cfg.asset_criticality.items():
        if level not in CRITICALITY_LEVELS:
            raise ValueError(f"asset_criticality[{agent!r}] must be low, medium or high")
    for net in cfg.internal_networks:
        ipaddress.ip_network(net, strict=False)  # raises ValueError if malformed
    for sev in cfg.ticketing.auto_severities:
        if sev not in SEVERITIES:
            raise ValueError(f"Unknown severity {sev!r}; use Low, Medium, High or Critical")
    if cfg.ticketing.system not in TICKET_SYSTEMS:
        raise ValueError(f"ticketing.system must be one of {sorted(TICKET_SYSTEMS)}")
    if int(cfg.ticketing.jira.api_version) not in (2, 3):
        raise ValueError("ticketing.jira.api_version must be 2 or 3")


def load_config(path: Optional[str] = None, provider: Optional[str] = None) -> Config:
    cfg = Config()
    path = path or os.environ.get("SOC_TRIAGE_CONFIG")
    if path:
        with open(path, encoding="utf-8") as fh:
            _merge(cfg, json.load(fh))
    load_secrets(os.environ.get("SOC_TRIAGE_SECRETS_FILE", cfg.secrets_file))
    for env, (section, key) in ENV_OVERRIDES.items():
        if env in os.environ:
            setattr(getattr(cfg, section) if section else cfg, key, os.environ[env])
    if provider:
        cfg.llm.provider = provider
    validate(cfg)
    return cfg
