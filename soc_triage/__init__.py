"""AI-assisted SOC alert triage for Wazuh.

Pipeline: Wazuh alert JSON -> parse -> enrich/correlate -> deterministic risk score
-> LLM analysis (validated, can only raise the score) -> Markdown/JSON incident report.
"""

__version__ = "1.0.0"

# Sent on every outbound HTTP request. Some APIs sit behind Cloudflare, which rejects
# Python's default "Python-urllib" User-Agent with HTTP 403 (error code 1010).
USER_AGENT = f"soc-triage-bot/{__version__}"
