"""Small JSON-over-HTTPS client (standard library only) shared by the integrations."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

from . import USER_AGENT


class HTTPError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def ssl_context(verify: bool = True, ca_cert: str = "") -> ssl.SSLContext:
    if ca_cert and not os.path.isfile(ca_cert):
        raise HTTPError(f"CA certificate not found: {ca_cert}")
    ctx = ssl.create_default_context(cafile=ca_cert or None)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def basic_auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")


def request(method: str, url: str, *, payload: Any = None, headers: Optional[dict] = None,
            verify: bool = True, ca_cert: str = "", timeout: int = 15) -> tuple:
    """Send a request; return (status, parsed JSON or text). Raises HTTPError on failure."""
    data = None
    all_headers = {"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    if payload is not None:
        data = json.dumps(payload, default=str).encode("utf-8")
        all_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
    context = ssl_context(verify, ca_cert) if url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read()[:500].decode("utf-8", "replace")
        raise HTTPError(f"{method} {url} -> HTTP {exc.code}: {body}", exc.code, body) from exc
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError) as exc:
        raise HTTPError(f"{method} {url} failed: {exc}") from exc
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def env_value(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise HTTPError(f"Environment variable {name} is not set (put it in the secrets file)")
    return value
