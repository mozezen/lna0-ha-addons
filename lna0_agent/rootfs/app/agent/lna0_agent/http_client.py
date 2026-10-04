"""Small JSON HTTP client with signed node requests."""

from __future__ import annotations

import json
import secrets
import ssl
from typing import Any
from urllib import request
from urllib.error import HTTPError
from urllib.parse import urlparse

from lna0_shared.security import canonical_json, sign_request, utc_iso


class HttpJsonError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def tls_context(ca_pem: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if ca_pem:
        context.load_verify_locations(cadata=ca_pem)
    return context


def reject_insecure_url(url: str, allow_insecure_dev_http: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and allow_insecure_dev_http:
        print(
            '{"level":"warning","message":"insecure development HTTP override is enabled; do not use with real node credentials"}',
            flush=True,
        )
        return
    raise ValueError("Control Plane URL must use https:// unless allow_insecure_dev_http is explicitly enabled for local development")


def post_json(
    url: str,
    data: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    ca_pem: str | None = None,
    allow_insecure_dev_http: bool = False,
) -> dict[str, Any]:
    reject_insecure_url(url, allow_insecure_dev_http)
    body = canonical_json(data)
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    return _send(req, timeout, ca_pem)


def signed_request(
    *,
    method: str,
    url: str,
    credential: str,
    data: dict[str, Any] | None = None,
    timeout: int = 20,
    ca_pem: str | None = None,
    allow_insecure_dev_http: bool = False,
) -> dict[str, Any]:
    reject_insecure_url(url, allow_insecure_dev_http)
    body = canonical_json(data or {}) if method.upper() != "GET" else b""
    parsed = urlparse(url)
    path = parsed.path
    timestamp = utc_iso()
    nonce = secrets.token_urlsafe(24)
    headers = {
        "X-LNA0-Timestamp": timestamp,
        "X-LNA0-Nonce": nonce,
        "X-LNA0-Signature": sign_request(method, path, timestamp, nonce, body, credential),
    }
    if method.upper() == "GET":
        req = request.Request(url, method="GET", headers=headers)
    else:
        req = request.Request(url, data=body, method=method.upper(), headers={"Content-Type": "application/json", **headers})
    return _send(req, timeout, ca_pem)


def _send(req: request.Request, timeout: int, ca_pem: str | None = None) -> dict[str, Any]:
    try:
        context = tls_context(ca_pem) if req.full_url.startswith("https://") else None
        with request.urlopen(req, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        raise HttpJsonError(exc.code, exc.read().decode("utf-8")) from exc
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise HttpJsonError(500, "response was not a JSON object")
    return data
