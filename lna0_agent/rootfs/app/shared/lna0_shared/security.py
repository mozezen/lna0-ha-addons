"""Security primitives shared by the Control Plane and Agent."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

SECRET_FIELD_FRAGMENTS = (
    "authorization",
    "credential",
    "secret",
    "token",
    "password",
    "private_key",
)


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def utc_iso(value: datetime | None = None) -> str:
    return (value or now_utc()).astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def generate_secret(prefix: str, bytes_len: int = 32) -> str:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(bytes_len)).decode("ascii")
    return f"{prefix}{raw.rstrip('=')}"


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def hash_admin_password(password: str, *, iterations: int = 310_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def verify_admin_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = base64.urlsafe_b64decode(salt_raw + "=" * (-len(salt_raw) % 4))
        expected = base64.urlsafe_b64decode(digest_raw + "=" * (-len(digest_raw) % 4))
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signature_payload(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = request_body_hash(body)
    payload = "\n".join([method.upper(), path, timestamp, nonce, body_hash])
    return payload.encode("utf-8")


def sign_request(method: str, path: str, timestamp: str, nonce: str, body: bytes, credential: str) -> str:
    digest = hmac.new(
        credential.encode("utf-8"),
        signature_payload(method, path, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def verify_signature(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    credential: str,
    supplied_signature: str,
    max_skew_seconds: int = 300,
) -> bool:
    request_time = parse_utc_iso(timestamp)
    skew = abs((now_utc() - request_time).total_seconds())
    if skew > max_skew_seconds:
        return False
    expected = sign_request(method, path, timestamp, nonce, body, credential)
    return hmac.compare_digest(expected, supplied_signature)


def expiry_from_now(seconds: int) -> str:
    return utc_iso(now_utc() + timedelta(seconds=seconds))


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(fragment in lowered for fragment in SECRET_FIELD_FRAGMENTS):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
