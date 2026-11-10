"""Receive ephemeral Session Master credentials from the trusted HA Supervisor.

The existing LNA0 Agent is the only component holding the durable Node secret.
It writes short-lived credentials to this app using Supervisor's app stdin API.
No inbound listener, shared directory, or durable Node secret is needed here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, Callable

MAX_STDIN_LINE = 16 * 1024
COMMAND = "lna0_remote_credentials_v1"


def validate_command(raw: bytes, hostname: str, validator: Callable) -> dict:
    if not 0 < len(raw) <= MAX_STDIN_LINE:
        raise ValueError("invalid credential command size")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"type", "credentials"} or payload["type"] != COMMAND:
        raise ValueError("invalid credential command")
    credentials = payload["credentials"]
    if not isinstance(credentials, dict):
        raise ValueError("invalid credential object")
    validator(credentials, hostname)
    return credentials


def store_credentials(path: Path, credentials: dict) -> None:
    """Atomically replace the owner-only credential file without exposing content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".lna0-creds-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(credentials, stream, separators=(",", ":"), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def consume_stream(source: BinaryIO, path: Path, hostname: str, validator: Callable, logger) -> None:
    """Read newline-framed JSON commands; never log raw input or exceptions."""
    while True:
        raw = source.readline(MAX_STDIN_LINE + 2)
        if not raw:
            return
        if len(raw) > MAX_STDIN_LINE + 1 or not raw.endswith(b"\n"):
            # A truncated/unterminated command must never be accepted.
            logger.warning("CREDENTIAL_COMMAND_REJECTED reason=InvalidFrame")
            # Discard the rest of an oversized line, bounded chunks.
            if not raw.endswith(b"\n"):
                while True:
                    chunk = source.readline(MAX_STDIN_LINE + 2)
                    if not chunk or chunk.endswith(b"\n"):
                        break
            continue
        try:
            credentials = validate_command(raw.strip(), hostname, validator)
            store_credentials(path, credentials)
            logger.info("CREDENTIALS_RECEIVED hostname=%s", hostname)
        except (ValueError, TypeError, KeyError, UnicodeError, OSError, json.JSONDecodeError) as exc:
            logger.warning("CREDENTIAL_COMMAND_REJECTED reason=%s", type(exc).__name__)
