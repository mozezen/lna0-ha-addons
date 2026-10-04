"""Agent configuration loading."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from lna0_shared.constants import (
    DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    MAX_HEARTBEAT_INTERVAL_SECONDS,
    MIN_HEARTBEAT_INTERVAL_SECONDS,
)


@dataclass
class AgentConfig:
    control_plane_url: str
    house_id: str
    node_id: str
    hostname: str
    enrollment_token: str | None
    state_path: Path
    heartbeat_interval_seconds: int
    supervisor_base_url: str
    supervisor_token: str | None
    control_plane_ca_pem: str | None
    allow_insecure_dev_http: bool


def _read_options(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("options file must contain a JSON object")
    return data


def load_config() -> AgentConfig:
    options_path = Path(os.environ.get("LNA0_OPTIONS_PATH", "/data/options.json"))
    options = _read_options(options_path)

    def get(name: str, default: str | None = None) -> str | None:
        env_value = os.environ.get(f"LNA0_{name.upper()}")
        if env_value is not None:
            return env_value
        value = options.get(name)
        return str(value) if value is not None else default

    interval_raw = get("heartbeat_interval_seconds", str(DEFAULT_HEARTBEAT_INTERVAL_SECONDS))
    interval = int(interval_raw or DEFAULT_HEARTBEAT_INTERVAL_SECONDS)
    interval = max(MIN_HEARTBEAT_INTERVAL_SECONDS, min(MAX_HEARTBEAT_INTERVAL_SECONDS, interval))
    control_plane_url = get("control_plane_url")
    house_id = get("house_id")
    node_id = get("node_id")
    hostname = get("hostname")
    if not control_plane_url or not house_id or not node_id or not hostname:
        raise ValueError("control_plane_url, house_id, node_id and hostname are required")
    return AgentConfig(
        control_plane_url=control_plane_url.rstrip("/"),
        house_id=house_id,
        node_id=node_id,
        hostname=hostname,
        enrollment_token=get("enrollment_token"),
        state_path=Path(get("state_path", "/data/lna0-agent-state.json") or "/data/lna0-agent-state.json"),
        heartbeat_interval_seconds=interval,
        supervisor_base_url=get("supervisor_base_url", "http://supervisor") or "http://supervisor",
        supervisor_token=os.environ.get("SUPERVISOR_TOKEN") or get("supervisor_token"),
        control_plane_ca_pem=get("control_plane_ca_pem"),
        allow_insecure_dev_http=(get("allow_insecure_dev_http", "false") or "false").lower() == "true",
    )
