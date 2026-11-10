"""Node-authorized, secret-free-Supervisor-storage HAOS remote access bootstrap.

This runs inside the *existing* LNA0 Agent which already holds its Node secret.
The other app receives only 300-second SniTun credentials through Supervisor
stdin. No durable Node secret is exported and no remotely accessible listener
is created on the HAOS machine.
"""
from __future__ import annotations

import json
import re
import time
from urllib import request

from .http_client import signed_request, post_json
from .state import load_state, save_state

_ROUTE = re.compile(r"[0-9a-f]{32}\.remote\.55projects\.com\Z")
_REFRESH_SECONDS = 180  # Issuer default 300 seconds; heartbeat is normally 60s.
_STDIN_COMMAND = "lna0_remote_credentials_v1"
_TARGET_SUFFIX = "_lna0_remote_access"


def _data(reply: dict) -> dict:
    value = reply.get("data", reply)
    if not isinstance(value, dict):
        raise ValueError("invalid Supervisor reply")
    return value


def _expect_ok(reply: dict) -> None:
    if reply.get("result") == "error":
        raise RuntimeError("Supervisor request rejected")


def _discover_addon(supervisor) -> str | None:
    installed = _data(supervisor.get("/addons")).get("addons", [])
    if not isinstance(installed, list):
        raise ValueError("invalid installed app list")
    candidates = [x.get("slug") for x in installed
                  if isinstance(x, dict) and isinstance(x.get("slug"), str)
                  and x["slug"].endswith(_TARGET_SUFFIX)]
    if len(candidates) > 1:
        raise RuntimeError("ambiguous remote access app")
    return candidates[0] if candidates else None


def _send_ephemeral_stdin(supervisor, slug: str, credentials: dict) -> None:
    """Raw Supervisor stdin, not persisted in addon options or logs."""
    if not supervisor.token:
        raise RuntimeError("Supervisor authentication unavailable")
    data = json.dumps({"type": _STDIN_COMMAND, "credentials": credentials},
                      separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(data) > 16 * 1024:
        raise RuntimeError("credential message too large")
    req = request.Request(
        supervisor.base_url + f"/addons/{slug}/stdin",
        data=data, method="POST",
        headers={"Authorization": f"Bearer {supervisor.token}",
                 "Content-Type": "application/json"},
    )
    # Never include request bodies, error bodies, or exception strings in logs.
    with request.urlopen(req, timeout=10) as resp:
        raw = resp.read(4096)
        if not 200 <= resp.status < 300:
            raise RuntimeError("Supervisor stdin rejected")
        result = json.loads(raw)
        _expect_ok(result)


def _ensure_addon_ready(supervisor, slug: str, hostname: str) -> bool:
    info = _data(supervisor.get(f"/addons/{slug}/info"))
    if info.get("stdin") is not True:
        # Do not deliver credentials to an older, unprepared app.
        return False
    opts = info.get("options")
    if not isinstance(opts, dict):
        raise ValueError("remote app options missing")
    assigned = opts.get("public_hostname", "")
    if assigned not in ("", hostname):
        raise RuntimeError("remote app belongs to a different house")
    changed = assigned != hostname
    if changed:
        _expect_ok(supervisor.post(f"/addons/{slug}/options", {
            "options": {"public_hostname": hostname}
        }))
    state = str(info.get("state", ""))
    if state != "started":
        _expect_ok(supervisor.post(f"/addons/{slug}/start", {}))
    elif changed:
        _expect_ok(supervisor.post(f"/addons/{slug}/restart", {}))
    return True


def provision_remote_access(config, supervisor, node_credential: str) -> str:
    """Called after a successful heartbeat; fail closed on unavailable dependencies.

    Returns a status string; caller logs only that string (never credentials).
    """
    tls_args = {
        "ca_pem": config.control_plane_ca_pem,
        "allow_insecure_dev_http": config.allow_insecure_dev_http,
    }
    if config.allow_insecure_dev_http:
        return "insecure_transport_disabled"
    route = signed_request(
        method="GET",
        url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/remote-access",
        credential=node_credential, **tls_args,
    )
    if route.get("status") != "requested":
        # Stop this Node's local app promptly after administrative disablement.
        # Gateway-side active-peer revocation is a separate production gate.
        if route.get("status") == "disabled":
            slug = _discover_addon(supervisor)
            if slug:
                info = _data(supervisor.get(f"/addons/{slug}/info"))
                assigned = info.get("options", {})
                if (isinstance(assigned, dict)
                    and assigned.get("public_hostname") == route.get("hostname")
                    and info.get("state") == "started"):
                    _expect_ok(supervisor.post(f"/addons/{slug}/stop", {}))
                    return "stopped_on_disable"
        return "not_requested"
    hostname = route.get("hostname")
    if not isinstance(hostname, str) or not _ROUTE.fullmatch(hostname):
        raise ValueError("unexpected route hostname")
    if route.get("node_id") != config.node_id:
        raise ValueError("route belongs to another Node")
    slug = _discover_addon(supervisor)
    if slug is None:
        return "app_missing"
    if not _ensure_addon_ready(supervisor, slug, hostname):
        return "app_version_unready"

    state = load_state(config.state_path)
    metadata = state.get("remote_access_issuance")
    if (isinstance(metadata, dict)
        and metadata.get("hostname") == hostname
        and metadata.get("target") == slug
        and type(metadata.get("next_refresh")) in (float, int)
        and time.time() < metadata["next_refresh"]):
        return "current"

    grant_reply = signed_request(
        method="POST",
        url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/remote-access/grant",
        credential=node_credential, data={}, **tls_args,
    )
    grant = grant_reply.get("grant")
    if not isinstance(grant, str) or not grant:
        raise RuntimeError("invalid remote access grant")
    credentials = post_json(
        f"{config.control_plane_url}/api/v1/remote-access/redeem",
        {"grant": grant}, timeout=10, **tls_args,
    )
    if credentials.get("hostname") != hostname:
        raise ValueError("issued credentials do not match Node route")
    # Receiver validates cipher, AES lengths, and expiration before writing.
    _send_ephemeral_stdin(supervisor, slug, credentials)

    updated = dict(load_state(config.state_path))
    updated["remote_access_issuance"] = {
        "hostname": hostname, "target": slug,
        "next_refresh": time.time() + _REFRESH_SECONDS,
    }
    save_state(config.state_path, updated)
    return "delivered"
