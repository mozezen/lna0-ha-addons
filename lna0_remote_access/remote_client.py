"""LNA0 Home Assistant SniTun edge client.

This component is deliberately outbound-only. The public TLS certificate and
private key remain on the HAOS appliance. Neither the SniTun Gateway nor the
Control Plane receives the TLS private key.

Provisioning credentials currently arrive via /data/credentials.json. An
approved automated credential-refresh component is still required before
production rollout. No user-facing service is activated without credentials.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path

from stdin_credentials import consume_stream
import re
import signal
import socket
import ssl
import stat
import sys
import threading
import time

LOG = logging.getLogger("lna0.remote_client")
DATA = Path("/data")
SSL_DIR = Path("/ssl")
OPTIONS = DATA / "options.json"
CREDENTIALS = DATA / "credentials.json"
NGINX_CONFIG = DATA / "nginx-remote.conf"
DOMAIN = "remote.55projects.com"
RECONNECT_MAX_SECONDS = 60
EDGE_TLS_PORT = 10443
LABEL_RE = re.compile(r"[0-9a-f]{32}\.remote\.55projects\.com\Z")
HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
FILE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")


class InvalidConfig(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    gateway_host: str
    gateway_port: int
    public_hostname: str
    homeassistant_port: int
    certificate_file: str
    private_key_file: str


@dataclass(frozen=True, repr=False)
class Credentials:
    fernet_token: bytes
    aes_key: bytes
    aes_iv: bytes
    expires_at: float


def _port(value: object) -> int:
    if type(value) is not int or not (1 <= value <= 65535):
        raise InvalidConfig("invalid TCP port")
    return value


def settings_from_dict(data: dict) -> Settings:
    if not isinstance(data, dict):
        raise InvalidConfig("invalid settings")
    hostname = data.get("public_hostname")
    if not isinstance(hostname, str) or not LABEL_RE.fullmatch(hostname):
        raise InvalidConfig("public_hostname must be a provisioned 128-bit route")
    gateway = data.get("gateway_host")
    if not isinstance(gateway, str) or not HOST_RE.fullmatch(gateway):
        raise InvalidConfig("invalid gateway hostname")
    cert = data.get("certificate_file")
    key = data.get("private_key_file")
    if not isinstance(cert, str) or not FILE_RE.fullmatch(cert):
        raise InvalidConfig("invalid certificate basename")
    if not isinstance(key, str) or not FILE_RE.fullmatch(key):
        raise InvalidConfig("invalid private key basename")
    return Settings(
        gateway_host=gateway,
        gateway_port=_port(data.get("gateway_port")),
        public_hostname=hostname,
        homeassistant_port=_port(data.get("homeassistant_port")),
        certificate_file=cert,
        private_key_file=key,
    )


def credentials_from_dict(data: dict, hostname: str) -> Credentials:
    if not isinstance(data, dict) or data.get("hostname") != hostname:
        raise InvalidConfig("credentials do not match assigned route")
    if data.get("cipher") != "aes-gcm-siv" or data.get("protocol_version") != 2:
        raise InvalidConfig("unsupported tunnel cipher or protocol")
    raw_token = data.get("fernet_token")
    if not isinstance(raw_token, str) or not (80 <= len(raw_token) <= 8192):
        raise InvalidConfig("invalid token format")
    try:
        token = raw_token.encode("ascii")
        aes_key = bytes.fromhex(data["aes_key"])
        aes_iv = bytes.fromhex(data["aes_iv"])
    except (KeyError, ValueError, UnicodeError, TypeError) as exc:
        raise InvalidConfig("invalid credential encoding") from exc
    if len(aes_key) != 32 or len(aes_iv) != 16:
        raise InvalidConfig("invalid AES key length")
    expires_at = data.get("expires_at")
    if isinstance(expires_at, str):
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone required")
            expires_at = parsed.timestamp()
        except ValueError as exc:
            raise InvalidConfig("invalid expiration timestamp") from exc
    if type(expires_at) not in (int, float) or not (time.time() + 10 < expires_at < time.time() + 3600):
        raise InvalidConfig("expired or excessively long-lived credential")
    return Credentials(token, aes_key, aes_iv, float(expires_at))


def read_credentials(path: Path, hostname: str) -> Credentials:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise InvalidConfig("credential file must be private (0600)")
    return credentials_from_dict(json.loads(path.read_text(encoding="utf-8")), hostname)


def nginx_text(settings: Settings) -> str:
    """All interpolated values are restricted to safe alphabets above."""
    cert_path = str(SSL_DIR / settings.certificate_file)
    key_path = str(SSL_DIR / settings.private_key_file)
    return f'''worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/lna0-nginx.pid;
events {{ worker_connections 256; }}
http {{
  server_tokens off;
  server_names_hash_bucket_size 128;
  map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
  server {{
    listen 127.0.0.1:{EDGE_TLS_PORT} ssl default_server;
    ssl_reject_handshake on;
  }}
  server {{
    listen 127.0.0.1:{EDGE_TLS_PORT} ssl;
    server_name {settings.public_hostname};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    client_max_body_size 64m;
    location / {{
      proxy_pass http://homeassistant.local.hass.io:{settings.homeassistant_port};
      proxy_http_version 1.1;
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Host $http_host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_buffering off;
      proxy_read_timeout 3600s;
      proxy_send_timeout 3600s;
    }}
  }}
}}
'''


async def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.1)
        else:
            writer.close()
            await writer.wait_closed()
            return
    raise RuntimeError("TLS reverse proxy did not start")


async def run() -> None:
    # Remain available while the Agent provisions this app; do not crash-loop.
    missing_assignment_logged = False
    while True:
        try:
            settings = settings_from_dict(json.loads(OPTIONS.read_text(encoding="utf-8")))
            break
        except (FileNotFoundError, OSError, InvalidConfig, ValueError, json.JSONDecodeError):
            if not missing_assignment_logged:
                LOG.info("WAITING_FOR_REMOTE_ASSIGNMENT")
                missing_assignment_logged = True
            await asyncio.sleep(5)

    # Supervisor provides a private Docker stdin stream; no network listener.
    threading.Thread(
        target=consume_stream,
        args=(sys.stdin.buffer, CREDENTIALS, settings.public_hostname,
              credentials_from_dict, LOG),
        name="ephemeral-credential-receiver",
        daemon=True,
    ).start()

    cert_file = SSL_DIR / settings.certificate_file
    key_file = SSL_DIR / settings.private_key_file
    missing_tls_logged = False
    while True:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_file), str(key_file))
            break
        except (FileNotFoundError, PermissionError, ssl.SSLError, OSError):
            if not missing_tls_logged:
                LOG.warning("WAITING_FOR_CUSTOMER_TLS_CERTIFICATE")
                missing_tls_logged = True
            await asyncio.sleep(5)
    NGINX_CONFIG.write_text(nginx_text(settings), encoding="utf-8")
    os.chmod(NGINX_CONFIG, 0o600)
    check = await asyncio.create_subprocess_exec("nginx", "-t", "-c", str(NGINX_CONFIG))
    if await check.wait() != 0:
        raise RuntimeError("nginx configuration invalid")
    nginx = await asyncio.create_subprocess_exec("nginx", "-c", str(NGINX_CONFIG), "-g", "daemon off;")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop.set)

    try:
        await wait_for_port(EDGE_TLS_PORT)
        LOG.info("EDGE_TLS_PROXY_READY hostname=%s", settings.public_hostname)
        from snitun.client.client_peer import ClientPeer
        from snitun.client.connector import EndpointConnector

        backoff = 2
        last_status = None
        while not stop.is_set():
            try:
                credentials = read_credentials(CREDENTIALS, settings.public_hostname)
                stat_stamp = CREDENTIALS.stat().st_mtime_ns
            except (FileNotFoundError, OSError, InvalidConfig, ValueError) as err:
                status = type(err).__name__
                if status != last_status:
                    LOG.warning("CREDENTIALS_UNAVAILABLE reason=%s", status)
                    last_status = status
                try:
                    await asyncio.wait_for(stop.wait(), 5)
                except asyncio.TimeoutError:
                    pass
                continue

            last_status = None
            peer = ClientPeer(settings.gateway_host, settings.gateway_port)
            try:
                await peer.start(
                    EndpointConnector("127.0.0.1", EDGE_TLS_PORT),
                    credentials.fernet_token,
                    credentials.aes_key,
                    credentials.aes_iv,
                    cipher="aes-gcm-siv",
                    protocol_version=2,
                )
                backoff = 2
                LOG.info("TUNNEL_CONNECTED hostname=%s", settings.public_hostname)
                disconnected = peer.wait()
                while not stop.is_set() and not disconnected.done():
                    await asyncio.sleep(3)
                    try:
                        if CREDENTIALS.stat().st_mtime_ns != stat_stamp:
                            LOG.info("CREDENTIALS_ROTATED reconnecting")
                            break
                    except OSError:
                        break
            except Exception as err:
                # Do not log exception strings: remote libraries can include tokens.
                LOG.warning("TUNNEL_DISCONNECTED reason=%s", type(err).__name__)
            finally:
                if peer.is_connected:
                    with contextlib.suppress(Exception):
                        await peer.stop()

            if not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, RECONNECT_MAX_SECONDS)
    finally:
        if nginx.returncode is None:
            nginx.terminate()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(nginx.wait(), timeout=8)
            if nginx.returncode is None:
                nginx.kill()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(run())
    except Exception as err:
        LOG.error("REMOTE_CLIENT_START_FAILED reason=%s", type(err).__name__)
        raise SystemExit(1) from None
