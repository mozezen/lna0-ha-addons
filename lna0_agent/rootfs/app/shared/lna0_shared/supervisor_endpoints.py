"""Documented Home Assistant Supervisor API endpoints used by the Agent."""

SUPERVISOR_ENDPOINTS = {
    "heartbeat_versions": [
        "GET /supervisor/info",
        "GET /core/info",
        "GET /host/info",
    ],
    "diagnostic.snapshot": [
        "GET /supervisor/info",
        "GET /core/info",
        "GET /host/info",
        "GET /resolution/info",
    ],
    "backup.create": [
        "POST /backups/new/full",
    ],
    "home_assistant.restart": [
        "POST /core/restart",
    ],
    "node.restart": [
        "POST /host/reboot",
    ],
    "inventory.refresh": [
        "GET /supervisor/info",
        "GET /core/info",
        "GET /host/info",
        "GET /network/info",
    ],
    "health.refresh": [
        "GET /supervisor/info",
        "GET /core/info",
        "GET /host/info",
        "GET /resolution/info",
    ],
}

