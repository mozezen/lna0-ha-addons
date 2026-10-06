"""Shared constants for the LNA0 v0.1 contracts."""

AGENT_VERSION = "0.1.4"
SCHEMA_VERSION = "1"
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 60
MIN_HEARTBEAT_INTERVAL_SECONDS = 30
MAX_HEARTBEAT_INTERVAL_SECONDS = 300
ONLINE_THRESHOLD_MULTIPLIER = 2.5

ALLOWED_OPERATIONS = {
    "diagnostic.snapshot",
    "backup.create",
    "home_assistant.restart",
    "node.restart",
    "inventory.refresh",
    "health.refresh",
}

DISRUPTIVE_OPERATIONS = {
    "home_assistant.restart",
    "node.restart",
}

NODE_ID_PREFIX = "LNA0-N-"
HOUSE_ID_PREFIX = "LNA0-H-"
