#!/usr/bin/env sh
set -eu

export PYTHONPATH="/app/agent:/app/shared${PYTHONPATH:+:$PYTHONPATH}"
cd /app/agent

exec python -m lna0_agent
