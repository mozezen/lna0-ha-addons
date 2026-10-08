ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/shared:/app/agent

WORKDIR /app
COPY shared /app/shared
COPY agent/lna0_agent /app/agent/lna0_agent
COPY agent/home-assistant-addon/run.sh /run.sh

RUN chmod a+x /run.sh

CMD ["/run.sh"]
