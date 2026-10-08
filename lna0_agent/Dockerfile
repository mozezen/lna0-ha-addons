ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/shared:/app/agent

WORKDIR /app
COPY rootfs/app /app
COPY run.sh /run.sh

RUN chmod a+x /run.sh
RUN python -c "import lna0_agent; import lna0_shared"

CMD ["/run.sh"]
