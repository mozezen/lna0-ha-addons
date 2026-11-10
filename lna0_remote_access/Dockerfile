# Deliberately explicit FROM: Supervisor no longer supplies BUILD_FROM implicitly.
FROM ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
ARG BUILD_VERSION=0.1.1
ARG BUILD_ARCH=amd64
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache nginx ca-certificates \
    && python3 -m pip install --no-cache-dir 'snitun==0.47.0' \
    && python3 -c 'from snitun.client.client_peer import ClientPeer; print("SniTun dependency OK")'
COPY remote_client.py /app/remote_client.py
COPY stdin_credentials.py /app/stdin_credentials.py
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/run.sh"]
