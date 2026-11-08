# The EagleEye network agent (eagleeye/netagent): reads the routers and switches over SNMP and
# sends what it found to the EagleEye server. Build from agent-gui/:
#
#   docker build -f packaging/network-agent/Dockerfile -t eagleeye-network-agent .
#
# Run (the connection code comes from the dashboard's Agents page; README "Network agent"):
#
#   docker run -d --name eagleeye-network-agent --restart unless-stopped \
#     -e EAGLEEYE_CONNECTION_CODE_FILE=/run/secrets/connection_code \
#     -e EAGLEEYE_SNMP_USER=eagleeye \
#     -e EAGLEEYE_SNMP_AUTH_KEY_FILE=/run/secrets/snmp_auth \
#     -e EAGLEEYE_SNMP_PRIV_KEY_FILE=/run/secrets/snmp_priv \
#     -v /etc/eagleeye/secrets:/run/secrets:ro -v eagleeye-netagent:/data \
#     eagleeye-network-agent
#
# What it reads (seeds, allowed ranges, depth, interval) is set on the dashboard, or with
# EAGLEEYE_NETWORK_SEEDS / _RANGES / _DEPTH / _INTERVAL. Nothing listens: it only needs UDP 161
# to the devices and HTTPS to the server.
FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EAGLEEYE_KIND=network \
    EAGLEEYE_CONFIG=/data/config.json

COPY packaging/network-agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin eagleeye \
    && mkdir -p /data && chown eagleeye /data

WORKDIR /app
COPY eagleeye /app/eagleeye
COPY packaging/network-agent/THIRD-PARTY-NOTICES.txt /app/THIRD-PARTY-NOTICES.txt

# SNMP needs no privileges: the agent runs as an ordinary user. /data keeps its applied
# settings, when it last crawled and its health status across restarts.
USER eagleeye
VOLUME /data
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD ["python", "-m", "eagleeye.netagent.health"]

ENTRYPOINT ["python", "-m", "eagleeye"]
CMD ["run"]
