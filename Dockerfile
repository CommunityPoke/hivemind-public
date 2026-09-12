# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN uv venv /opt/venv && /opt/venv/bin/python -V \
    && uv pip install --python /opt/venv/bin/python .

FROM python:3.12-slim AS runtime
RUN groupadd -g 10001 pip && useradd -u 10001 -g pip -m pip
COPY --from=builder /opt/venv /opt/venv
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /data /config && chown pip:pip /data
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PIP_PRIVATE_KEY_FILE=/data/instance.key \
    PIP_POLICY_FILE=/config/policy.yaml \
    PIP_STORE_URL=sqlite:////data/pip.db \
    PIP_HTTP_HOST=0.0.0.0 \
    PIP_HTTP_PORT=8642 \
    PIP_MCP_PORT=8643
VOLUME ["/data"]
USER pip
EXPOSE 8642 8643
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,os,sys;sys.exit(0 if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PIP_HEALTH_PORT','8642')}/healthz\",timeout=2).status==200 else 1)"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve-http"]
