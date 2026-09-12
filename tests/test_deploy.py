import os
import subprocess
from pathlib import Path

import yaml

from pip_protocol.config import Settings

ROOT = Path(__file__).resolve().parent.parent


def test_env_example_covers_settings_and_has_no_secrets():
    text = (ROOT / "config" / ".env.example").read_text()
    assert "PIP_HTTP_BEARER_TOKEN=\n" in text or text.endswith("PIP_HTTP_BEARER_TOKEN=")
    for name in Settings.model_fields:
        assert f"PIP_{name.upper()}" in text, name
    # no real values: every uncommented assignment is empty or a safe default
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            assert not any(s in value.lower() for s in ("secret", "token=", "hunter")), line


def test_compose_ports_loopback_only():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for svc in compose["services"].values():
        for port in svc["ports"]:
            assert str(port).split(":")[0] == "127.0.0.1", port
    assert "pip-data" in compose["volumes"]
    for svc in compose["services"].values():
        assert svc["read_only"] is True
        assert svc["cap_drop"] == ["ALL"]


def test_dockerfile_hardening():
    text = (ROOT / "Dockerfile").read_text()
    assert "USER pip" in text
    assert "HEALTHCHECK" in text
    assert "EXPOSE 8642 8643" in text


def test_scripts_executable():
    out = subprocess.run(
        ["/usr/bin/git", "ls-files", "-s", "docker/entrypoint.sh", "deploy/deploy.sh"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for path in ("docker/entrypoint.sh", "deploy/deploy.sh"):
        assert os.access(ROOT / path, os.X_OK), path
        tracked = [ln for ln in out.splitlines() if ln.endswith(path)]
        if tracked:  # once committed, git must record the exec bit
            assert tracked[0].split()[0] == "100755", tracked[0]


def test_mcp_healthz_no_token():
    from starlette.testclient import TestClient

    from pip_protocol.identity import KeyPair
    from pip_protocol.mcp_server import build_mcp_http_app, create_mcp_server
    from pip_protocol.node import Node

    node = Node(KeyPair.generate())
    app = build_mcp_http_app(create_mcp_server(node))
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": "pip/1.0", "transport": "mcp"}


_MCP_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
_MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def _mcp_body(resp):
    import json

    if resp.headers["content-type"].startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:") :])
        raise AssertionError("no data line in SSE response")
    return resp.json()


def test_mcp_initialize_end_to_end():
    """Real MCP initialize POST exercises the propagated lifespan."""
    from starlette.testclient import TestClient

    from pip_protocol.identity import KeyPair
    from pip_protocol.mcp_server import build_mcp_http_app, create_mcp_server
    from pip_protocol.node import Node

    node = Node(KeyPair.generate())
    app = build_mcp_http_app(create_mcp_server(node), bearer_token="tok123")  # noqa: S106
    # loopback Host passes MCP's DNS-rebinding guard; context runs lifespan
    # Host must match MCP allowed_hosts pattern "127.0.0.1:*" (port required)
    with TestClient(app, base_url="http://127.0.0.1:8643") as client:
        assert client.get("/healthz").status_code == 200
        assert client.post("/mcp", json=_MCP_INIT, headers=_MCP_HEADERS).status_code == 401
        resp = client.post(
            "/mcp",
            json=_MCP_INIT,
            headers={**_MCP_HEADERS, "Authorization": "Bearer tok123"},  # noqa: S106
        )
        assert resp.status_code == 200, resp.text
        body = _mcp_body(resp)
        assert body["result"]["serverInfo"]["name"] == "pip-v1"
