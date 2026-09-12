import importlib
import json
import sys

from starlette.testclient import TestClient

from pip_protocol.config import Settings
from pip_protocol.identity import KeyPair
from pip_protocol.node import Node
from pip_protocol.schemas import parse_envelope
from pip_protocol.transport.combined import create_combined_app

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
    if resp.headers["content-type"].startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:") :])
        raise AssertionError("no data line in SSE response")
    return resp.json()


def test_combined_app(clock):
    node = Node(KeyPair.generate(), clock=clock)
    app = create_combined_app(node)
    # ported loopback Host passes MCP's DNS-rebinding guard
    with TestClient(app, base_url="http://127.0.0.1:8642") as client:
        assert client.get("/healthz").json()["status"] == "ok"
        hs = parse_envelope(client.get("/.well-known/pip").json())
        assert hs.typed_payload().identity.instance_id == node.instance_id
        resp = client.post("/mcp", json=_MCP_INIT, headers=_MCP_HEADERS)
        assert resp.status_code == 200, resp.text
        assert _mcp_body(resp)["result"]["serverInfo"]["name"] == "pip-v1"


def test_combined_bearer_gates_mcp_not_healthz(clock):
    node = Node(KeyPair.generate(), clock=clock)
    settings = Settings(http_bearer_token="tok")  # noqa: S106
    app = create_combined_app(node, settings)
    with TestClient(app, base_url="http://127.0.0.1:8642") as client:
        assert client.get("/healthz").status_code == 200
        assert client.post("/mcp", json=_MCP_INIT, headers=_MCP_HEADERS).status_code == 401
        ok = client.post(
            "/mcp",
            json=_MCP_INIT,
            headers={**_MCP_HEADERS, "Authorization": "Bearer tok"},  # noqa: S106
        )
        assert ok.status_code == 200


def _load_main(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("PIP_PRIVATE_KEY_FILE", str(tmp_path / "k.key"))
    monkeypatch.setenv("PIP_POLICY_FILE", str(tmp_path / "policy.yaml"))
    monkeypatch.setenv("PIP_STORE_URL", "memory://")
    for var in ("FLY_APP_NAME", "PORT", "PIP_PUBLIC_HTTP_URL", "PIP_PUBLIC_MCP_URL"):
        monkeypatch.delenv(var, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    sys.path.insert(0, ".")
    try:
        import main

        return importlib.reload(main)
    finally:
        sys.path.remove(".")


def test_main_module_fly_env(tmp_path, monkeypatch):
    main = _load_main(monkeypatch, tmp_path, FLY_APP_NAME="demo")
    with TestClient(main.app, base_url="http://127.0.0.1:8642") as client:
        assert client.get("/healthz").status_code == 200
        hs = parse_envelope(client.get("/.well-known/pip").json())
        ep = hs.typed_payload().identity.endpoints
        assert ep["http"] == "https://demo.fly.dev"
        assert ep["mcp"] == "https://demo.fly.dev/mcp"


def test_main_module_port_env(tmp_path, monkeypatch):
    main = _load_main(monkeypatch, tmp_path, PORT="9999")
    assert main.settings.http_port == 9999
