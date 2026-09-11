import json

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import make_peer
from pip_protocol.config import Settings
from pip_protocol.delivery import Outbox
from pip_protocol.envelope import verify_signature
from pip_protocol.errors import ErrorCode, PipError
from pip_protocol.identity import KeyPair
from pip_protocol.node import Node
from pip_protocol.policy import Policy
from pip_protocol.schemas import EnvelopeType, MessagePayload, parse_envelope
from pip_protocol.store import MemoryStore
from pip_protocol.transport.http import HttpPeerClient, create_app, deliver_outbox


def make_pair(clock, *, scopes=None, b_settings=None):
    ka, kb = KeyPair.generate(), KeyPair.generate()
    a = Node(ka, Policy(peers=[make_peer(kb, ["admin:*"])]), clock=clock)
    b = Node(
        kb,
        Policy(peers=[make_peer(ka, scopes if scopes is not None else ["messages:send"])]),
        clock=clock,
    )
    app = create_app(b, b_settings)
    return a, b, TestClient(app)


def post_env(client, env, headers=None):
    return client.post(
        "/pip/v1/inbox",
        content=env.model_dump_json(by_alias=True),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def message(a, to, clock):
    return a.build(EnvelopeType.MESSAGE, to, MessagePayload(subject="s", body="hi"))


def test_healthz(clock):
    _, _, client = make_pair(clock)
    assert client.get("/healthz").json() == {"status": "ok", "version": "pip/1.0"}


def test_well_known_handshake(clock):
    _, b, client = make_pair(clock)
    env = parse_envelope(client.get("/.well-known/pip").json())
    verify_signature(env, b.keypair.public_key)
    assert env.from_ == b.instance_id


def test_message_ok(clock):
    a, b, client = make_pair(clock)
    resp = post_env(client, message(a, b.instance_id, clock))
    assert resp.status_code == 200
    env = parse_envelope(resp.json())
    verify_signature(env, b.keypair.public_key)
    assert env.typed_payload().status == "accepted"
    assert resp.headers["x-pip-request-id"]


def test_unknown_peer_401(clock):
    a = Node(KeyPair.generate(), clock=clock)
    b = Node(KeyPair.generate(), Policy(), clock=clock)
    client = TestClient(create_app(b))
    resp = post_env(client, message(a, b.instance_id, clock))
    assert resp.status_code == 401
    assert parse_envelope(resp.json()).typed_payload().code == "UNKNOWN_PEER"


def test_forbidden_403(clock):
    a, b, client = make_pair(clock, scopes=[])
    resp = post_env(client, message(a, b.instance_id, clock))
    assert resp.status_code == 403
    assert parse_envelope(resp.json()).typed_payload().code == "FORBIDDEN"


def test_replay_409(clock):
    a, b, client = make_pair(clock)
    env = message(a, b.instance_id, clock)
    assert post_env(client, env).status_code == 200
    resp = post_env(client, env)
    assert resp.status_code == 409
    assert parse_envelope(resp.json()).typed_payload().code == "REPLAY"


def test_oversize_413(clock):
    _, b, client = make_pair(clock)
    b.policy.max_payload_bytes = 100
    resp = client.post("/pip/v1/inbox", content=b"x" * 9000)
    assert resp.status_code == 413
    assert parse_envelope(resp.json()).typed_payload().code == "PAYLOAD_TOO_LARGE"


def test_bad_json_400(clock):
    _, b, client = make_pair(clock)
    resp = client.post("/pip/v1/inbox", content=b"not json")
    assert resp.status_code == 400
    env = parse_envelope(resp.json())
    assert env.typed_payload().code == "SCHEMA_INVALID"
    verify_signature(env, b.keypair.public_key)


def test_wrong_addressee(clock):
    a, b, client = make_pair(clock)
    env = message(a, "pip:someoneelse", clock)
    resp = post_env(client, env)
    assert resp.status_code == 401
    assert parse_envelope(resp.json()).typed_payload().code == "IDENTITY_MISMATCH"


def test_bearer_token(clock):
    settings = Settings(http_bearer_token="sekrit")  # noqa: S106
    a, b, client = make_pair(clock, b_settings=settings)
    env = message(a, b.instance_id, clock)
    assert post_env(client, env).status_code == 401
    assert post_env(client, env, {"Authorization": "Bearer wrong"}).status_code == 401
    ok = post_env(client, env, {"Authorization": "Bearer sekrit"})  # noqa: S106
    assert ok.status_code == 200
    assert client.get("/metrics").status_code == 401
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer sekrit"}).status_code  # noqa: S106
        == 200
    )


def test_metrics_endpoint(clock):
    a, b, client = make_pair(clock)
    post_env(client, message(a, b.instance_id, clock))
    resp = client.get("/metrics")
    assert "envelopes_received_total" in resp.text


def test_http_peer_client(clock):
    a, b, client = make_pair(clock)
    peer = HttpPeerClient(a, "http://b", b.keypair.public_key, client=client)
    resp = peer.send(message(a, b.instance_id, clock))
    assert resp.typed_payload().status == "accepted"
    hs = peer.fetch_handshake()
    assert hs.from_ == b.instance_id


def test_http_peer_client_bad_reply(clock):
    a, b, client = make_pair(clock)
    env = message(a, b.instance_id, clock)

    def handler(request: httpx.Request) -> httpx.Response:
        wire = env.model_dump(mode="json", by_alias=True)
        wire["in_reply_to"] = "bogus"
        return httpx.Response(200, json=wire)

    http_client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://b")
    peer = HttpPeerClient(a, "http://b", b.keypair.public_key, client=http_client)
    with pytest.raises(PipError) as e:
        peer.send(env)
    assert e.value.code == ErrorCode.SIGNATURE_INVALID


def test_deliver_outbox(clock):
    a, b, client = make_pair(clock)
    peer = HttpPeerClient(a, "http://b", b.keypair.public_key, client=client)
    outbox = Outbox(MemoryStore(), clock)
    outbox.enqueue(
        b.instance_id,
        message(a, b.instance_id, clock).model_dump(mode="json", by_alias=True),
    )
    deliver_outbox(a, outbox, {b.instance_id: peer})
    assert outbox.due() == []
    assert len(b.inbox) == 1


def test_deliver_outbox_dead_on_nonretryable(clock):
    a = Node(KeyPair.generate(), clock=clock)
    outbox = Outbox(MemoryStore(), clock)

    class FailingClient:
        def send(self, env):
            raise PipError(ErrorCode.FORBIDDEN, "nope", retryable=False)

    outbox.enqueue(
        "pip:peer",
        message(a, "pip:peer", clock).model_dump(mode="json", by_alias=True),
    )
    deliver_outbox(a, outbox, {"pip:peer": FailingClient()})
    # dead items are retained for inspection; fetch via a late 'now'
    clock.advance(3600)
    stored = outbox.store.outbox_due(clock.now())
    assert len(stored) == 1 and stored[0]["dead"]


def test_json_content_type(clock):
    a, b, client = make_pair(clock)
    resp = post_env(client, message(a, b.instance_id, clock))
    assert resp.headers["content-type"].startswith("application/json")
    json.dumps(resp.json())  # valid JSON
