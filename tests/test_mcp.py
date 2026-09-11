import pytest

from conftest import make_peer
from pip_protocol.envelope import verify_signature
from pip_protocol.identity import KeyPair
from pip_protocol.mcp_server import create_mcp_server
from pip_protocol.node import Node
from pip_protocol.policy import Policy
from pip_protocol.schemas import EnvelopeType, MessagePayload, parse_envelope

mcp = pytest.importorskip("mcp")
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402


def make_nodes(clock, scopes=None):
    ka, kb = KeyPair.generate(), KeyPair.generate()
    a = Node(ka, Policy(peers=[make_peer(kb, ["admin:*"])]), clock=clock)
    b = Node(
        kb,
        Policy(peers=[make_peer(ka, scopes if scopes is not None else ["messages:send"])]),
        clock=clock,
    )
    return a, b


def tool_result_payload(result):
    # FastMCP returns CallToolResult; structured dict is in structuredContent or text
    if result.structuredContent is not None:
        return result.structuredContent
    import json

    return json.loads(result.content[0].text)


async def test_mcp_tools(clock):
    a, b = make_nodes(clock)
    server = create_mcp_server(b)
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert {
            "pip_handshake",
            "pip_send_message",
            "pip_exchange_data",
            "pip_get_receipt",
            "pip_list_capabilities",
        } <= names

        caps = await session.call_tool("pip_list_capabilities", {})
        payload = tool_result_payload(caps)
        assert payload["instance_id"] == b.instance_id
        assert any(c["name"] == "messages.send" for c in payload["capabilities"])


async def test_mcp_handshake(clock):
    a, b = make_nodes(clock)
    server = create_mcp_server(b)
    hs = a.handshake_envelope(to=b.instance_id)
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        result = await session.call_tool(
            "pip_handshake", {"envelope": hs.model_dump(mode="json", by_alias=True)}
        )
        env = parse_envelope(tool_result_payload(result))
        assert env.type == EnvelopeType.HANDSHAKE
        verify_signature(env, b.keypair.public_key)
        assert env.typed_payload().identity.instance_id == b.instance_id


async def test_mcp_send_message(clock):
    a, b = make_nodes(clock)
    server = create_mcp_server(b)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="hi"))
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        result = await session.call_tool(
            "pip_send_message", {"envelope": env.model_dump(mode="json", by_alias=True)}
        )
        resp = parse_envelope(tool_result_payload(result))
        assert resp.type == EnvelopeType.RECEIPT
        assert resp.typed_payload().status == "accepted"
        verify_signature(resp, b.keypair.public_key)


async def test_mcp_forbidden_error_envelope(clock):
    a, b = make_nodes(clock, scopes=[])
    server = create_mcp_server(b)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        result = await session.call_tool(
            "pip_send_message", {"envelope": env.model_dump(mode="json", by_alias=True)}
        )
        resp = parse_envelope(tool_result_payload(result))
        assert resp.type == EnvelopeType.ERROR
        assert resp.typed_payload().code == "FORBIDDEN"
        verify_signature(resp, b.keypair.public_key)


async def test_mcp_malformed_schema_invalid(clock):
    _, b = make_nodes(clock)
    server = create_mcp_server(b)
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        result = await session.call_tool("pip_send_message", {"envelope": {"x": 1}})
        resp = parse_envelope(tool_result_payload(result))
        assert resp.type == EnvelopeType.ERROR
        assert resp.typed_payload().code == "SCHEMA_INVALID"
        verify_signature(resp, b.keypair.public_key)


async def test_mcp_wrong_type(clock):
    a, b = make_nodes(clock)
    server = create_mcp_server(b)
    env = a.build(
        EnvelopeType.DATA,
        b.instance_id,
        {"op": "offer", "dataset": "x"},
    )
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        result = await session.call_tool(
            "pip_send_message", {"envelope": env.model_dump(mode="json", by_alias=True)}
        )
        resp = parse_envelope(tool_result_payload(result))
        assert resp.typed_payload().code == "SCHEMA_INVALID"


async def test_mcp_resources(clock):
    _, b = make_nodes(clock)
    server = create_mcp_server(b)
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        import json

        res = await session.read_resource("pip://identity")
        doc = json.loads(res.contents[0].text)
        assert doc["instance_id"] == b.instance_id

        res = await session.read_resource("pip://capabilities")
        assert "messages.send" in res.contents[0].text

        res = await session.read_resource("pip://policy/scopes")
        assert "admin:*" in json.loads(res.contents[0].text)


async def test_mcp_prompt(clock):
    _, b = make_nodes(clock)
    server = create_mcp_server(b)
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        prompt = await session.get_prompt(
            "pip_compose_message", {"to": "pip:x", "subject": "hi", "intent": "greet"}
        )
        assert "subject" in prompt.messages[0].content.text.lower()


async def test_mcp_get_receipt(clock):
    a, b = make_nodes(clock)
    server = create_mcp_server(b)
    env = a.build(
        EnvelopeType.MESSAGE,
        b.instance_id,
        MessagePayload(subject="s", body="x"),
        idempotency_key="k1",
    )
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        r1 = await session.call_tool(
            "pip_send_message", {"envelope": env.model_dump(mode="json", by_alias=True)}
        )
        assert parse_envelope(tool_result_payload(r1)).typed_payload().status == "accepted"
        # now look it up by ref — peer needs messages:read
        b.policy.peers[0].scopes.append("messages:read")
        lookup = a.build(
            EnvelopeType.RECEIPT,
            b.instance_id,
            {"ref": env.id, "status": "accepted"},
        )
        r2 = await session.call_tool(
            "pip_get_receipt", {"envelope": lookup.model_dump(mode="json", by_alias=True)}
        )
        resp = parse_envelope(tool_result_payload(r2))
        assert resp.type == EnvelopeType.RECEIPT
        assert resp.typed_payload().ref == env.id
