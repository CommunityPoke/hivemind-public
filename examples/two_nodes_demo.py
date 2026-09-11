"""In-process demo: two PIP nodes exchange a message and a data request.

Run: python examples/two_nodes_demo.py
"""

from pip_protocol.identity import KeyPair
from pip_protocol.node import DictDataProvider, Node
from pip_protocol.policy import Consent, PeerRecord, Policy
from pip_protocol.schemas import DataPayload, EnvelopeType, MessagePayload


def peer(kp, scopes, consents=None):
    return PeerRecord(
        instance_id=kp.instance_id,
        public_key=kp.public_key,
        scopes=scopes,
        consents=consents or [],
    )


def main() -> None:
    ka, kb = KeyPair.generate(), KeyPair.generate()
    a = Node(ka, Policy(peers=[peer(kb, ["admin:*"])]), display_name="alice")
    b = Node(
        kb,
        Policy(
            peers=[
                peer(
                    ka,
                    ["messages:send", "data:request"],
                    [Consent(resource="data:notes", actions=["read"])],
                )
            ]
        ),
        data_provider=DictDataProvider({"notes": [{"n": i} for i in range(3)]}),
        display_name="bob",
    )
    print(f"A={a.instance_id}  B={b.instance_id}")

    # direct Node API
    env = a.build(
        EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="hi", body="hello bob")
    )
    receipt, err = b.handle(env)
    assert err is None
    print("message receipt:", receipt.typed_payload().status, "| inbox:", len(b.inbox))

    req = a.build(EnvelopeType.DATA, b.instance_id, DataPayload(op="request", dataset="notes"))
    resp, err = b.handle(req)
    assert err is None
    print("data records:", resp.typed_payload().records)

    # over the HTTP transport (in-process ASGI)
    try:
        from fastapi.testclient import TestClient

        from pip_protocol.transport.http import HttpPeerClient, create_app

        peer_client = HttpPeerClient(
            a, "http://bob", kb.public_key, client=TestClient(create_app(b))
        )
        env2 = a.build(
            EnvelopeType.MESSAGE,
            b.instance_id,
            MessagePayload(subject="via http", body="hi over http"),
        )
        receipt2 = peer_client.send(env2)
        print("http receipt:", receipt2.typed_payload().status)
        hs = peer_client.fetch_handshake()
        print("handshake from:", hs.typed_payload().identity.display_name)
    except ImportError:
        print("(install httpx+fastapi for the HTTP part of the demo)")


if __name__ == "__main__":
    main()
