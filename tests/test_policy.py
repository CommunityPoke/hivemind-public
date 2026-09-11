import pytest

from conftest import make_peer
from pip_protocol.errors import ErrorCode, PipError
from pip_protocol.policy import (
    Consent,
    PeerRecord,
    Policy,
    PolicyEngine,
    dataset_resource,
)


def engine_for(kp, scopes=(), consents=(), **kw):
    policy = Policy(peers=[make_peer(kp, list(scopes), list(consents))], **kw)
    return PolicyEngine(policy)


def test_unknown_peer(keypair, clock):
    engine = PolicyEngine(Policy(), clock)
    with pytest.raises(PipError) as e:
        engine.authorize(None, "messages:send")
    assert e.value.code == ErrorCode.UNKNOWN_PEER


def test_scope_exact(keypair, clock):
    engine = PolicyEngine(Policy(peers=[make_peer(keypair, ["messages:send"])]), clock)
    engine.authorize(engine.get_peer(keypair.instance_id), "messages:send")
    with pytest.raises(PipError) as e:
        engine.authorize(engine.get_peer(keypair.instance_id), "data:request")
    assert e.value.code == ErrorCode.FORBIDDEN


def test_scope_wildcard(keypair, clock):
    engine = PolicyEngine(Policy(peers=[make_peer(keypair, ["data:*"])]), clock)
    peer = engine.get_peer(keypair.instance_id)
    engine.authorize(peer, "data:request")
    engine.authorize(peer, "data:offer")
    with pytest.raises(PipError):
        engine.authorize(peer, "messages:send")


def test_admin_wildcard_implies_all(keypair, clock):
    engine = PolicyEngine(Policy(peers=[make_peer(keypair, ["admin:*"])]), clock)
    peer = engine.get_peer(keypair.instance_id)
    engine.authorize(peer, "messages:send")
    engine.authorize(peer, "data:request")


def test_default_scopes_apply(keypair, clock):
    engine = PolicyEngine(
        Policy(default_scopes=["messages:send"], peers=[make_peer(keypair)]), clock
    )
    engine.authorize(engine.get_peer(keypair.instance_id), "messages:send")


def test_consent_required(keypair, clock):
    engine = engine_for(keypair, scopes=["data:request"])
    peer = engine.get_peer(keypair.instance_id)
    with pytest.raises(PipError) as e:
        engine.authorize(peer, "data:request", resource="data:notes", action="read")
    assert e.value.code == ErrorCode.CONSENT_REQUIRED


def test_consent_granted(keypair, clock):
    consent = Consent(resource="data:notes", actions=["read"])
    engine = engine_for(keypair, scopes=["data:request"], consents=[consent])
    peer = engine.get_peer(keypair.instance_id)
    engine.authorize(peer, "data:request", resource="data:notes", action="read")


def test_consent_wrong_action(keypair, clock):
    consent = Consent(resource="data:notes", actions=["write"])
    engine = engine_for(keypair, scopes=["data:request"], consents=[consent])
    peer = engine.get_peer(keypair.instance_id)
    with pytest.raises(PipError) as e:
        engine.authorize(peer, "data:request", resource="data:notes", action="read")
    assert e.value.code == ErrorCode.CONSENT_REQUIRED


def test_consent_expired(keypair, clock):
    consent = Consent(
        resource="data:notes",
        actions=["read"],
        expires=clock.now(),
    )
    engine = PolicyEngine(Policy(peers=[make_peer(keypair, ["data:request"], [consent])]), clock)
    clock.advance(1)
    peer = engine.get_peer(keypair.instance_id)
    with pytest.raises(PipError) as e:
        engine.authorize(peer, "data:request", resource="data:notes", action="read")
    assert e.value.code == ErrorCode.CONSENT_REQUIRED


def test_rate_limit(clock):
    from pip_protocol.identity import KeyPair

    kp = KeyPair.generate()
    policy = Policy(
        peers=[make_peer(kp)],
        rate_limits={"per_peer_per_minute": 60, "burst": 3},
    )
    engine = PolicyEngine(policy, clock)
    for _ in range(3):
        engine.check_rate(kp.instance_id)
    with pytest.raises(PipError) as e:
        engine.check_rate(kp.instance_id)
    assert e.value.code == ErrorCode.RATE_LIMITED
    clock.advance(60)
    engine.check_rate(kp.instance_id)  # refilled


def test_dataset_resource():
    assert dataset_resource("notes") == "data:notes"


def test_policy_load_yaml(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "allow_unknown_peers: true\npeers:\n"
        "  - instance_id: pip:x\n    public_key: ed25519:AAAA\n"
        "    scopes: [messages:send]\n"
    )
    policy = Policy.load(p)
    assert policy.allow_unknown_peers
    assert policy.peers[0].scopes == ["messages:send"]


def test_policy_load_json(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text('{"allow_unknown_peers": false, "max_payload_bytes": 100}')
    policy = Policy.load(p)
    assert policy.max_payload_bytes == 100


def test_peer_record_type(keypair):
    peer = make_peer(keypair)
    assert isinstance(peer, PeerRecord)
