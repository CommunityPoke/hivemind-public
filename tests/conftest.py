import pytest

from pip_protocol.clock import FakeClock
from pip_protocol.identity import KeyPair
from pip_protocol.policy import Consent, PeerRecord


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def keypair() -> KeyPair:
    return KeyPair.generate()


def make_peer(kp: KeyPair, scopes=None, consents=None) -> PeerRecord:
    return PeerRecord(
        instance_id=kp.instance_id,
        public_key=kp.public_key,
        display_name="peer",
        scopes=scopes or [],
        consents=consents or [],
    )


@pytest.fixture
def consent_read_notes() -> Consent:
    return Consent(resource="data:notes", actions=["read"], expires=None)
