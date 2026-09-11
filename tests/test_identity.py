import os
import stat

import pytest

from pip_protocol.errors import PipError
from pip_protocol.identity import (
    IdentityDocument,
    InsecureKeyFileError,
    KeyPair,
    decode_public_key,
    instance_id_from_public_key,
    verify,
)


def test_keygen_and_sign_verify():
    kp = KeyPair.generate()
    sig = kp.sign(b"hello")
    assert verify(kp.public_key, b"hello", sig)


def test_verify_rejects_wrong_data():
    kp = KeyPair.generate()
    sig = kp.sign(b"hello")
    assert not verify(kp.public_key, b"tampered", sig)


def test_public_key_roundtrip():
    kp = KeyPair.generate()
    assert kp.public_key.startswith("ed25519:")
    decoded = decode_public_key(kp.public_key)
    assert decoded.public_bytes_raw() == kp.public_bytes


def test_decode_public_key_bad_prefix():
    with pytest.raises(PipError):
        decode_public_key("rsa:AAAA")


def test_instance_id_derivation():
    kp = KeyPair.generate()
    iid = instance_id_from_public_key(kp.public_key)
    assert iid.startswith("pip:")
    assert len(iid) == 4 + 26
    assert iid == iid.lower()


def test_save_load_roundtrip(tmp_path):
    kp = KeyPair.generate()
    path = tmp_path / "instance.key"
    kp.save(path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    loaded = KeyPair.load(path)
    assert loaded.public_key == kp.public_key


def test_load_insecure_perms_raises(tmp_path):
    kp = KeyPair.generate()
    path = tmp_path / "instance.key"
    kp.save(path)
    os.chmod(path, 0o644)
    with pytest.raises(InsecureKeyFileError):
        KeyPair.load(path)


def test_load_insecure_perms_allowed(tmp_path):
    kp = KeyPair.generate()
    path = tmp_path / "instance.key"
    kp.save(path)
    os.chmod(path, 0o644)
    loaded = KeyPair.load(path, allow_insecure=True)
    assert loaded.public_key == kp.public_key


def test_identity_document_valid(keypair, clock):
    doc = IdentityDocument(
        instance_id=keypair.instance_id,
        public_key=keypair.public_key,
        display_name="test",
        pip_versions=["1.0"],
        endpoints={},
        previous_keys=[],
        issued_at=clock.now(),
    )
    assert doc.instance_id == keypair.instance_id


def test_identity_document_mismatch(keypair, clock):
    other = KeyPair.generate()
    with pytest.raises(PipError):
        IdentityDocument(
            instance_id=other.instance_id,
            public_key=keypair.public_key,
            display_name="test",
            pip_versions=["1.0"],
            endpoints={},
            previous_keys=[],
            issued_at=clock.now(),
        )
