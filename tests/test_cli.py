import json
import os

from pip_protocol.cli import main
from pip_protocol.identity import KeyPair


def test_keygen(tmp_path, capsys):
    out = tmp_path / "k.key"
    assert main(["keygen", "--out", str(out)]) == 0
    captured = capsys.readouterr().out
    assert "instance_id: pip:" in captured
    assert "public_key:  ed25519:" in captured
    # private key material never printed
    assert KeyPair.load(out).private_bytes.hex() not in captured


def test_keygen_refuses_overwrite(tmp_path, capsys):
    out = tmp_path / "k.key"
    main(["keygen", "--out", str(out)])
    assert main(["keygen", "--out", str(out)]) == 2
    assert main(["keygen", "--out", str(out), "--force"]) == 0


def test_identity(tmp_path, capsys, monkeypatch):
    out = tmp_path / "k.key"
    main(["keygen", "--out", str(out)])
    monkeypatch.setenv("PIP_PRIVATE_KEY_FILE", str(out))
    assert main(["identity"]) == 0
    doc = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert doc["instance_id"] == KeyPair.load(out).instance_id


def test_sign(tmp_path, capsys, monkeypatch):
    out = tmp_path / "k.key"
    main(["keygen", "--out", str(out)])
    capsys.readouterr()
    monkeypatch.setenv("PIP_PRIVATE_KEY_FILE", str(out))
    monkeypatch.setenv("PIP_POLICY_FILE", str(tmp_path / "nonexistent.yaml"))
    payload = json.dumps({"subject": "s", "body": "hi"})
    rc = main(
        [
            "sign",
            "--type",
            "message",
            "--to",
            "pip:example",
            "--payload-json",
            payload,
            "--idempotency-key",
            "k1",
        ]
    )
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    assert env["type"] == "message"
    assert env["to"] == "pip:example"
    assert env["idempotency_key"] == "k1"
    assert env["sig"]["kid"].startswith("ed25519:")


def test_env_prefix_settings(monkeypatch):
    monkeypatch.setenv("PIP_DISPLAY_NAME", "tester")
    from pip_protocol.config import Settings

    s = Settings()
    assert s.display_name == "tester"
    assert "PIP_PRIVATE_KEY_FILE" not in os.environ or True
