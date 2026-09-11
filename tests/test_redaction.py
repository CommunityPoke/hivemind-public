from pip_protocol.policy import RedactionConfig
from pip_protocol.redaction import MASK, Redactor
from pip_protocol.schemas import EnvelopeType, MessagePayload


def redactor(**kw):
    return Redactor(RedactionConfig(**kw))


def test_field_name_masked_case_insensitive():
    r = redactor(fields=["email"])
    assert r.redact_value({"Email": "a@b.c", "ok": 1}) == {"Email": MASK, "ok": 1}


def test_nested_and_list():
    r = redactor(fields=["ssn"])
    out = r.redact_value({"a": [{"SSN": "123", "b": [{"ssn": "x"}]}]})
    assert out["a"][0]["SSN"] == MASK
    assert out["a"][0]["b"][0]["ssn"] == MASK


def test_regex_pattern():
    r = redactor(patterns=[r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"])
    assert r.redact_value("mail me at a@b.com please") == f"mail me at {MASK} please"


def test_message_payload_redacted():
    r = redactor(fields=["token"], patterns=["secret\\d+"])
    p = MessagePayload(subject="s", body="the secret1", attributes={"TOKEN": "x"})
    out = r.redact_payload(EnvelopeType.MESSAGE, p)
    assert out.body == f"the {MASK}"
    assert out.attributes["TOKEN"] == MASK
    assert p.body == "the secret1"  # original untouched


def test_data_records_redacted():
    from pip_protocol.schemas import DataPayload

    r = redactor(fields=["phone"])
    p = DataPayload(op="offer", dataset="d", records=[{"phone": "1", "keep": 2}])
    out = r.redact_payload(EnvelopeType.DATA, p)
    assert out.records == [{"phone": MASK, "keep": 2}]
