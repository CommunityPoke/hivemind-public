import pytest

from pip_protocol.canonical import canonical_json


def test_sorted_keys_no_whitespace():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_nested_determinism():
    a = {"x": [{"z": 1, "y": 2}], "b": {"d": 4, "c": 3}}
    b = {"b": {"c": 3, "d": 4}, "x": [{"y": 2, "z": 1}]}
    assert canonical_json(a) == canonical_json(b)


def test_utf8_preserved():
    assert "é".encode() in canonical_json({"k": "é"})


def test_nan_rejected():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
