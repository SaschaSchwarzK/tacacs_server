import pytest

from tacacs_server.tacacs.structures import (
    parse_acct_request,
    parse_authen_start,
    parse_author_request,
)


def test_parse_authen_start_minimal():
    # action=1, priv=1, type=1, service=1, user_len=1 ('a'), port_len=0, rem_len=0, data_len=0
    body = bytes([1, 1, 1, 1, 1, 0, 0, 0]) + b"a"
    parsed = parse_authen_start(body)
    assert parsed["user"] == "a"
    assert parsed["port"] == ""
    assert parsed["rem_addr"] == ""
    assert parsed["data"] == b""


def test_parse_author_request_minimal_with_args():
    # method=1, priv=1, type=1, service=1, user_len=1 ('u'), port_len=1 ('p'), rem_len=1 ('r'), argc=2
    # arg lengths: 3 ('a=b'), 1 ('X')
    head = bytes([1, 1, 1, 1, 1, 1, 1, 2])
    lens = bytes([3, 1])
    payload = b"u" + b"p" + b"r" + lens + b"a=b" + b"X"
    parsed = parse_author_request(head + payload)
    assert parsed["user"] == "u"
    assert parsed["args"]["a"] == "b"
    assert "X" in parsed["args"] and parsed["args"]["X"] == ""


def test_parse_acct_request_minimal():
    # flags=0, method=1, priv=1, type=1, service=1, user_len=1, port_len=0, rem_len=0, argc=0
    body = bytes([0, 1, 1, 1, 1, 1, 0, 0, 0]) + b"u"
    parsed = parse_acct_request(body)
    assert parsed["user"] == "u"
    assert parsed["args"] == {}


def test_parse_short_bodies_raise():
    with pytest.raises(ValueError):
        parse_authen_start(b"\x00\x01")
    with pytest.raises(ValueError):
        parse_author_request(b"\x00")
    with pytest.raises(ValueError):
        parse_acct_request(b"")
