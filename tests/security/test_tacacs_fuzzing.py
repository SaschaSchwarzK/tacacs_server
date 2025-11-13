"""
TACACS+ Protocol Fuzzing Tests

This module uses property-based testing (fuzzing) to probe the TACACS+
protocol implementation for vulnerabilities, particularly in packet and
message parsing. The goal is to uncover defects that could lead to denial of
service, information disclosure, or other security weaknesses.

Test Coverage:
- TACACS+ packet header parsing
- Authentication message body parsing
- Authorization message body parsing
- Accounting message body parsing

Methodology:
- `hypothesis` is used to generate a wide range of unexpected and malformed
  inputs.
- Tests focus on ensuring that parsing functions are resilient and do not
  crash or behave unexpectedly when processing invalid data.
- Assertions verify that malformed inputs either raise expected exceptions
  (e.g., ProtocolError) or are handled gracefully without causing crashes.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.structures import (
    parse_acct_request,
    parse_authen_start,
    parse_author_request,
)
from tacacs_server.utils.exceptions import ProtocolError


@given(st.binary())
def test_fuzz_unpack_header(data):
    """
    Fuzz test for TacacsPacket.unpack_header.

    This test feeds arbitrary byte strings into the header unpacking logic
    to ensure it doesn't crash on malformed input.
    """
    try:
        TacacsPacket.unpack_header(data)
    except ProtocolError:
        # This is an expected outcome for malformed data
        pass
    except Exception as e:
        pytest.fail(f"Unexpected exception during header unpacking: {e}")


@given(st.binary())
def test_fuzz_parse_authen_start(body):
    """
    Fuzz test for parse_authen_start.

    This test feeds arbitrary byte strings into the authentication start
    message parsing logic.
    """
    try:
        parse_authen_start(body)
    except ProtocolError:
        # Expected for malformed bodies
        pass
    except Exception as e:
        pytest.fail(f"Unexpected exception during authen_start parsing: {e}")


@given(st.binary())
def test_fuzz_parse_author_request(body):
    """
    Fuzz test for parse_author_request.

    This test feeds arbitrary byte strings into the authorization request
    message parsing logic.
    """
    try:
        parse_author_request(body)
    except ProtocolError:
        # Expected for malformed bodies
        pass
    except Exception as e:
        pytest.fail(f"Unexpected exception during author_request parsing: {e}")


@given(st.binary())
def test_fuzz_parse_acct_request(body):
    """
    Fuzz test for parse_acct_request.

    This test feeds arbitrary byte strings into the accounting request
    message parsing logic.
    """
    try:
        parse_acct_request(body)
    except ProtocolError:
        # Expected for malformed bodies
        pass
    except Exception as e:
        pytest.fail(f"Unexpected exception during acct_request parsing: {e}")
