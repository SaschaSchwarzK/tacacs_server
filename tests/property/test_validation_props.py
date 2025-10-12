import pytest
from hypothesis import given
from hypothesis import strategies as st

from tacacs_server.utils.validation import InputValidator

valid_chars = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"))
    | st.sampled_from([" ", "_", ".", "-"]),
    min_size=1,
    max_size=64,
)
invalid_chars = st.text(
    alphabet=st.sampled_from(["`", "$", ";", "|", "&", "<", ">", "(", ")", "*", "#"])
)


@given(name=valid_chars)
def test_validate_safe_text_accepts_basic_names(name: str):
    out = InputValidator.validate_safe_text(name, "device name", min_len=1, max_len=64)
    assert isinstance(out, str)
    assert 1 <= len(out) <= 64


@given(name=invalid_chars)
def test_validate_safe_text_rejects_shell_sql_ldap_chars(name: str):
    with pytest.raises(Exception):
        InputValidator.validate_safe_text(name, "device name", min_len=1, max_len=64)


@given(s=st.text(min_size=0, max_size=5))
def test_validate_string_length_bounds(s: str):
    if len(s) == 0:
        with pytest.raises(Exception):
            InputValidator.validate_string_length(s, "field", min_len=1, max_len=5)
    elif len(s) <= 5:
        assert (
            InputValidator.validate_string_length(s, "field", min_len=0, max_len=5) == s
        )
    else:
        with pytest.raises(Exception):
            InputValidator.validate_string_length(s, "field", min_len=0, max_len=5)
