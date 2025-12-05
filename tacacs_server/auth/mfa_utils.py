"""Shared MFA password suffix parsing helpers."""

from __future__ import annotations


def parse_mfa_suffix(
    password: str,
    *,
    mfa_enabled: bool,
    otp_digits: int = 6,
    push_keyword: str = "push",
) -> tuple[str, str | None, bool]:
    """Parse password for MFA suffix (OTP or push keyword).

    Returns: (base_password, otp_code, push_requested)
    """
    if not mfa_enabled or not isinstance(password, str):
        return password, None, False

    pw = password.strip()
    kw = (push_keyword or "").lower()

    # Check for push keyword with separators or exact match
    if kw:
        pw_lower = pw.lower()
        for sep in (" ", "+", ":", "/", ".", "-", "#", "@", ""):
            suf = sep + kw
            if pw_lower.endswith(suf):
                base_pw = pw[: len(pw) - len(suf)]
                return base_pw, None, True

    # Check for trailing OTP digits
    d = otp_digits
    if d >= 4 and len(pw) > d and pw[-d:].isdigit():
        otp = pw[-d:]
        base_pw = pw[:-d]
        if len(base_pw) < 1:
            return password, None, False
        return base_pw, otp, False

    return password, None, False
