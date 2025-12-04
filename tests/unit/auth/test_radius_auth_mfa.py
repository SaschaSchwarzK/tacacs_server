from tacacs_server.auth.radius_auth import RADIUSAuthBackend


def test_parse_mfa_suffix_otp():
    backend = RADIUSAuthBackend({
        "radius_server": "localhost",
        "radius_secret": "secret",
        "mfa_enabled": True,
        "mfa_otp_digits": 6
    })
    
    base, otp, push = backend._parse_mfa_suffix("mypass123456")
    assert base == "mypass"
    assert otp == "123456"
    assert push == False

def test_parse_mfa_suffix_push():
    backend = RADIUSAuthBackend({
        "radius_server": "localhost",
        "radius_secret": "secret",
        "mfa_enabled": True,
        "mfa_push_keyword": "push"
    })
    
    base, otp, push = backend._parse_mfa_suffix("mypasspush")
    assert base == "mypass"
    assert otp is None
    assert push == True

def test_parse_mfa_suffix_disabled():
    backend = RADIUSAuthBackend({
        "radius_server": "localhost",
        "radius_secret": "secret",
        "mfa_enabled": False
    })
    
    base, otp, push = backend._parse_mfa_suffix("mypass123456")
    assert base == "mypass123456"  # Not parsed
    assert otp is None
    assert push == False
