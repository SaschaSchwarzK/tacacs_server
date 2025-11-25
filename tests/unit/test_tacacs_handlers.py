from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.tacacs.packet import TacacsPacket


class FakeDBLogger:
    def __init__(self, result=True):
        self.result = result

    def log_accounting(self, record):
        return self.result


def make_handlers(db_ok: bool = True) -> AAAHandlers:
    return AAAHandlers([], FakeDBLogger(result=db_ok))


def test_handle_authentication_parse_error(monkeypatch):
    handlers = make_handlers()
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        body=b"bad",
        seq_no=1,
        session_id=0x01,
    )

    # Force parse error
    from tacacs_server.tacacs import handlers as handlers_module
    from tacacs_server.utils.exceptions import ProtocolError

    monkeypatch.setattr(
        handlers_module,
        "parse_authen_start",
        lambda body: (_ for _ in ()).throw(ProtocolError("bad")),
    )

    response = handlers.handle_authentication(packet, None)

    assert isinstance(response, TacacsPacket)
    assert response.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN


def test_handle_authorization_policy_denied(monkeypatch):
    handlers = make_handlers()
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        body=b"\x00",
        seq_no=1,
        session_id=0x02,
    )

    # Provide a parsed authorization request
    monkeypatch.setattr(
        "tacacs_server.tacacs.handlers.parse_author_request",
        lambda body: {
            "priv_lvl": 15,
            "authen_service": "shell",
            "user": "user1",
            "args": {"cmd": "show run"},
        },
    )

    from tacacs_server.utils.policy import PolicyResult

    monkeypatch.setattr(
        "tacacs_server.tacacs.handlers.evaluate_policy",
        lambda ctx, lookup: PolicyResult(
            allowed=False, privilege_level=1, denial_message="denied"
        ),
    )

    # Prevent webhook side effects
    monkeypatch.setattr("tacacs_server.utils.webhook.notify", lambda *a, **k: None)

    response = handlers.handle_authorization(packet, None)

    assert isinstance(response, TacacsPacket)
    assert response.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR


def test_handle_accounting_parse_error(monkeypatch):
    handlers = make_handlers()
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        body=b"bad",
        seq_no=1,
        session_id=0x03,
    )

    from tacacs_server.utils.exceptions import ProtocolError

    monkeypatch.setattr(
        "tacacs_server.tacacs.handlers.parse_acct_request",
        lambda body: (_ for _ in ()).throw(ProtocolError("badacct")),
    )

    response = handlers.handle_accounting(packet, None)

    assert isinstance(response, TacacsPacket)
    assert response.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT


def test_process_accounting_success_and_failure(monkeypatch):
    # Patch Prometheus integration used inside _process_accounting
    class DummyProm:
        @staticmethod
        def record_accounting_record(result):
            DummyProm.last = result

    monkeypatch.setattr(
        "tacacs_server.web.monitoring.PrometheusIntegration", DummyProm, raising=False
    )

    args = {"service": "shell", "cmd": "show", "bytes_in": "1", "bytes_out": "2"}
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        body=b"",
        seq_no=1,
        session_id=0x04,
    )

    # Success path
    handlers = make_handlers(db_ok=True)
    response_ok = handlers._process_accounting(
        packet,
        "user",
        "tty0",
        "127.0.0.1",
        TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
        0,
        1,
        args,
        None,
    )
    assert response_ok.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT

    # Failure path
    handlers_fail = make_handlers(db_ok=False)
    response_fail = handlers_fail._process_accounting(
        packet,
        "user",
        "tty0",
        "127.0.0.1",
        TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START,
        0,
        1,
        args,
        None,
    )
    assert response_fail.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT


def test_authenticate_user_rate_limited(monkeypatch):
    handlers = make_handlers()

    # Force rate limiter denial
    handlers.rate_limiter.is_allowed = lambda ip: False

    allowed = handlers._authenticate_user("user", "pass", client_ip="1.1.1.1")

    assert allowed[0] is False
