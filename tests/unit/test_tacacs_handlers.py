import struct

from tacacs_server.tacacs.constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_TYPE,
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


class CaptureDBLogger:
    def __init__(self):
        self.records = []

    def log_accounting(self, record):
        self.records.append(record)
        return True


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


def test_accounting_more_flag_records_update(monkeypatch):
    """Accounting with MORE flag should be treated as update, not unknown."""
    db_logger = CaptureDBLogger()
    handlers = AAAHandlers([], db_logger)
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        seq_no=1,
        session_id=0x0BADF00D,
        flags=0,
        body=b"",
    )
    # Flags: MORE only
    resp = handlers._process_accounting(
        packet=packet,
        user="acctuser",
        port="ttyS0",
        rem_addr="127.0.0.1",
        flags=TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_MORE,
        service=0,
        priv_lvl=1,
        args={"service": "shell", "cmd": "show version"},
        device=None,
    )
    # Response should be success
    assert resp.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT
    server_msg_len, data_len, status = struct.unpack("!HHH", resp.body[:6])
    assert status == TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS
    # DB record should be logged with UPDATE status
    assert db_logger.records, "Accounting record not logged"
    assert db_logger.records[0].status == "UPDATE"
    assert db_logger.records[0].cause is None


def test_accounting_cause_is_recorded():
    """Ensure accounting cause arg is captured."""
    db_logger = CaptureDBLogger()
    handlers = AAAHandlers([], db_logger)
    packet = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        seq_no=1,
        session_id=0x0BADF00D,
        flags=0,
        body=b"",
    )
    resp = handlers._process_accounting(
        packet=packet,
        user="acctuser",
        port="ttyS0",
        rem_addr="127.0.0.1",
        flags=TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP,
        service=0,
        priv_lvl=1,
        args={"service": "shell", "cmd": "show version", "cause": "IDLE-TIMEOUT"},
        device=None,
    )
    assert resp.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT
    server_msg_len, data_len, status = struct.unpack("!HHH", resp.body[:6])
    assert status == TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS
    assert db_logger.records, "Accounting record not logged"
    assert db_logger.records[0].cause == "IDLE-TIMEOUT"


def test_ascii_flow_prompts_for_missing_username_and_password(monkeypatch):
    """ASCII auth should prompt for username then password when both are missing."""
    handlers = make_handlers()

    # Force auth success when a password is provided
    monkeypatch.setattr(
        handlers, "_authenticate_user", lambda *a, **k: (True, "backend=fake")
    )
    monkeypatch.setattr(
        handlers, "_enforce_device_group_policy", lambda *a, **k: (True, None)
    )

    # START: no username/password (ulen=0, dlen=0) -> expect GETUSER
    start_body = struct.pack(
        "!BBBBBBBB",
        1,  # action login
        1,  # priv_lvl
        TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII,
        1,  # service login
        0,  # ulen
        0,  # plen
        0,  # rlen
        0,  # dlen
    )
    start_pkt = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=1,
        session_id=0xAA01,
        body=start_body,
    )
    resp1 = handlers.handle_authentication(start_pkt, None)
    assert resp1.body[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETUSER

    # CONTINUE seq=2: provide username in data field (user_msg_len=0, data_len>0) -> expect GETPASS
    username = b"routeruser"
    cont_user_body = struct.pack("!HHB", 0, len(username), 0) + username
    cont_user_pkt = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=2,
        session_id=0xAA01,
        body=cont_user_body,
    )
    resp2 = handlers.handle_authentication(cont_user_pkt, None)
    assert resp2.body[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS

    # CONTINUE seq=3: provide password in user_msg (user_msg_len>0, data_len=0) -> expect PASS
    password = b"Sup3rSecret!"
    cont_pass_body = struct.pack("!HHB", len(password), 0, 0) + password
    cont_pass_pkt = TacacsPacket(
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=3,
        session_id=0xAA01,
        body=cont_pass_body,
    )
    resp3 = handlers.handle_authentication(cont_pass_pkt, None)
    assert resp3.body[0] == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS
