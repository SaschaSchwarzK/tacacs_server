"""Unit tests for TACACS session management."""

from dataclasses import dataclass

from tacacs_server.tacacs.session import SessionManager


@dataclass
class DummyGroup:
    tacacs_secret: str | None = None
    metadata: dict | None = None


@dataclass
class DummyDevice:
    group: DummyGroup | None = None


class RecordingHandlers:
    def __init__(self):
        self.cleaned = []

    def cleanup_session(self, session_id: int):
        self.cleaned.append(session_id)


def test_validate_sequence_transitions_and_reset():
    """Validate monotonic progression, rejection, and reset logic."""
    manager = SessionManager()
    assert manager.validate_sequence(0xAAAA, 1)
    assert manager.validate_sequence(0xAAAA, 3)
    assert manager.validate_sequence(0xAAAA, 5)

    # Out-of-order within window should be rejected
    assert manager.validate_sequence(0xAAAA, 3) is False

    # Large backwards jump is treated as a reset and accepted
    assert manager.validate_sequence(0xAAAA, 50) is False
    assert manager.validate_sequence(0xAAAA, 203)
    assert manager.validate_sequence(0xAAAA, 50)


def test_session_secrets_prefer_device_and_stick():
    """Ensure device/group secrets win and are reused."""
    group = DummyGroup(tacacs_secret="device-secret")
    device = DummyDevice(group=group)
    manager = SessionManager()

    secret = manager.get_or_create_secret(0xABC, device, default_secret="fallback")
    assert secret == "device-secret"

    # Subsequent lookup without device should keep existing secret
    secret2 = manager.get_or_create_secret(0xABC, None, default_secret="new-default")
    assert secret2 == "device-secret"


def test_session_lru_enforces_concurrent_limit():
    """Adding sessions beyond limit evicts oldest (simulated timeout)."""
    manager = SessionManager(max_sessions=2)
    manager.get_or_create_secret(1, None, "one")
    manager.get_or_create_secret(2, None, "two")
    manager.get_or_create_secret(3, None, "three")

    assert set(manager.session_secrets.keys()) == {2, 3}
    assert manager.session_secrets.get(1) is None

    # Touch session 2 to make it most recent, then add another
    manager.get_or_create_secret(2, None, "two")
    manager.get_or_create_secret(4, None, "four")
    assert set(manager.session_secrets.keys()) == {2, 4}


def test_cleanup_session_removes_state_and_calls_handler():
    """cleanup_session drops secrets/seq tracking and notifies handlers."""
    manager = SessionManager()
    handlers = RecordingHandlers()

    manager.get_or_create_secret(0x1234, None, "secret")
    manager.validate_sequence(0x1234, 1)

    manager.cleanup_session(0x1234, handlers=handlers)

    assert manager.session_secrets.get(0x1234) is None
    assert manager._last_request_seq.get(0x1234) is None
    assert handlers.cleaned == [0x1234]
