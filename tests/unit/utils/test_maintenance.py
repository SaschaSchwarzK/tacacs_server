"""Unit tests for maintenance utilities."""

from tacacs_server.utils import maintenance


class DummyResource:
    def __init__(self):
        self.closed = False
        self.reloaded = False

    def close(self):
        self.closed = True

    def reload(self):
        self.reloaded = True


def test_register_and_unregister():
    """Registration should track resources and avoid duplicates."""
    mgr = maintenance._DBConnectionManager()
    res = DummyResource()
    mgr.register(res)
    mgr.register(res)  # duplicate should be ignored
    assert len(mgr._registrations) == 1
    mgr.unregister(res)
    assert not mgr._registrations


def test_enter_and_exit_maintenance_triggers_callbacks():
    """enter/exit maintenance should call close/reload and flip state."""
    mgr = maintenance._DBConnectionManager()
    res = DummyResource()
    mgr.register(res)

    mgr.enter_maintenance()
    assert mgr.is_in_maintenance() is True
    assert res.closed is True

    mgr.exit_maintenance()
    assert mgr.is_in_maintenance() is False
    # reload is optional, verify called when available
    assert res.reloaded is True
