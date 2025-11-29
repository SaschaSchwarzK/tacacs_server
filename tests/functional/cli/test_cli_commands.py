"""Functional-ish tests for CLI entrypoints."""

import sys
from types import SimpleNamespace

import tacacs_server.main as main_mod
from tacacs_server import admin_cli


class _FakeManager:
    def __init__(self, _config):
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        # Simulate clean shutdown path
        self.stop()
        return True

    def stop(self):
        self.stopped = True


def test_server_start_stop(monkeypatch, tmp_path):
    """main() should invoke TacacsServerManager.start/stop."""
    monkeypatch.chdir(tmp_path)
    seen = {}

    class RecordingManager(_FakeManager):
        def __init__(self, cfg):
            super().__init__(cfg)
            seen["instance"] = self

    monkeypatch.setattr(main_mod, "TacacsServerManager", RecordingManager)
    monkeypatch.setattr(sys, "argv", ["tacacs-server"])
    rc = main_mod.main()
    assert rc == 0
    mgr = seen.get("instance")
    assert mgr is not None
    assert mgr.started and mgr.stopped


def test_validate_config_invokes_config_loader(monkeypatch, capsys, tmp_path):
    """--validate-config should construct TacacsConfig and exit 0 on success."""
    seen = {}

    class DummyConfig:
        def __init__(self, path):
            seen["path"] = path

        def validate_config(self):
            return []

    monkeypatch.chdir(tmp_path)
    cfg_path = tmp_path / "test.conf"
    cfg_path.write_text("[server]\nhost=127.0.0.1\nport=49\n", encoding="utf-8")
    monkeypatch.setattr(main_mod, "TacacsConfig", DummyConfig)
    monkeypatch.setattr(sys, "argv", ["tacacs-server", "--validate-config", "-c", str(cfg_path)])

    rc = main_mod.main()
    captured = capsys.readouterr()
    assert rc == 0
    assert "Configuration is valid" in captured.out
    assert seen["path"] == str(cfg_path)


def test_database_init_creates_standard_dirs(monkeypatch, tmp_path):
    """main() should create default directories before starting."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main_mod, "TacacsServerManager", _FakeManager)
    monkeypatch.setattr(sys, "argv", ["tacacs-server", "--skip-startup-orchestration"])

    rc = main_mod.main()
    assert rc == 0
    for dirname in ["config", "data", "logs", "tests", "scripts"]:
        assert (tmp_path / dirname).exists()


def test_user_management_generate_bcrypt(capsys, monkeypatch):
    """Admin CLI should generate bcrypt hashes for user passwords."""
    monkeypatch.setenv("PYTHONHASHSEED", "0")  # keep hash deterministic for test
    args = SimpleNamespace(password="secret", stdin=False)
    rc = admin_cli.cmd_generate_bcrypt(args)
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out.startswith("$2")
