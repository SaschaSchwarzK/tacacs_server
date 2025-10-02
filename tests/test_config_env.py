from pathlib import Path

from tacacs_server.config.config import TacacsConfig
from tacacs_server.web.admin.routers import _sanitize_config_data


def _write_config(path: Path, port: int, host: str) -> None:
    path.write_text(
        """
[server]
host = {host}
port = {port}
secret_key = envsecret
log_level = INFO
max_connections = 10
socket_timeout = 20
""".strip().format(host=host, port=port)
    )


def test_config_env_file(monkeypatch, tmp_path):
    cfg_file = tmp_path / "env.conf"
    _write_config(cfg_file, 5555, "127.0.0.1")

    monkeypatch.setenv("TACACS_CONFIG", str(cfg_file))
    config = TacacsConfig()

    server_cfg = config.get_server_config()
    assert server_cfg['port'] == 5555
    assert server_cfg['host'] == "127.0.0.1"
    assert config.config_file == str(cfg_file)

    monkeypatch.delenv("TACACS_CONFIG", raising=False)


def test_sanitize_config_masks_sensitive_fields():
    sample = {
        "server": {
            "host": "127.0.0.1",
            "secret_key": "supersecret",
        },
        "auth": {
            "password": "plain",
            "backends": ["local"],
        },
        "metadata": {
            "custom_secret": "abc",
            "nested": {"api_token": "token"},
        },
    }

    sanitized = _sanitize_config_data(sample)

    assert sanitized["server"]["host"] == "127.0.0.1"
    assert sanitized["auth"]["backends"] == ["local"]
    assert sanitized["server"]["secret_key"].startswith("[redacted")
    assert sanitized["auth"]["password"].startswith("[redacted")
    assert sanitized["metadata"]["custom_secret"].startswith("[redacted")
    assert sanitized["metadata"]["nested"]["api_token"].startswith("[redacted")



def test_config_env_url(monkeypatch, tmp_path):
    cfg_file = tmp_path / "env_url.conf"
    _write_config(cfg_file, 6000, "10.0.0.1")

    monkeypatch.setenv("TACACS_CONFIG", cfg_file.as_uri())
    config = TacacsConfig()

    server_cfg = config.get_server_config()
    assert server_cfg['port'] == 6000
    assert server_cfg['host'] == "10.0.0.1"
    assert config.config_file is None

    monkeypatch.delenv("TACACS_CONFIG", raising=False)
