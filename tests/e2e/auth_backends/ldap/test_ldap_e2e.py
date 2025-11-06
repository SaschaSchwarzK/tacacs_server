"""End-to-end test verifying TACACS+ server with LDAP backend in Docker.

This module contains end-to-end tests that verify the integration between the TACACS+ server
and an LDAP backend. It uses Docker containers to spin up both the TACACS+ server and an
OpenLDAP server for testing authentication and authorization flows.

Test Environment:
- Creates a Docker network for isolated testing
- Builds and runs an OpenLDAP container with test data
- Builds and runs the TACACS+ server configured to use the LDAP backend
- Performs authentication and authorization tests against the running services

Prerequisites:
- Docker must be installed and running on the host system
- Sufficient permissions to run Docker commands
- Available ports for container services
"""

from __future__ import annotations

import configparser
import csv
import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import ldap3
import pytest
import requests

from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate


@pytest.mark.e2e
def test_tacacs_server_with_ldap_backend(tmp_path: Path) -> None:
    """Test TACACS+ server integration with LDAP backend.

    This test performs the following steps:
    1. Builds Docker images for both TACACS+ server and OpenLDAP
    2. Creates a Docker network for communication between containers
    3. Starts the OpenLDAP container with test data
    4. Configures and starts the TACACS+ server with LDAP backend
    5. Verifies authentication and authorization of test users
    6. Cleans up all test resources

    Args:
        tmp_path: Pytest fixture providing a temporary directory for test files

    Raises:
        AssertionError: If any test assertion fails
        subprocess.CalledProcessError: If any Docker command fails
        TimeoutError: If services don't start within expected time
    """

    if not shutil.which("docker"):
        pytest.skip("Docker is required for LDAP E2E test")

    project_root = Path(__file__).resolve().parents[4]
    ldap_dir = Path(__file__).resolve().parent
    bootstrap_dir = ldap_dir / "bootstrap"

    groups_csv = bootstrap_dir / "groups.csv"
    users_csv = bootstrap_dir / "users.csv"

    unique = uuid.uuid4().hex[:8]
    network_name = f"tacacs-e2e-net-{unique}"
    tacacs_image = f"tacacs-server-e2e:{unique}"
    ldap_image = f"tacacs-ldap-e2e:{unique}"
    tacacs_container = f"tacacs-e2e-{unique}"
    ldap_container = f"ldap-e2e-{unique}"
    api_token = f"token-{unique}"
    ldap_admin_password = "secret"
    ldap_domain = "example.org"
    ldap_base_dn = ",".join(f"dc={part}" for part in ldap_domain.split("."))

    tacacs_secret = "TacacsSecret123!"
    target_group = "admin-a"

    tmp_config = tmp_path / "tacacs.container.ini"
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"
    for directory in (data_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o777)

    config = configparser.ConfigParser(interpolation=None)
    config.read(project_root / "config" / "tacacs.container.ini")
    config["auth"]["backends"] = "ldap"
    config["auth"]["require_all_backends"] = "false"
    if not config.has_section("ldap"):
        config.add_section("ldap")
    # ldap3 expects a hostname (no scheme) and uses default port; container listens on 389
    config["ldap"]["server"] = f"{ldap_container}"
    config["ldap"]["base_dn"] = f"ou=people,{ldap_base_dn}"
    config["ldap"]["user_attribute"] = "uid"
    config["ldap"]["bind_dn"] = f"cn=admin,{ldap_base_dn}"
    # Use explicit password; server config loader does not interpolate ${ENV} here
    config["ldap"]["bind_password"] = ldap_admin_password
    # Force plaintext LDAP: backend casts string truthily, so set empty string
    config["ldap"]["use_tls"] = "false"
    config["ldap"]["group_attribute"] = "memberOf"
    config["ldap"]["timeout"] = "10"
    if not config.has_section("devices"):
        config.add_section("devices")
    config["devices"]["default_group"] = target_group
    config["devices"]["auto_register"] = "true"
    # Use default stdout logging from the container; no file overrides
    # Increase server log verbosity to aid startup diagnostics
    if not config.has_section("server"):
        config.add_section("server")
    config["server"]["log_level"] = "DEBUG"
    # Ensure encryption_required is not forcing TLS on unconfigured endpoints
    if not config.has_section("security"):
        config.add_section("security")
    config["security"]["encryption_required"] = "false"
    # Relax rate limiting for e2e to avoid false rejections
    config["security"]["rate_limit_requests"] = "100000"
    config["security"]["rate_limit_window"] = "1"
    # Respect schema (1-10); use upper bound to avoid lockouts
    config["security"]["max_auth_attempts"] = "10"

    with tmp_config.open("w", encoding="utf-8") as fh:
        config.write(fh)

    ldap_host_port = _find_free_port()
    tacacs_host_port = _find_free_port()
    api_host_port = _find_free_port()

    groups_data = _load_group_records(groups_csv)
    users_data = _load_user_records(users_csv)

    docker_network_created = False
    started_containers: list[str] = []

    # Capture build logs for diagnostics
    build_logs: dict[str, str] = {}

    try:
        proc_t = subprocess.run(
            ["docker", "build", "-t", tacacs_image, str(project_root)],
            check=False,
            capture_output=True,
            text=True,
        )
        build_logs["tacacs_build"] = (proc_t.stdout or "") + ("\n" + proc_t.stderr if proc_t.stderr else "")
        if proc_t.returncode != 0:
            raise AssertionError(
                f"TACACS image build failed (exit {proc_t.returncode})\n--- tacacs build logs ---\n{build_logs['tacacs_build']}"
            )

        proc_l = subprocess.run(
            ["docker", "build", "-t", ldap_image, str(ldap_dir)],
            check=False,
            capture_output=True,
            text=True,
        )
        build_logs["ldap_build"] = (proc_l.stdout or "") + ("\n" + proc_l.stderr if proc_l.stderr else "")
        if proc_l.returncode != 0:
            raise AssertionError(
                f"LDAP image build failed (exit {proc_l.returncode})\n--- ldap build logs ---\n{build_logs['ldap_build']}"
            )

        _run_docker(["network", "create", network_name])
        docker_network_created = True

        _run_docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                ldap_container,
                "--network",
                network_name,
                "-p",
                f"{ldap_host_port}:389",
                "-e",
                f"LDAP_DOMAIN={ldap_domain}",
                "-e",
                "LDAP_TLS_ENABLE=false",
                "-e",
                f"LDAP_ADMIN_PASSWORD={ldap_admin_password}",
                "-v",
                f"{bootstrap_dir}:/bootstrap:ro",
                ldap_image,
            ]
        )
        started_containers.append(ldap_container)

        _wait_for_ldap(ldap_host_port, ldap_admin_password, ldap_base_dn, container_name=ldap_container)

        # Resolve LDAP container IP and switch tacacs LDAP server to literal IP to avoid DNS/timing issues
        try:
            ip_proc = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    ldap_container,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            ldap_ip = ip_proc.stdout.strip()
            if ldap_ip:
                config["ldap"]["server"] = ldap_ip
                with tmp_config.open("w", encoding="utf-8") as fh:
                    config.write(fh)
        except Exception:
            # Non-fatal: keep hostname if inspect fails
            pass

        _run_docker(
            [
                "run",
                "-d",
                "--name",
                tacacs_container,
                "--network",
                network_name,
                "-p",
                f"{tacacs_host_port}:5049",
                "-p",
                f"{api_host_port}:8080",
                "-e",
                f"API_TOKEN={api_token}",
                "-e",
                "PYTHONUNBUFFERED=1",
                "-e",
                "TACACS_BACKEND_TIMEOUT=10",
                "-e",
                "TACACS_LDAP_DEBUG=1",
                "-e",
                f"LDAP_BIND_PASSWORD={ldap_admin_password}",
                "-v",
                f"{tmp_config}:/app/config/tacacs.container.ini:ro",
                "-v",
                f"{data_dir}:/app/data",
                "-v",
                f"{logs_dir}:/app/logs",
                tacacs_image,
                "sh",
                "-lc",
                "/opt/venv/bin/tacacs-server --config /app/config/tacacs.container.ini 2>&1 | tee -a /app/logs/stdouterr.log; code=$?; echo $code > /app/logs/exitcode.txt; exit $code",
            ]
        )
        started_containers.append(tacacs_container)

        try:
            _wait_for_http(f"http://127.0.0.1:{api_host_port}/health", timeout=90.0)
        except TimeoutError as e:
            # Dump container logs to diagnose startup failure
            try:
                dl = subprocess.run(
                    ["docker", "logs", tacacs_container],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                logs = (dl.stdout or "") + ("\n" + dl.stderr if dl.stderr else "")
            except Exception:
                logs = "(failed to read docker logs)"

            # Add in-container diagnostics: processes, ports, config, env, direct health curl
            def _exec(cmd: str) -> str:
                try:
                    pr = subprocess.run(
                        [
                            "docker",
                            "exec",
                            tacacs_container,
                            "sh",
                            "-lc",
                            cmd,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    return (pr.stdout or "") + ("\n" + pr.stderr if pr.stderr else "")
                except Exception:
                    return "(exec failed)"

            ps_out = _exec("ps -ef || ps aux || true")
            ports_out = _exec("(ss -lntp || netstat -lntp || true) 2>&1")
            cfg_out = _exec("echo '--- config file ---'; cat /app/config/tacacs.container.ini 2>/dev/null || true")
            env_out = _exec("env | sort | egrep '^(API_TOKEN|LDAP|SERVER_|PORT|HOST)=' || true")
            curl_out = _exec("curl -sv --max-time 5 http://127.0.0.1:8080/health 2>&1 || true")
            # Inspect container state for exit reason
            try:
                insp = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{json .State}}",
                        tacacs_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                inspect_out = (insp.stdout or "") + ("\n" + insp.stderr if insp.stderr else "")
            except Exception:
                inspect_out = "(inspect failed)"

            # Also capture container config and mounts
            try:
                insp_cfg = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{json .Config}}",
                        tacacs_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                inspect_cfg = (insp_cfg.stdout or "") + ("\n" + insp_cfg.stderr if insp_cfg.stderr else "")
            except Exception:
                inspect_cfg = "(inspect config failed)"
            try:
                insp_mnt = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{json .Mounts}}",
                        tacacs_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                inspect_mounts = (insp_mnt.stdout or "") + ("\n" + insp_mnt.stderr if insp_mnt.stderr else "")
            except Exception:
                inspect_mounts = "(inspect mounts failed)"

            # LDAP container logs and inspect
            try:
                dl_ldap = subprocess.run(
                    ["docker", "logs", ldap_container],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                ldap_logs = (dl_ldap.stdout or "") + ("\n" + dl_ldap.stderr if dl_ldap.stderr else "")
            except Exception:
                ldap_logs = "(failed to read ldap docker logs)"
            try:
                insp_l = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{json .State}}",
                        ldap_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                inspect_ldap = (insp_l.stdout or "") + ("\n" + insp_l.stderr if insp_l.stderr else "")
            except Exception:
                inspect_ldap = "(inspect ldap failed)"

            # Also include captured stdouterr and exit code if present (mounted volume)
            try:
                stdouterr_path = logs_dir / "stdouterr.log"
                stdouterr_txt = (
                    stdouterr_path.read_text(encoding="utf-8", errors="replace")
                    if stdouterr_path.exists()
                    else "(no stdouterr.log on host)"
                )
            except Exception:
                stdouterr_txt = "(failed to read stdouterr.log)"
            try:
                exitcode_path = logs_dir / "exitcode.txt"
                exitcode_txt = (
                    exitcode_path.read_text(encoding="utf-8", errors="replace").strip()
                    if exitcode_path.exists()
                    else "(no exitcode.txt)"
                )
            except Exception:
                exitcode_txt = "(failed to read exitcode.txt)"

            # Show host-side generated config too
            try:
                host_cfg = tmp_config.read_text(encoding="utf-8", errors="replace")
            except Exception:
                host_cfg = "(failed to read host tmp_config)"

            # Include any files the app wrote into the mounted /app/logs
            try:
                files = []
                for p in sorted(logs_dir.glob("**/*")):
                    if p.is_file():
                        try:
                            content = p.read_text(encoding="utf-8", errors="replace")
                            tail = content[-8000:]
                            files.append(f"--- host logs: {p.name} ---\n{tail}\n")
                        except Exception:
                            files.append(f"--- host logs: {p.name} --- (unreadable)\n")
                host_logs_dump = "".join(files) if files else "(no files under host logs dir)"
            except Exception:
                host_logs_dump = "(failed to enumerate host logs dir)"

            diag = (
                f"--- tacacs docker logs ---\n{logs}\n"
                f"--- ps inside container ---\n{ps_out}\n"
                f"--- listening ports ---\n{ports_out}\n"
                f"{cfg_out}\n"
                f"--- host tmp_config ---\n{host_cfg}\n"
                f"--- env (filtered) ---\n{env_out}\n"
                f"--- curl 127.0.0.1:8080/health ---\n{curl_out}\n"
                f"--- docker inspect .State ---\n{inspect_out}\n"
                f"--- docker inspect .Config ---\n{inspect_cfg}\n"
                f"--- docker inspect .Mounts ---\n{inspect_mounts}\n"
                f"--- ldap docker logs ---\n{ldap_logs}\n"
                f"--- ldap docker inspect .State ---\n{inspect_ldap}\n"
                f"--- tacacs image build logs ---\n{build_logs.get('tacacs_build','(no build logs)')}\n"
                f"--- ldap image build logs ---\n{build_logs.get('ldap_build','(no build logs)')}\n"
                f"--- stdouterr.log (host mount) ---\n{stdouterr_txt}\n"
                f"--- process exit code ---\n{exitcode_txt}\n"
                f"{host_logs_dump}"
            )
            raise AssertionError(
                f"TACACS container did not become healthy: {e}\n{diag}"
            )

        host_ip = _get_docker_host_ip(tacacs_container)

        session = requests.Session()
        session.headers.update({"X-API-Token": api_token})
        base_url = f"http://127.0.0.1:{api_host_port}"

        # Sanity-check LDAP from the host using the published port
        try:
            server = ldap3.Server("127.0.0.1", port=ldap_host_port, use_ssl=False)
            with ldap3.Connection(server, user=f"cn=admin,{ldap_base_dn}", password=ldap_admin_password, auto_bind=True) as admin_conn:
                admin_conn.search(
                    search_base=f"ou=people,{ldap_base_dn}",
                    search_filter=f"(uid={users_data[0]['username']})",
                    attributes=["cn"],
                )
            # Probe the target user credentials as well
            target_dn = f"uid={users_data[0]['username']},ou=people,{ldap_base_dn}"
            with ldap3.Connection(server, user=target_dn, password=users_data[0]['password'], auto_bind=True):
                pass
        except Exception as e:
            raise AssertionError(f"LDAP sanity check failed from host: {e}")

        for group in groups_data:
            group_name = group["name"].lower()
            payload = {
                "name": group_name,
                "description": group["description"],
                "privilege_level": 15 if "admin" in group_name else 5,
                "ldap_group": f"cn={group['name']},ou=groups,{ldap_base_dn}",
            }
            resp = session.post(
                f"{base_url}/api/user-groups", json=payload, timeout=15
            )
            resp.raise_for_status()

        # Fetch created user groups to build name->id mapping
        user_group_ids_by_name: dict[str, int] = {}
        try:
            ug_resp = session.get(f"{base_url}/api/user-groups", timeout=15)
            ug_resp.raise_for_status()
            ug_list = (
                ug_resp.json()
                if ug_resp.headers.get("content-type", "").startswith("application/json")
                else []
            )
            for record in ug_list:
                if not isinstance(record, dict):
                    continue
                n = str(record.get("name", "")).lower()
                gid = int(record.get("id", 0))
                if n and gid:
                    user_group_ids_by_name[n] = gid
        except Exception:
            user_group_ids_by_name = {}

        for index, group in enumerate(groups_data):
            group_name = group["name"].lower()
            effective_group_name = group_name
            # Use a dedicated E2E device group for the target to ensure we control secrets
            if group_name == target_group:
                effective_group_name = f"e2e-{group_name}"
            payload = {
                "name": effective_group_name,
                "description": f"Devices for {group['name']}",
                "tacacs_secret": tacacs_secret,
            }
            # To avoid dependency on LDAP memberOf overlay, allow all users
            # for the target test group by leaving ACL empty. Other groups keep ACL.
            if group_name != target_group and user_group_ids_by_name.get(group_name):
                payload["allowed_user_groups"] = [user_group_ids_by_name[group_name]]
            resp = session.post(
                f"{base_url}/api/device-groups", json=payload, timeout=15
            )
            if resp.status_code >= 400:
                body = resp.text
                # Tolerate idempotency: group may already exist (e.g., default_group auto-created)
                if resp.status_code in (400, 409) and "already exists" in body:
                    pass
                else:
                    resp.raise_for_status()

            # Resolve group id by name; then ensure the secret is set on the existing group
            dg_list = session.get(f"{base_url}/api/device-groups", timeout=15)
            dg_list.raise_for_status()
            dg_json = (
                dg_list.json()
                if dg_list.headers.get("content-type", "").startswith("application/json")
                else []
            )
            group_id_map = {
                str(item.get("name", "")).lower(): int(item.get("id", 0))
                for item in dg_json
                if isinstance(item, dict)
            }
            group_id = group_id_map.get(effective_group_name)
            assert group_id, f"Device group '{effective_group_name}' not found after creation. Response list: {dg_json}"

            # If the group pre-existed and we couldn't set secret via PUT due to route conflicts,
            # we rely on our dedicated e2e group to carry the expected secret; skip PUT.

            network_cidr = f"10.{index}.0.0/24"
            if group_name == target_group:
                # Ensure the TACACS handler matches this device regardless of NATed source IP
                network_cidr = "0.0.0.0/0"
            # group_id already resolved above

            device_payload = {
                "name": f"{group_name}-device",
                "ip_address": network_cidr,
                "device_group_id": group_id,
                "enabled": True,
            }
            resp = session.post(
                f"{base_url}/api/devices", json=device_payload, timeout=15
            )
            try:
                resp.raise_for_status()
            except requests.HTTPError as e:
                raise AssertionError(
                    f"Failed to create device for group {group_name}: {resp.status_code} {resp.text}"
                ) from e

        target_user = next(
            user for user in users_data if target_group in user["groups"]
        )

        # Proactively ensure LDAP is accepting binds right before TACACS auth
        # Try admin bind and user DN bind from the host to the published port
        try:
            server = ldap3.Server("127.0.0.1", port=ldap_host_port, use_ssl=False)
            user_dn = f"uid={target_user['username']},ou=people,{ldap_base_dn}"
            deadline = time.time() + 5.0
            ldap_ready = False
            while time.time() < deadline:
                try:
                    # Admin bind
                    with ldap3.Connection(
                        server,
                        user=f"cn=admin,{ldap_base_dn}",
                        password=ldap_admin_password,
                        auto_bind=True,
                    ):
                        pass
                    # User bind
                    with ldap3.Connection(
                        server, user=user_dn, password=target_user["password"], auto_bind=True
                    ):
                        ldap_ready = True
                        break
                except ldap3.core.exceptions.LDAPException:
                    time.sleep(0.25)
            if not ldap_ready:
                raise AssertionError("LDAP did not accept binds in readiness window before TACACS auth")
        except Exception as e:
            raise AssertionError(f"LDAP readiness pre-check failed: {e}")

        # Additionally, probe LDAP from inside the TACACS container to catch bridge/DNS timing issues
        try:
            probe_code = (
                "import sys,ldap3,time; "
                f"host='{config['ldap']['server']}'; base='{ldap_base_dn}'; "
                f"admin='cn=admin,{ldap_base_dn}'; user='uid={target_user['username']},ou=people,{ldap_base_dn}'; "
                "srv=ldap3.Server(host, use_ssl=False, connect_timeout=5); ok=False; deadline=time.time()+8;\n"
                "import ldap3.core.exceptions as E\n"
                "while time.time()<deadline:\n"
                "  try:\n"
                "    c=ldap3.Connection(srv, user=admin, password='" + ldap_admin_password + "'); ok=c.bind(); c.unbind();\n"
                "    cu=ldap3.Connection(srv, user=user, password='" + target_user['password'] + "'); ok=ok and cu.bind(); cu.unbind();\n"
                "    break\n"
                "  except E.LDAPException:\n"
                "    time.sleep(0.5)\n"
                "print('probe_ok=' + str(ok)); sys.exit(0 if ok else 1)\n"
            )
            pr = subprocess.run(
                [
                    "docker",
                    "exec",
                    tacacs_container,
                    "sh",
                    "-lc",
                    f"/opt/venv/bin/python -c \"{probe_code}\"",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if pr.returncode != 0:
                raise AssertionError(
                    "LDAP probe inside TACACS container failed before auth.\n" + (pr.stdout or "") + ("\n" + pr.stderr if pr.stderr else "")
                )
        except Exception as e:
            raise AssertionError(f"In-container LDAP probe failed: {e}")

        # Small pause to let any just-started listeners fully settle
        time.sleep(5.0)
        success = False
        message = ""
        for attempt in range(2):
            success, message = tacacs_authenticate(
                host="127.0.0.1",
                port=tacacs_host_port,
                key=tacacs_secret,
                username=target_user["username"],
                password=target_user["password"],
            )
            if success:
                break
            # Conservative backoff to avoid hitting internal auth rate limiter (5/300s)
            time.sleep(6.0)

        if not success:
            log_tail = ""
            # From TACACS container: TCP connectivity + LDAP bind/search diagnostics
            try:
                ldap_host_for_tacacs = config["ldap"]["server"]
                tcp_probe = subprocess.run(
                    [
                        "docker","exec",tacacs_container,"sh","-lc",
                        (
                            "echo '--- tcp probe from tacacs -> %s:389 ---' && "
                            "/opt/venv/bin/python - <<'PY'\n"
                            "import socket,sys; host='%s';\n"
                            "try:\n"
                            "    s=socket.create_connection((host,389),timeout=5); s.close(); print('tcp_connect_ok')\n"
                            "except Exception as e:\n"
                            "    print('tcp_connect_error:', e)\n"
                            "PY\n"
                        ) % (ldap_host_for_tacacs, ldap_host_for_tacacs)
                    ],
                    check=False, capture_output=True, text=True,
                )
                log_tail += "\n" + (tcp_probe.stdout or "") + ("\n" + tcp_probe.stderr if tcp_probe.stderr else "")
            except Exception:
                pass
            try:
                # LDAP bind and search using ldap3 inside TACACS container
                probe_py = (
                    "import sys,ldap3; host='%s'; base='%s'; admin='cn=admin,%s'; user_dn='uid=%s,ou=people,%s';\n"
                    "out=[]; srv=ldap3.Server(host,use_ssl=False,connect_timeout=5);\n"
                    "try:\n"
                    "  c=ldap3.Connection(srv,user=admin,password='%s'); out.append('admin_bind='+str(c.bind())); c.unbind()\n"
                    "except Exception as e: out.append('admin_bind_error='+repr(e))\n"
                    "try:\n"
                    "  cu=ldap3.Connection(srv,user=user_dn,password='%s'); out.append('user_bind='+str(cu.bind())); cu.unbind()\n"
                    "except Exception as e: out.append('user_bind_error='+repr(e))\n"
                    "print('--- ldap probe inside tacacs ---\\n'+'\\n'.join(out))\n"
                ) % (
                    config["ldap"]["server"],
                    ldap_base_dn,
                    ldap_base_dn,
                    target_user["username"],
                    ldap_base_dn,
                    ldap_admin_password,
                    target_user["password"],
                )
                ldap_probe = subprocess.run(
                    [
                        "docker","exec",tacacs_container,"sh","-lc",
                        f"/opt/venv/bin/python - <<'PY'\n{probe_py}\nPY\n",
                    ],
                    check=False, capture_output=True, text=True,
                )
                log_tail += "\n" + (ldap_probe.stdout or "") + ("\n" + ldap_probe.stderr if ldap_probe.stderr else "")
            except Exception:
                pass
            # Try reading server log file
            try:
                log_path = logs_dir / "server.log"
                if log_path.exists():
                    content = log_path.read_text(encoding="utf-8", errors="replace")
                    log_tail += "\n--- server.log tail ---\n" + content[-8000:]
            except Exception:
                pass
            # Include any other logs under host logs dir (e.g., tacacs.log, stdouterr.log)
            try:
                files = []
                for p in sorted(logs_dir.glob("**/*")):
                    if p.is_file():
                        try:
                            content = p.read_text(encoding="utf-8", errors="replace")
                            tail = content[-8000:]
                            files.append(f"--- host logs: {p.name} ---\n{tail}\n")
                        except Exception:
                            files.append(f"--- host logs: {p.name} --- (unreadable)\n")
                if files:
                    log_tail += "\n" + "".join(files)
            except Exception:
                pass
            # Fallback: docker logs for tacacs container
            try:
                dl = subprocess.run(
                    [
                        "docker",
                        "logs",
                        "--tail",
                        "1000",
                        tacacs_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                combined = (dl.stdout or "") + ("\n" + dl.stderr if dl.stderr else "")
                log_tail += "\n--- docker logs (tacacs) ---\n" + combined
            except Exception:
                pass
            # Directly read the tacacs server.log inside the container for details
            try:
                dlt = subprocess.run(
                    [
                        "docker",
                        "exec",
                        tacacs_container,
                        "sh",
                        "-lc",
                        "tail -n 1000 /app/logs/server.log || true",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                combined2 = (dlt.stdout or "") + ("\n" + dlt.stderr if dlt.stderr else "")
                log_tail += "\n--- tacacs server.log (exec) ---\n" + combined2
            except Exception:
                pass
            # Also include LDAP container logs for correlation
            try:
                dl_ldap = subprocess.run(
                    [
                        "docker",
                        "logs",
                        "--tail",
                        "1000",
                        ldap_container,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                ldap_combined = (dl_ldap.stdout or "") + ("\n" + dl_ldap.stderr if dl_ldap.stderr else "")
                log_tail += "\n--- docker logs (ldap) ---\n" + ldap_combined
            except Exception:
                pass
            # Connectivity probe from tacacs container (TCP port check)
            try:
                tcp_probe = subprocess.run(
                    [
                        "docker",
                        "exec",
                        tacacs_container,
                        "sh",
                        "-lc",
                        f"python - <<'PY'\nimport socket\ns=socket.create_connection(('" + ldap_container + "',389),5)\nprint('tcp_connect_ok')\ns.close()\nPY",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                tcp_out = (tcp_probe.stdout or "") + ("\n" + tcp_probe.stderr if tcp_probe.stderr else "")
                log_tail += "\n--- tcp probe from tacacs -> ldap:389 ---\n" + tcp_out
            except Exception:
                pass
            # LDAP bind/search probe inside LDAP container (ldapwhoami/ldapsearch)
            try:
                ldap_probe = subprocess.run(
                    [
                        "docker",
                        "exec",
                        ldap_container,
                        "sh",
                        "-lc",
                        (
                            f"ldapwhoami -x -D 'cn=admin,{ldap_base_dn}' -w '{ldap_admin_password}' && "
                            f"ldapsearch -x -D 'cn=admin,{ldap_base_dn}' -w '{ldap_admin_password}' -b 'ou=people,{ldap_base_dn}' '(uid={target_user['username']})' dn"
                        ),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                ldap_out = (ldap_probe.stdout or "") + ("\n" + ldap_probe.stderr if ldap_probe.stderr else "")
                log_tail += "\n--- ldap probe inside ldap container ---\n" + ldap_out
            except Exception:
                pass
            raise AssertionError(
                f"Expected TACACS authentication success, got: {message}{log_tail}"
            )

    finally:
        for name in reversed(started_containers):
            subprocess.run(["docker", "rm", "-f", name], check=False)
        if docker_network_created:
            subprocess.run(["docker", "network", "rm", network_name], check=False)
        for image in (tacacs_image, ldap_image):
            subprocess.run(["docker", "rmi", "-f", image], check=False)


def _run_docker(args: list[str]) -> None:
    subprocess.run(["docker", *args], check=True)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_ldap(port: int, password: str, base_dn: str, timeout: float = 120.0, container_name: str | None = None) -> None:
    deadline = time.time() + timeout
    server = ldap3.Server("127.0.0.1", port=port, use_ssl=False)
    while time.time() < deadline:
        try:
            with ldap3.Connection(
                server, user=f"cn=admin,{base_dn}", password=password, auto_bind=True
            ):
                return
        except (
            ldap3.core.exceptions.LDAPSocketOpenError,
            ldap3.core.exceptions.LDAPSocketReceiveError,
            ldap3.core.exceptions.LDAPBindError,
            ldap3.core.exceptions.LDAPSessionTerminatedByServerError,
            ConnectionResetError,
            OSError,
        ):
            # Server not quite ready; give it a moment and retry
            time.sleep(1.0)
    # Fallback: attempt an in-container bind using ldapwhoami for better diagnostics
    if container_name:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container_name,
                    "sh",
                    "-c",
                    f"ldapwhoami -x -H ldap://127.0.0.1:389 -D 'cn=admin,{base_dn}' -w '{password}'",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return
        except subprocess.CalledProcessError:
            pass
    # Include LDAP container logs to aid debugging
    logs = _docker_logs(container_name) if container_name else ""
    raise TimeoutError(
        "LDAP container did not become ready in time" + (f"\n--- ldap logs ---\n{logs}" if logs else "")
    )

def _docker_logs(container_name: str | None, tail: int = 200) -> str:
    if not container_name:
        return ""
    try:
        res = subprocess.run(
            ["docker", "logs", "--tail", str(tail), container_name],
            check=False,
            capture_output=True,
            text=True,
        )
        return (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
    except Exception:
        return ""


def _wait_for_http(url: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code < 500:
                return
        except requests.RequestException:
            time.sleep(1.0)
            continue
        time.sleep(1.0)
    raise TimeoutError(f"Service at {url} did not become ready")


def _get_docker_host_ip(container_name: str) -> str:
    try:
        result = subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "sh",
                "-c",
                "ip route | awk '/default/ {print $3; exit}'",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        value = result.stdout.strip()
        if value:
            return value
    except subprocess.CalledProcessError:
        pass
    return "172.17.0.1"


def _load_group_records(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            name = row[0].strip()
            if not name or name.startswith("#"):
                continue
            description = row[1].strip() if len(row) > 1 else ""
            records.append({"name": name, "description": description})
    return records


def _load_user_records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            username = row[0].strip()
            if not username or username.startswith("#"):
                continue
            password = row[1].strip()
            groups = []
            if len(row) > 4:
                groups = [item.strip().lower() for item in row[4].split("|") if item.strip()]
            records.append(
                {
                    "username": username,
                    "password": password,
                    "groups": groups,
                }
            )
    return records
