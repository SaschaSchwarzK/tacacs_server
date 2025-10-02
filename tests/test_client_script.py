
def test_test_client_script_runs(run_test_client, server_process):
    host = server_process["host"]
    port = server_process["port"]
    secret = server_process["secret"]

    result = run_test_client(host, port, secret, username="admin", password="admin123")
    assert result.returncode == 0, (
        f"Test client failed: {result.stdout}\n{result.stderr}"
    )

    # Accept several possible success messages emitted by different 
    # client implementations
    ok_markers = [
        "OK",
        "Connected",
        "PASSED",
        "Authentication PASSED",
        "Authentication successful",
        "✓ Authentication PASSED",
        "Authentication accepted",
        "✅ Authentication accepted"
    ]
    assert any(marker in result.stdout for marker in ok_markers), (
        f"Unexpected test client output:\n{result.stdout}\n{result.stderr}"
    )
