import shlex

import pytest

import tools


@pytest.fixture
def capture_cmd(monkeypatch):
    """拦截 _run_command，记录构造出的命令，不真正执行。"""
    captured = []

    def fake_run(command, timeout=30, request_id=""):
        captured.append(command)
        return ""

    monkeypatch.setattr(tools, "_run_command", fake_run)
    return captured


def test_check_service_quotes_name(capture_cmd):
    payload = "nginx; rm -rf ~"
    tools.check_service.func(payload)
    assert any(shlex.quote(payload) in c for c in capture_cmd)
    assert all("; rm -rf ~" not in c.replace(shlex.quote(payload), "") for c in capture_cmd)


def test_check_disk_quotes_path(capture_cmd):
    payload = "/; rm -rf ~"
    tools.check_disk.func(payload)
    assert shlex.quote(payload) in capture_cmd[0]


def test_network_check_quotes_target(capture_cmd):
    payload = "x$(whoami)"
    tools.network_check.func(payload)
    assert shlex.quote(payload) in capture_cmd[0]


def test_check_log_quotes_unit_and_since(capture_cmd):
    tools.check_log.func(unit="ng; rm -rf ~", since="1h; reboot")
    assert shlex.quote("ng; rm -rf ~") in capture_cmd[0]
    assert shlex.quote("1h; reboot") in capture_cmd[0]


def test_check_port_rejects_non_int(capture_cmd):
    out = tools.check_port.func("22; rm -rf ~")
    assert "无效端口" in out
    assert capture_cmd == []


def test_check_port_int_ok(capture_cmd):
    tools.check_port.func(8080)
    assert "8080" in capture_cmd[0]


def test_check_process_rejects_non_int(capture_cmd):
    out = tools.check_process.func(limit="20; rm -rf ~")
    assert "无效 limit" in out
    assert capture_cmd == []


def test_check_log_rejects_non_int_lines(capture_cmd):
    out = tools.check_log.func(lines="100; rm -rf ~")
    assert "无效 lines" in out
    assert capture_cmd == []
