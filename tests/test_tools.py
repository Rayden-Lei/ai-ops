import shlex

import pytest

import tools


class _Captured:
    """像 list[str] 一样能索引/迭代/比较的轻量代理；.raw 给完整记录。"""
    def __init__(self):
        self.raw: list[dict] = []

    def __getitem__(self, i):
        return self.raw[i]["command"]

    def __len__(self):
        return len(self.raw)

    def __iter__(self):
        return (r["command"] for r in self.raw)

    def __eq__(self, other):
        if isinstance(other, list):
            return [r["command"] for r in self.raw] == other
        return NotImplemented


@pytest.fixture
def capture_cmd(monkeypatch):
    """拦截 _run_command，记录命令与 sandbox 标志，不真正执行。"""
    cap = _Captured()

    def fake_run(command, timeout=30, request_id="", sandbox=False):
        cap.raw.append({"command": command, "sandbox": sandbox})
        return ""

    monkeypatch.setattr(tools, "_run_command", fake_run)
    return cap


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


def test_execute_command_safe_uses_sandbox(capture_cmd):
    tools.execute_command.func("ls -la")
    assert len(capture_cmd.raw) == 1
    assert capture_cmd.raw[0]["sandbox"] is True


def test_execute_command_confirmed_medium_bypasses_sandbox(capture_cmd):
    # systemctl restart 是 MEDIUM，需 confirmed=True 才执行
    tools.execute_command.func("systemctl restart nginx", confirmed=True)
    assert len(capture_cmd.raw) == 1
    assert capture_cmd.raw[0]["sandbox"] is False


def test_execute_command_blocked_not_executed(capture_cmd):
    out = tools.execute_command.func("rm -rf /")
    assert "[拦截]" in out
    assert capture_cmd.raw == []
