import pytest

import sandbox
from sandbox import detect, reset_cache, wrap_argv


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


def _stub_which(table: dict[str, str | None]):
    def fake_which(name):
        return table.get(name)
    return fake_which


def test_detect_bwrap_when_available(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": "/usr/bin/bwrap", "firejail": None}
    ))
    s = detect()
    assert s.backend == "bwrap"
    assert s.available is True


def test_detect_firejail_when_no_bwrap(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": None, "firejail": "/usr/bin/firejail"}
    ))
    s = detect()
    assert s.backend == "firejail"
    assert s.available is True


def test_detect_none_when_neither(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": None, "firejail": None}
    ))
    s = detect()
    assert s.backend is None
    assert s.available is False
    assert "未启用" in s.description


def test_detect_caches(monkeypatch):
    calls = []

    def counting_which(name):
        calls.append(name)
        return None
    monkeypatch.setattr(sandbox.shutil, "which", counting_which)
    detect()
    detect()
    # 第一次检测 bwrap/firejail 两次；第二次走缓存不重复
    assert calls == ["bwrap", "firejail"]


def test_wrap_argv_uses_bwrap(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": "/usr/bin/bwrap", "firejail": None}
    ))
    argv, sandboxed = wrap_argv("ls -la")
    assert sandboxed is True
    assert argv[0] == "bwrap"
    assert "--ro-bind" in argv
    assert "--tmpfs" in argv
    assert "--die-with-parent" in argv
    # 原始命令完整保留在末尾
    assert argv[-3:] == ["bash", "-c", "ls -la"]


def test_wrap_argv_uses_firejail_when_no_bwrap(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": None, "firejail": "/usr/bin/firejail"}
    ))
    argv, sandboxed = wrap_argv("df -h")
    assert sandboxed is True
    assert argv[0] == "firejail"
    assert "--read-only=/etc" in argv
    assert "--read-only=/usr" in argv
    assert argv[-3:] == ["bash", "-c", "df -h"]


def test_wrap_argv_falls_through_when_unavailable(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": None, "firejail": None}
    ))
    argv, sandboxed = wrap_argv("ls")
    assert sandboxed is False
    assert argv == ["bash", "-c", "ls"]


def test_wrap_argv_preserves_complex_command(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", _stub_which(
        {"bwrap": "/usr/bin/bwrap"}
    ))
    cmd = "ls -la | grep foo && echo done"
    argv, _ = wrap_argv(cmd)
    assert argv[-1] == cmd
