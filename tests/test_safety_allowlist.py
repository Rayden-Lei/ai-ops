import json

import pytest

import safety_allowlist
from safety_allowlist import (
    DEFAULT_ALLOWLIST,
    get_allowlist,
    is_allowed,
    load_allowlist,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


@pytest.fixture
def isolated_user_path(tmp_path, monkeypatch):
    """把 USER_ALLOWLIST_PATH 指向 tmp_path/allow.json（默认不存在）。"""
    p = tmp_path / "allow.json"
    monkeypatch.setattr(safety_allowlist, "USER_ALLOWLIST_PATH", p)
    return p


@pytest.mark.parametrize("cmd", [
    "systemctl", "ps", "df", "ss", "journalctl", "grep", "find",
    "rm", "chmod", "curl", "ip", "tail", "awk",
])
def test_default_contains_common_ops(cmd):
    assert cmd in DEFAULT_ALLOWLIST


@pytest.mark.parametrize("cmd", [
    "dd", "mkfs", "mkfs.ext4", "fdisk", "parted", "modprobe", "sysctl",
    "python", "python3", "perl", "ruby", "node",
    "bash", "sh", "zsh",
    "ssh", "scp", "sftp", "rsync",
    "nc", "ncat", "socat",
])
def test_default_excludes_dangerous(cmd):
    assert cmd not in DEFAULT_ALLOWLIST


def test_is_allowed_basename(isolated_user_path):
    assert is_allowed("ps")
    assert is_allowed("/usr/bin/ps")
    assert is_allowed("/sbin/ifconfig")


def test_is_allowed_excludes(isolated_user_path):
    assert not is_allowed("dd")
    assert not is_allowed("/usr/bin/dd")


def test_is_allowed_empty(isolated_user_path):
    assert not is_allowed("")
    assert not is_allowed("/")


def test_user_allowlist_extends_default(isolated_user_path):
    isolated_user_path.write_text(json.dumps(["dd", "fdisk"]))
    allowlist = load_allowlist()
    assert "dd" in allowlist
    assert "fdisk" in allowlist
    assert "ps" in allowlist
    assert "systemctl" in allowlist


def test_user_allowlist_invalid_format_falls_back(isolated_user_path):
    isolated_user_path.write_text(json.dumps({"not": "an array"}))
    assert load_allowlist() == DEFAULT_ALLOWLIST


def test_user_allowlist_broken_json_falls_back(isolated_user_path):
    isolated_user_path.write_text("{ broken json")
    assert load_allowlist() == DEFAULT_ALLOWLIST


def test_user_allowlist_nonstring_entries_falls_back(isolated_user_path):
    isolated_user_path.write_text(json.dumps(["ok", 123]))
    assert load_allowlist() == DEFAULT_ALLOWLIST


def test_user_allowlist_empty_array_keeps_default(isolated_user_path):
    isolated_user_path.write_text(json.dumps([]))
    assert load_allowlist() == DEFAULT_ALLOWLIST


def test_get_allowlist_caches(isolated_user_path):
    a = get_allowlist()
    b = get_allowlist()
    assert a is b


def test_reset_cache_reloads(isolated_user_path):
    a = get_allowlist()
    isolated_user_path.write_text(json.dumps(["xyz_custom"]))
    reset_cache()
    b = get_allowlist()
    assert "xyz_custom" in b
    assert "xyz_custom" not in a
