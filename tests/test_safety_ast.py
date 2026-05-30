"""bashlex AST 路径专项测试。

bashlex 缺失时整个文件 skip；运行时（含 CI）会全部跑。
覆盖：命令替换 / 进程替换 / 反引号 / 二进制白名单。
"""

import pytest

pytest.importorskip("bashlex")

from safety import RiskLevel, review_command  # noqa: E402


@pytest.mark.parametrize("cmd", [
    "echo $(date)",
    "echo $(rm -rf /)",
    "ls $(which python)",
    "cd $(dirname $0)",
])
def test_command_substitution_blocked(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.BLOCKED
    assert "替换" in result.message


@pytest.mark.parametrize("cmd", [
    "echo `date`",
    "echo `rm -rf /`",
])
def test_backtick_substitution_blocked(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.BLOCKED
    assert "替换" in result.message


@pytest.mark.parametrize("cmd", [
    "diff <(ls /a) <(ls /b)",
    "cat <(echo hi)",
    "tee >(cat) >(cat)",
])
def test_process_substitution_blocked(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.BLOCKED
    assert "替换" in result.message


@pytest.mark.parametrize("cmd", [
    "dd if=/dev/zero of=/tmp/x",
    "fdisk -l",
    "scp foo user@host:/tmp/",
    "rsync -av a/ b/",
    "nc -l 1234",
    "socat - TCP:host:80",
    "perl -e 'print 1'",
    "ruby -e 'puts 1'",
    "docker ps",
])
def test_unknown_binary_medium_confirm(cmd):
    # 非交互式 + 不在白名单 → MEDIUM+confirm（让用户决定本次放行）
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "python -c 'print(1)'",
    "python3 script.py",
    "ssh user@host",
])
def test_interactive_binary_still_blocked(cmd):
    # 交互式命令仍 BLOCKED——优先于白名单判定
    assert review_command(cmd).risk_level == RiskLevel.BLOCKED


def test_allowlist_message_for_unknown_binary():
    result = review_command("fdisk -l")
    assert result.risk_level == RiskLevel.MEDIUM
    assert "白名单" in result.message
    assert "fdisk" in result.message


@pytest.mark.parametrize("cmd", [
    "ls -la",
    "df -h",
    "ps aux",
    "systemctl status nginx",
    "journalctl -u nginx -n 50",
    "grep -r foo /etc/nginx",
    "find / -name '*.conf'",
    "curl -sS https://example.com",
    "ss -tlnp",
])
def test_allowlisted_safe_commands_pass(cmd):
    assert review_command(cmd).risk_level == RiskLevel.SAFE


def test_compound_substitution_in_segment_blocked():
    # 复合命令里只要任一段含替换，整串 BLOCKED
    assert review_command("ls; echo $(date)").risk_level == RiskLevel.BLOCKED


def test_pipeline_with_substitution_blocked():
    assert review_command("echo $(date) | cat").risk_level == RiskLevel.BLOCKED
