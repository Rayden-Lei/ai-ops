import pytest

from safety import review_file_path, FileReview


@pytest.mark.parametrize("path", [
    "~/.ssh/id_rsa",
    "/root/.ssh/id_rsa",
    "/home/alice/.ssh/authorized_keys",
    ".ssh/config",
    "/etc/shadow",
    "/etc/../etc/shadow",
    "/etc/gshadow",
    "/proc/123/mem",
    "/opt/app/secret.conf",
    "/data/credentials.json",
])
def test_file_path_deny(path):
    assert review_file_path(path) == FileReview.DENY


@pytest.mark.parametrize("path", [
    "/etc/ssl/server.pem",
    "/home/bob/server.key",
    "/home/bob/.bash_history",
])
def test_file_path_warn(path):
    assert review_file_path(path) == FileReview.WARN


@pytest.mark.parametrize("path", [
    "/etc/nginx/nginx.conf",
    "/var/log/syslog",
    "/home/bob/notes.txt",
    "/etc/ssh/sshd_config",
    "/home/bob/myssh/config",
])
def test_file_path_allow(path):
    assert review_file_path(path) == FileReview.ALLOW


from safety import review_command, RiskLevel


@pytest.mark.parametrize("cmd", [
    "rm -rf /",
    "rm -rf /*",
    "mkfs.ext4 /dev/sdb",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "echo x > /dev/sda",
    "rm -rf / ; echo done",
])
def test_command_blocked(cmd):
    assert review_command(cmd).risk_level == RiskLevel.BLOCKED


@pytest.mark.parametrize("cmd", [
    "vim /etc/hosts",
    "top",
    "sudo vim /etc/hosts",
    "echo hello; vim",
    "env -i vim",
])
def test_command_interactive_blocked(cmd):
    assert review_command(cmd).risk_level == RiskLevel.BLOCKED


@pytest.mark.parametrize("cmd", [
    "rm -rf /etc",
    "rm -rf /usr/local",
    "chmod 777 /etc",
    "chown -R user /var",
    "shutdown -h now",
    "reboot",
    "iptables -F",
    "userdel bob",
])
def test_command_high(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.HIGH
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "systemctl restart nginx",
    "systemctl stop nginx",
    "kill 1234",
    "killall nginx",
    "crontab -e",
    "mv foo /etc/bar",
    "ls && systemctl restart nginx",
])
def test_command_medium(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "apt update",
    "apt-get install x",
    "dpkg -i foo.deb",
    "dpkg --remove foo",
    "snap install x",
    "yum install x",
    "dnf remove y",
    "rpm -e pkg",
    "pacman -S pkg",
    "zypper install pkg",
    "aptitude install pkg",
    "sudo apt install vim",
    "env -i apt install vim",
])
def test_command_package_manager_medium(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "ls -la",
    "df -h",
    "ps aux",
    "echo hello",
    "rm -rf /tmp/cache",
    "rm -rf ./build",
    "rm -rf ~/scratch",
    "cat /etc/nginx/nginx.conf",
])
def test_command_safe(cmd):
    assert review_command(cmd).risk_level == RiskLevel.SAFE


def test_command_empty():
    assert review_command("   ").risk_level == RiskLevel.SAFE


def test_command_parse_failure_fails_safe():
    result = review_command('echo "unbalanced')
    assert result.risk_level == RiskLevel.HIGH
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "cat /etc/shadow",
    "cat ~/.ssh/id_rsa",
    "tail -n 5 /home/alice/.ssh/authorized_keys",
    "less /etc/gshadow",
])
def test_filereader_denied_path_blocked(cmd):
    assert review_command(cmd).risk_level == RiskLevel.BLOCKED


def test_filereader_warn_path_medium():
    result = review_command("cat /etc/ssl/server.pem")
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.require_confirm is True


def test_filereader_normal_path_safe():
    assert review_command("cat /etc/nginx/nginx.conf").risk_level == RiskLevel.SAFE
