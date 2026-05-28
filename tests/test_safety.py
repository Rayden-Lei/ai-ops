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
