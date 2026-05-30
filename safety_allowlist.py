"""二进制白名单：strict whitelist 模式。

只放行 DEFAULT_ALLOWLIST 中的二进制；其余一律被 safety 层 BLOCKED。
用户可通过 ~/.aiops/safety_allowlist.json（JSON 字符串数组）追加自定义条目，
追加而非替换默认名单。

设计取舍：
- 包含所有 ops 常用诊断/维护工具（systemctl/ps/df/grep/find/curl 等）
- 已有 patterns 覆盖的"已知风险写操作"也在列（rm/chmod/chown/systemctl restart
  会先被 patterns 标 HIGH/MEDIUM；白名单只决定"能否被允许进入分级流程"）
- 故意排除：dd/mkfs/fdisk/parted、modprobe/sysctl、ssh/scp/rsync、
  python/bash/perl 等脚本宿主、netcat/socat 等"任意通信"工具
- 交互式命令（vim/top/python 等）由 safety.INTERACTIVE_COMMANDS 单独 BLOCKED，
  此处不重复
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

USER_ALLOWLIST_PATH = Path.home() / ".aiops" / "safety_allowlist.json"

DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    # 系统信息
    "uname", "hostname", "hostnamectl", "uptime", "whoami", "id",
    "w", "who", "last", "lastlog",
    # 进程
    "ps", "pgrep", "pidof", "lsof", "fuser",
    "nice", "renice", "taskset", "nohup", "timeout",
    "kill", "killall", "pkill",
    # 资源
    "free", "vmstat", "mpstat", "iostat", "sar",
    # 磁盘/挂载（只读视角）
    "df", "du", "lsblk", "blkid", "findmnt", "mountpoint",
    # 网络
    "ip", "ifconfig", "ss", "netstat", "route", "arp",
    "ping", "traceroute", "dig", "nslookup", "host", "mtr",
    "curl", "wget",
    "iptables", "ip6tables",
    # 日志
    "journalctl", "dmesg",
    # 服务管理（restart/stop 由 patterns 拦 MEDIUM+confirm）
    "systemctl", "service",
    # 文件查询/属性
    "ls", "stat", "file", "readlink", "realpath", "find", "locate",
    "basename", "dirname", "which", "type", "command",
    "getfacl", "getcap",
    # 文件读取
    "cat", "head", "tail", "nl", "od", "xxd", "strings", "tac",
    # 文本处理
    "grep", "egrep", "fgrep", "awk", "gawk", "sed",
    "cut", "tr", "sort", "uniq", "wc", "paste", "join", "comm",
    "diff", "cmp", "tee",
    # 文件操作（rm/chmod 777/chown -R 由 patterns 拦 HIGH+confirm）
    "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln",
    "chmod", "chown", "chgrp",
    # 计划任务
    "crontab",
    # 系统关停（HIGH+confirm，由 patterns 拦）
    "shutdown", "reboot", "halt", "poweroff",
    # 用户/组管理（HIGH+confirm，由 patterns 拦）
    "useradd", "userdel", "usermod",
    "groupadd", "groupdel", "groupmod",
    "passwd",
    # 包管理器（MEDIUM+confirm，由 patterns 拦）
    "apt", "apt-get", "aptitude", "dpkg",
    "yum", "dnf", "rpm", "snap", "zypper", "pacman",
    # 杂项
    "echo", "printf", "date", "env", "sleep",
    "test", "[", "true", "false",
    "xargs", "history", "pwd",
    "timedatectl",
})


_cached_allowlist: frozenset[str] | None = None


def load_allowlist(path: Path | None = None) -> frozenset[str]:
    """读取 DEFAULT_ALLOWLIST + 用户 JSON 扩展，合并返回。

    用户文件不存在/损坏/格式无效时静默回退到默认名单（只 logger.warning）。
    """
    user_path = path if path is not None else USER_ALLOWLIST_PATH
    if not user_path.exists():
        return DEFAULT_ALLOWLIST
    try:
        data = json.loads(user_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("safety_allowlist.json 读取失败，仅使用默认名单: %s", e)
        return DEFAULT_ALLOWLIST
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        logger.warning("safety_allowlist.json 必须为字符串数组，仅使用默认名单")
        return DEFAULT_ALLOWLIST
    return DEFAULT_ALLOWLIST | frozenset(data)


def get_allowlist() -> frozenset[str]:
    global _cached_allowlist
    if _cached_allowlist is None:
        _cached_allowlist = load_allowlist()
    return _cached_allowlist


def is_allowed(binary: str) -> bool:
    """比较 basename。空串、纯路径前缀都视为不允许。"""
    if not binary:
        return False
    name = binary.rsplit("/", 1)[-1]
    if not name:
        return False
    return name in get_allowlist()


def reset_cache() -> None:
    """测试钩子：清掉模块级缓存。"""
    global _cached_allowlist
    _cached_allowlist = None
