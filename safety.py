import os
import re
import shlex
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class FileReview(Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


@dataclass
class SafetyResult:
    risk_level: RiskLevel
    message: str
    require_confirm: bool


# 交互式命令列表
INTERACTIVE_COMMANDS = {
    "vim", "vi", "nano", "top", "htop", "less", "more", "man",
    "ssh", "mysql", "psql", "redis-cli", "python", "python3",
    "bash", "zsh", "sh", "apt", "apt-get", "dpkg",
}

# 系统关键路径
SYSTEM_CRITICAL_PATHS = {"/", "/*"}

SYSTEM_HIGH_PATHS = {
    "/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/lib", "/lib64",
}

# read_file 禁止目录
FILE_DENY_PATTERNS = [
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/etc/gshadow"),
    re.compile(r"/proc/\d+/mem"),
]

FILE_DENY_KEYWORDS = ["private", "secret", "credential"]

# read_file 警告模式
FILE_WARN_PATTERNS = [
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"\.bash_history$"),
    re.compile(r"\.zsh_history$"),
]

# 禁止执行的命令模式
BLOCKED_PATTERNS = [
    re.compile(r"rm\s+(-[a-zA-Z]*[rf]){1,2}\s+/\s*$"),
    re.compile(r"rm\s+(-[a-zA-Z]*[rf]){1,2}\s+/\*"),
    re.compile(r"mkfs\."),
    re.compile(r"dd\s+.*of=/dev/"),
    re.compile(r":\(\)\{\s*:\|:&\s*\};:"),
    re.compile(r">\s*/dev/[sh]d[a-z]"),
]

# 高风险命令模式
HIGH_RISK_PATTERNS = [
    (re.compile(r"rm\s+(-[a-zA-Z]*[rf]){1,2}\s+(.+)"), "_check_rm_target"),
    (re.compile(r"chmod\s+777\s+(.+)"), "_check_system_path"),
    (re.compile(r"chown\s+-[a-zA-Z]*R\s+(.+)"), "_check_system_path"),
    (re.compile(r"\b(shutdown|reboot|init\s+[06])\b"), None),
    (re.compile(r"iptables\s+-F"), None),
    (re.compile(r"\b(userdel|groupdel)\b"), None),
]

# 中风险命令模式
MEDIUM_RISK_PATTERNS = [
    re.compile(r"systemctl\s+(stop|restart)\s+"),
    re.compile(r"\b(kill|killall)\s+"),
    re.compile(r"\b(mv|cp)\s+.*\s+/(etc|usr|var|bin|sbin|boot|lib)"),
    re.compile(r"crontab\s+-e"),
    re.compile(r"\b(apt|apt-get|yum|dnf)\s+(install|remove|purge)"),
]


def _is_rm_target_safe(target: str) -> bool:
    target = target.strip().rstrip("/")
    if not target:
        return False
    if target.startswith("/tmp") or target.startswith("/var/log"):
        return True
    if target.startswith("./") or target.startswith("~/"):
        return True
    if not target.startswith("/"):
        return True
    return False


def _is_system_path(target: str) -> bool:
    target = target.strip().rstrip("/")
    for p in SYSTEM_HIGH_PATHS:
        if target == p or target.startswith(p + "/"):
            return True
    return False


def review_command(command: str) -> SafetyResult:
    stripped = command.strip()
    if not stripped:
        return SafetyResult(RiskLevel.SAFE, "空命令", False)

    # 1. 检测交互式命令
    try:
        first_word = shlex.split(stripped)[0]
    except ValueError:
        first_word = stripped.split()[0] if stripped.split() else ""

    if first_word in INTERACTIVE_COMMANDS:
        return SafetyResult(
            RiskLevel.BLOCKED,
            f"交互式命令 '{first_word}' 无法在自动化环境中执行，请手动操作",
            False,
        )

    # 2. 匹配禁止模式
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.BLOCKED,
                f"命令被安全策略拦截: {stripped}",
                False,
            )

    # 3. 匹配高风险模式
    for pattern, checker in HIGH_RISK_PATTERNS:
        m = pattern.search(stripped)
        if m:
            if checker == "_check_rm_target":
                target = m.group(2) if m.lastindex >= 2 else ""
                if _is_rm_target_safe(target):
                    continue
                if _is_system_path(target):
                    return SafetyResult(
                        RiskLevel.HIGH,
                        f"高风险操作: 目标为系统路径 '{target}'",
                        True,
                    )
            elif checker == "_check_system_path":
                target = m.group(1) if m.lastindex >= 1 else ""
                if _is_system_path(target):
                    return SafetyResult(
                        RiskLevel.HIGH,
                        f"高风险操作: 目标为系统路径 '{target}'",
                        True,
                    )
            return SafetyResult(
                RiskLevel.HIGH,
                f"高风险操作: {stripped}",
                True,
            )

    # 4. 匹配中风险模式
    for pattern in MEDIUM_RISK_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.MEDIUM,
                f"中风险操作: {stripped}",
                True,
            )

    # 5. 默认安全
    return SafetyResult(RiskLevel.SAFE, "", False)


def review_file_path(path: str) -> FileReview:
    home = str(Path.home())
    expanded = os.path.normpath(path.replace("~", home))

    for pattern in FILE_DENY_PATTERNS:
        if pattern.search(expanded) or pattern.search(path):
            return FileReview.DENY

    lower = expanded.lower()
    for keyword in FILE_DENY_KEYWORDS:
        if keyword in lower:
            return FileReview.DENY

    for pattern in FILE_WARN_PATTERNS:
        if pattern.search(expanded) or pattern.search(path):
            return FileReview.WARN

    return FileReview.ALLOW
