import os
import re
import shlex
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from safety_allowlist import is_allowed

try:
    import bashlex
    _BASHLEX_AVAILABLE = True
except ImportError:
    bashlex = None
    _BASHLEX_AVAILABLE = False


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
    "bash", "zsh", "sh",
}

# 文件读取器：堵 cat /etc/shadow 这类经 execute_command 绕过 read_file 路径审查
FILE_READERS = {
    "cat", "less", "more", "head", "tail", "nl", "od", "xxd",
    "strings", "tac", "view",
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
    re.compile(r"/proc/(\d+|self)/mem"),
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
    re.compile(r">\s*/dev/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d+n\d+)"),
]

# 设备写重定向（bashlex 路径用，匹配规范化后的目标）
_DEV_WRITE_RE = re.compile(r"^/dev/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d+n\d+)")

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
]

# 包管理器：任意子命令都需用户确认（避免静默安装/卸载）
PACKAGE_MANAGERS = {
    "apt", "apt-get", "aptitude", "dpkg", "yum", "dnf", "rpm",
    "snap", "zypper", "pacman",
}

PREFIX_WRAPPERS = {"sudo", "env"}

COMPOUND_OPERATORS = {";", "&&", "||", "|", "&", "\n"}

_RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.BLOCKED: 4,
}


def _is_rm_target_safe(target: str) -> bool:
    # rm 可带多个目标，任一目标不安全则整体不安全（防 'rm -rf /tmp/x /etc' 误放行）
    tokens = target.split()
    if not tokens:
        return False
    for tok in tokens:
        t = tok.rstrip("/")
        if not t:
            return False
        if t.startswith("/tmp") or t.startswith("/var/log"):
            continue
        if t.startswith("./") or t.startswith("~/"):
            continue
        if not t.startswith("/"):
            continue
        return False
    return True


def _is_system_path(target: str) -> bool:
    target = target.strip().rstrip("/")
    for p in SYSTEM_HIGH_PATHS:
        if target == p or target.startswith(p + "/"):
            return True
    return False


def _split_compound(command: str) -> list[str]:
    """按 ; && || | & 和换行拆分复合命令，尊重引号。引号不配对会抛 ValueError。

    bashlex 不可用时的回退路径。
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens = list(lexer)
    segments = []
    current = []
    for tok in tokens:
        if tok in COMPOUND_OPERATORS or (tok and set(tok) <= {";", "&", "|"}):
            if current:
                segments.append(" ".join(current))
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(" ".join(current))
    return segments


def _looks_like_assignment(token: str) -> bool:
    """识别 bash NAME=VALUE 形式的环境赋值。NAME 必须以字母/下划线开头，
    其余为 [A-Za-z0-9_]。`if=/dev/zero` 这种以小写字母开头的也会被误判为
    assignment，但 _strip_prefix 仅剥离前导段直到遇到第一个非赋值非包装词，
    故不会误剥 dd 的参数。"""
    if "=" not in token or token.startswith(("-", "=")):
        return False
    name = token.split("=", 1)[0]
    if not name or name[0].isdigit():
        return False
    return all(c.isalnum() or c == "_" for c in name)


def _strip_prefix(segment: str) -> str:
    """剥离子命令前导的 NAME=VAL 赋值与 sudo/env（含选项）包装，
    定位真正要执行的命令。"""
    parts = segment.split()
    while parts:
        p = parts[0]
        if _looks_like_assignment(p):
            parts = parts[1:]
            continue
        if p == "env":
            parts = parts[1:]
            # env 的选项 (-i/-u/-S 等) 与紧跟的 NAME=VAL；
            # 否则 `env -i cmd` / `env FOO=x cmd` 会绕过审查
            while parts and (parts[0].startswith("-") or _looks_like_assignment(parts[0])):
                parts = parts[1:]
            continue
        if p == "sudo":
            parts = parts[1:]
            continue
        break
    return " ".join(parts)


# ---------- bashlex AST 辅助 ----------

def _walk_all(node):
    """递归遍历 bashlex AST，yield 每个节点。"""
    if node is None or not hasattr(node, "kind"):
        return
    yield node
    for attr in ("parts", "list", "command", "output"):
        val = getattr(node, attr, None)
        if val is None:
            continue
        if isinstance(val, list):
            for child in val:
                yield from _walk_all(child)
        else:
            yield from _walk_all(val)


def _has_substitution(tree) -> bool:
    """检测命令替换 $(...) / `...` 与进程替换 <(...) / >(...)。"""
    for n in _walk_all(tree):
        if n.kind in ("commandsubstitution", "processsubstitution"):
            return True
    return False


def _has_dev_write_redirect(tree) -> bool:
    """检测重定向到块设备（>/dev/sda 这类）。BLOCKED_PATTERNS 已用正则覆盖，
    bashlex 路径下做一次冗余检查可处理 `>` 与目标间任意空白/换行的极端情形。"""
    for n in _walk_all(tree):
        if n.kind != "redirect":
            continue
        rtype = getattr(n, "type", "")
        if rtype not in (">", ">>", "&>", ">|", "&>>"):
            continue
        out = getattr(n, "output", None)
        target = getattr(out, "word", "") if out is not None else ""
        if _DEV_WRITE_RE.match(target):
            return True
    return False


def _command_segments_via_bashlex(command: str) -> tuple[list[str] | None, str | None]:
    """用 bashlex 解析，返回 (各 command 节点的源串列表, 结构性 BLOCK 原因)。

    返回值：
      (segments, None)  解析成功
      (None, reason)    结构性 BLOCK（命令替换、进程替换、设备写）
      (None, None)      解析失败（调用方应 fail-safe HIGH）
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None, None

    for tree in trees:
        if _has_substitution(tree):
            return None, "命令包含 $(...) / `...` / <(...) 替换，安全策略不允许"
        if _has_dev_write_redirect(tree):
            return None, "命令试图重定向到块设备"

    segments = []
    for tree in trees:
        for n in _walk_all(tree):
            if n.kind == "command":
                start, end = n.pos
                segments.append(command[start:end])
    return segments, None


def _review_one(segment: str) -> SafetyResult:
    """审查单个子命令（已无复合操作符）。"""
    stripped = segment.strip()
    if not stripped:
        return SafetyResult(RiskLevel.SAFE, "", False)

    parts = stripped.split()
    first_word = parts[0]

    # 交互式命令
    if first_word in INTERACTIVE_COMMANDS:
        return SafetyResult(
            RiskLevel.BLOCKED,
            f"交互式命令 '{first_word}' 无法在自动化环境中执行，请手动操作",
            False,
        )

    # 二进制白名单：不在名单内一律 BLOCKED
    if not is_allowed(first_word):
        return SafetyResult(
            RiskLevel.BLOCKED,
            f"命令 '{first_word}' 不在白名单中。如确需放行，请加入 ~/.aiops/safety_allowlist.json",
            False,
        )

    # 禁止模式（逐段，补原始整串未覆盖的复合场景，如 'rm -rf / ; x'）
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.BLOCKED,
                f"命令被安全策略拦截: {stripped}",
                False,
            )

    # 文件读取器读取敏感文件（堵 cat /etc/shadow 这类跨工具绕过；启发式）
    if first_word in FILE_READERS:
        for arg in parts[1:]:
            if arg.startswith("-"):
                continue
            review = review_file_path(arg)
            if review == FileReview.DENY:
                return SafetyResult(
                    RiskLevel.BLOCKED,
                    f"命令试图读取敏感文件: {arg}",
                    False,
                )
            if review == FileReview.WARN:
                return SafetyResult(
                    RiskLevel.MEDIUM,
                    f"命令试图读取可能含敏感信息的文件: {arg}",
                    True,
                )

    # 高风险模式
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

    # 包管理器（任意子命令都需确认）
    if first_word in PACKAGE_MANAGERS:
        return SafetyResult(
            RiskLevel.MEDIUM,
            f"中风险操作: 包管理器 '{first_word}'",
            True,
        )

    # 中风险模式
    for pattern in MEDIUM_RISK_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.MEDIUM,
                f"中风险操作: {stripped}",
                True,
            )

    return SafetyResult(RiskLevel.SAFE, "", False)


def _max_risk(results: list[SafetyResult]) -> SafetyResult:
    """聚合多段审查结果，取最高风险。BLOCKED 不需确认。"""
    if not results:
        return SafetyResult(RiskLevel.SAFE, "", False)
    worst = max(results, key=lambda r: _RISK_ORDER[r.risk_level])
    if worst.risk_level == RiskLevel.BLOCKED:
        return SafetyResult(RiskLevel.BLOCKED, worst.message, False)
    require_confirm = any(r.require_confirm for r in results)
    return SafetyResult(worst.risk_level, worst.message, require_confirm)


def review_command(command: str) -> SafetyResult:
    stripped = command.strip()
    if not stripped:
        return SafetyResult(RiskLevel.SAFE, "空命令", False)

    # 1. 先对原始整串跑 BLOCKED 正则模式
    #    bashlex 可能解析失败（fork 炸弹的 :(){:|:&};: 不是合法 grammar），
    #    或 tokenize 后无法还原；正则在原始字符层更鲁棒。
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(RiskLevel.BLOCKED, f"命令被安全策略拦截: {stripped}", False)

    # 2. 优先用 bashlex AST 走结构性检查（命令替换/进程替换/设备写重定向）
    if _BASHLEX_AVAILABLE:
        segments, block_reason = _command_segments_via_bashlex(stripped)
        if block_reason:
            return SafetyResult(RiskLevel.BLOCKED, block_reason, False)
        if segments is None:
            return SafetyResult(RiskLevel.HIGH, "命令解析失败，无法完整审查", True)
    else:
        # 回退：shlex 拆分
        try:
            segments = _split_compound(stripped)
        except ValueError:
            return SafetyResult(RiskLevel.HIGH, "命令解析失败，无法完整审查", True)

    # 3. 逐段审查，取最高风险
    results = [_review_one(_strip_prefix(seg)) for seg in segments]
    return _max_risk(results)


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
