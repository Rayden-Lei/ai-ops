# 安全层加固 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `safety.py` 从「整串正则」重构为「命令分解式审查」，补齐文件路径与跨工具防护、关闭专用工具命令注入，并用 pytest 锁死全部行为。

**Architecture:** `review_command` 先对原始整串跑 BLOCKED 模式（防 tokenize 破坏连续标点如 fork 炸弹），再用 `shlex(punctuation_chars=True)` 按 `;`/`&&`/`||`/`|`/`&`/换行拆分复合命令，剥离 `sudo`/`env` 前缀后逐段送入 `_review_one`，取最高风险聚合。专用工具在命令构造边界用 `shlex.quote()` 转义、数值参数强制 `int()` 校验。

**Tech Stack:** Python 3.10+、标准库 `shlex`/`posixpath`/`re`、pytest（参数化）。测试在 Windows 上运行但命令面向 Linux，故路径规范化用 `posixpath` 而非 `os.path`。

---

## 设计约束（实现前必读）

- **跨平台陷阱**：本仓库在 Windows 开发，但命令面向 Linux。`os.path.normpath('/etc/shadow')` 在 Windows 会变成 `\etc\shadow`，破坏正则。**必须用 `posixpath.normpath`。**
- **fork 炸弹**：`:(){ :|:& };:` 经 tokenize 会被拆碎，连续标点正则失效。**因此 `review_command` 必须先对原始整串跑一遍 BLOCKED 模式**，再做分段审查。
- **接口不变**：`review_command(command) -> SafetyResult`、`review_file_path(path) -> FileReview` 签名与返回类型保持不变。
- **测试 import**：`test_safety.py` 只 import `safety`（纯标准库，零运行时依赖）；`test_tools.py` import `tools`（需 langchain）。根目录放空 `conftest.py` 保证 `import safety` 可用。

## File Structure

| 文件 | 动作 | 职责 |
|---|---|---|
| `requirements-dev.txt` | 创建 | 开发依赖（pytest） |
| `pytest.ini` | 创建 | pytest 配置（testpaths=tests） |
| `conftest.py` | 创建 | 空文件，使仓库根可被 import |
| `tests/test_safety.py` | 创建 | safety.py 全行为测试（纯标准库可跑） |
| `tests/test_tools.py` | 创建 | 专用工具注入/转义测试（需 langchain） |
| `safety.py` | 重构 | 命令分解式审查 + 路径加固 + 文件读取器检查 |
| `tools.py` | 修改 | 6 个专用工具参数 shlex.quote / int 校验 |
| `agent.py` | 修改 | 修正系统提示词中 shlex.quote 表述 |
| `docs/security/known-bypasses.md` | 创建 | 已知绕过登记表 |

---

## Task 1: 测试基建

**Files:**
- Create: `requirements-dev.txt`
- Create: `pytest.ini`
- Create: `conftest.py`

- [ ] **Step 1: 创建 `requirements-dev.txt`**

```
pytest>=8.0
```

- [ ] **Step 2: 创建 `pytest.ini`**

```ini
[pytest]
testpaths = tests
```

- [ ] **Step 3: 创建空 `conftest.py`**

文件内容为空（仅需存在，使 pytest 把仓库根加入 sys.path，让 `import safety` 生效）。

```python
```

- [ ] **Step 4: 安装并验证 pytest 可运行**

Run: `python -m pip install -r requirements-dev.txt`
然后：`python -m pytest -q`
Expected: 收集到 0 个用例（`no tests ran`），无 import 错误。

- [ ] **Step 5: Commit**

```bash
git add requirements-dev.txt pytest.ini conftest.py
git commit -m "test: 引入 pytest 测试基建"
```

---

## Task 2: 强化 `review_file_path`（漏洞 4）

把 `.ssh` 覆盖扩到任意 `.ssh/` 目录（含 `/home/*/.ssh/`），匹配前用 `posixpath.normpath` 解析 `..`。

**Files:**
- Modify: `safety.py`（`import` 段、`FILE_DENY_PATTERNS`、`review_file_path`）
- Test: `tests/test_safety.py`

- [ ] **Step 1: 写失败测试**

创建 `tests/test_safety.py`：

```python
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
])
def test_file_path_allow(path):
    assert review_file_path(path) == FileReview.ALLOW
```

- [ ] **Step 2: 运行，确认失败**

Run: `python -m pytest tests/test_safety.py -v`
Expected: `test_file_path_deny[/home/alice/.ssh/authorized_keys]` 等失败（现有代码仅覆盖 `~/` 和 `/root/` 的 `.ssh`）。

- [ ] **Step 3: 修改 `safety.py`**

把文件顶部 import 改为（新增 `os` 与 `posixpath`）：

```python
import os
import posixpath
import re
import shlex
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
```

把 `FILE_DENY_PATTERNS` 替换为：

```python
FILE_DENY_PATTERNS = [
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/etc/gshadow"),
    re.compile(r"/proc/\d+/mem"),
]
```

把 `review_file_path` 函数体替换为：

```python
def review_file_path(path: str) -> FileReview:
    home = str(Path.home())
    expanded = posixpath.normpath(path.replace("~", home))

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
```

- [ ] **Step 4: 运行，确认通过**

Run: `python -m pytest tests/test_safety.py -v`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add safety.py tests/test_safety.py
git commit -m "fix: review_file_path 覆盖任意 .ssh 目录并解析 .. (漏洞4)"
```

---

## Task 3: `review_command` 重构为命令分解式审查（漏洞 1、3 + fail-safe）

引入 `_split_compound` / `_strip_prefix` / `_review_one` / `_max_risk`，`review_command` 先查原始整串 BLOCKED，再分段取最高风险。

**Files:**
- Modify: `safety.py`（新增常量与 4 个辅助函数，重写 `review_command`）
- Test: `tests/test_safety.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_safety.py` 末尾追加：

```python
from safety import review_command, RiskLevel


@pytest.mark.parametrize("cmd", [
    "rm -rf /",
    "rm -rf /*",
    "mkfs.ext4 /dev/sdb",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "echo x > /dev/sda",
    "rm -rf / ; echo done",        # 复合命令：分段后首段命中 BLOCKED（漏洞1）
])
def test_command_blocked(cmd):
    assert review_command(cmd).risk_level == RiskLevel.BLOCKED


@pytest.mark.parametrize("cmd", [
    "vim /etc/hosts",
    "top",
    "sudo vim /etc/hosts",          # 剥离 sudo 后命中交互式（漏洞3）
    "echo hello; vim",              # 复合命令第二段是交互式（漏洞3）
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
    "apt install vim",
    "crontab -e",
    "mv foo /etc/bar",
    "ls && systemctl restart nginx",   # 复合：最高风险段为 MEDIUM
])
def test_command_medium(cmd):
    result = review_command(cmd)
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.require_confirm is True


@pytest.mark.parametrize("cmd", [
    "ls -la",
    "df -h",
    "ps aux",
    "echo hello",
    "rm -rf /tmp/cache",       # 安全目标，不升级
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
```

- [ ] **Step 2: 运行，确认失败**

Run: `python -m pytest tests/test_safety.py -v`
Expected: `test_command_blocked[rm -rf / ; echo done]`（现返回 HIGH）、`test_command_interactive_blocked[sudo vim ...]`、`[echo hello; vim]`、`test_command_parse_failure_fails_safe` 等失败。

- [ ] **Step 3: 重写 `safety.py` 命令审查部分**

在常量区新增（放在 `INTERACTIVE_COMMANDS` 之后）：

```python
PREFIX_WRAPPERS = {"sudo", "env"}

COMPOUND_OPERATORS = {";", "&&", "||", "|", "&", "\n"}

_RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.BLOCKED: 4,
}
```

新增 4 个辅助函数（放在 `_is_system_path` 之后）：

```python
def _split_compound(command: str) -> list[str]:
    """按 ; && || | & 和换行拆分复合命令，尊重引号。引号不配对会抛 ValueError。"""
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


def _strip_prefix(segment: str) -> str:
    """剥离子命令开头的 sudo / env VAR=VALUE 包装。"""
    parts = segment.split()
    while parts and parts[0] in PREFIX_WRAPPERS:
        if parts[0] == "env":
            parts = parts[1:]
            while parts and "=" in parts[0] and not parts[0].startswith("-"):
                parts = parts[1:]
        else:
            parts = parts[1:]
    return " ".join(parts)


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

    # 禁止模式（逐段，补原始整串未覆盖的复合场景，如 'rm -rf / ; x'）
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.BLOCKED,
                f"命令被安全策略拦截: {stripped}",
                False,
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
```

把整个 `review_command` 函数替换为：

```python
def review_command(command: str) -> SafetyResult:
    stripped = command.strip()
    if not stripped:
        return SafetyResult(RiskLevel.SAFE, "空命令", False)

    # 先对原始整串跑 BLOCKED 模式（tokenize 会拆碎 fork 炸弹等连续标点）
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(RiskLevel.BLOCKED, f"命令被安全策略拦截: {stripped}", False)

    # 拆分复合命令，逐段审查，取最高风险
    try:
        segments = _split_compound(stripped)
    except ValueError:
        return SafetyResult(RiskLevel.HIGH, "命令解析失败，无法完整审查", True)

    results = [_review_one(_strip_prefix(seg)) for seg in segments]
    return _max_risk(results)
```

- [ ] **Step 4: 运行，确认通过**

Run: `python -m pytest tests/test_safety.py -v`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add safety.py tests/test_safety.py
git commit -m "refactor: review_command 改命令分解式审查 (漏洞1/3 + 解析失败 fail-safe)"
```

---

## Task 4: 文件读取器跨工具检查（漏洞 2）

在 `_review_one` 中：若子命令首词是文件读取器，对其非选项参数跑 `review_file_path`，DENY→BLOCKED、WARN→MEDIUM+确认。堵 `execute_command("cat /etc/shadow")`。

**Files:**
- Modify: `safety.py`（新增 `FILE_READERS` 常量、在 `_review_one` 插入读取器检查）
- Test: `tests/test_safety.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_safety.py` 末尾追加：

```python
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
```

- [ ] **Step 2: 运行，确认失败**

Run: `python -m pytest tests/test_safety.py -k filereader -v`
Expected: `test_filereader_denied_path_blocked` / `test_filereader_warn_path_medium` 失败（现返回 SAFE）。

- [ ] **Step 3: 修改 `safety.py`**

在常量区新增（放在 `INTERACTIVE_COMMANDS` 之后）：

```python
FILE_READERS = {
    "cat", "less", "more", "head", "tail", "nl", "od", "xxd",
    "strings", "tac", "view",
}
```

在 `_review_one` 中，把这段：

```python
    # 禁止模式（逐段，补原始整串未覆盖的复合场景，如 'rm -rf / ; x'）
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(stripped):
            return SafetyResult(
                RiskLevel.BLOCKED,
                f"命令被安全策略拦截: {stripped}",
                False,
            )

    # 高风险模式
```

替换为（在禁止模式之后、高风险之前插入读取器检查）：

```python
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
```

- [ ] **Step 4: 运行，确认通过**

Run: `python -m pytest tests/test_safety.py -v`
Expected: 全部 PASS（含之前所有用例）。

- [ ] **Step 5: Commit**

```bash
git add safety.py tests/test_safety.py
git commit -m "fix: 文件读取器读取敏感文件检查，堵跨工具路径绕过 (漏洞2)"
```

---

## Task 5: 专用工具字符串参数 `shlex.quote` 转义（漏洞 6）

`check_service` / `check_disk` / `check_log` / `network_check` 对 LLM 提供的字符串参数转义。

**Files:**
- Modify: `tools.py`（`import shlex`、4 个工具函数）
- Test: `tests/test_tools.py`

- [ ] **Step 1: 写失败测试**

创建 `tests/test_tools.py`：

```python
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
```

- [ ] **Step 2: 运行，确认失败**

Run: `python -m pytest tests/test_tools.py -v`
Expected: 失败——注入串未被引号包裹直接拼进命令（若 langchain 未安装，先 `python -m pip install langchain langchain-openai langgraph rich`）。

- [ ] **Step 3: 修改 `tools.py`**

在文件顶部 import 区新增：

```python
import shlex
```

把 `check_service` 函数体替换为：

```python
@tool
def check_service(name: str) -> str:
    """查看 systemd 服务状态（is-active / is-enabled / status）。"""
    request_id = uuid.uuid4().hex[:8]
    q = shlex.quote(name)
    parts = []
    for sub in ["is-active", "is-enabled"]:
        out = _run_command(f"systemctl {sub} {q}", request_id=request_id)
        parts.append(f"{sub}: {out}")
    status_out = _run_command(f"systemctl status {q} --no-pager", request_id=request_id)
    parts.append(f"status:\n{status_out}")
    output = "\n".join(parts)
    _log("check_service", request_id, command=f"systemctl status {q}",
         result="success", output_len=len(output))
    return output
```

把 `check_disk` 的 `cmd` 行替换为：

```python
    cmd = "df -h" if path is None else f"df -h {shlex.quote(path)}"
```

把 `network_check` 的命令构造段替换为：

```python
    q = shlex.quote(target)
    if method == "curl":
        cmd = f"curl -sS -o /dev/null -w 'HTTP Status: %{{http_code}}\\nTime: %{{time_total}}s\\n' --max-time 10 {q}"
    elif method == "traceroute":
        cmd = f"traceroute -m 15 {q}"
    else:
        cmd = f"ping -c 4 {q}"
```

把 `check_log` 中 `cmd_parts` 构造的 unit/since 两行替换为（去掉原本手写的单引号）：

```python
    if unit:
        cmd_parts.append(f"-u {shlex.quote(unit)}")
    if since:
        cmd_parts.append(f"--since {shlex.quote(since)}")
```

- [ ] **Step 4: 运行，确认通过**

Run: `python -m pytest tests/test_tools.py -v`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add tools.py tests/test_tools.py
git commit -m "fix: 专用工具字符串参数 shlex.quote 转义，关闭命令注入 (漏洞6)"
```

---

## Task 6: 专用工具数值参数 `int()` 校验（漏洞 6）

`check_port` / `check_process` / `check_log` 的数值参数强制校验，非法值返回错误而非拼接。

**Files:**
- Modify: `tools.py`（`check_port`、`check_process`、`check_log`）
- Test: `tests/test_tools.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_tools.py` 末尾追加：

```python
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
```

- [ ] **Step 2: 运行，确认失败**

Run: `python -m pytest tests/test_tools.py -k "rejects or int_ok" -v`
Expected: 失败（当前直接拼接，无校验）。

- [ ] **Step 3: 修改 `tools.py`**

把 `check_port` 函数体替换为：

```python
@tool
def check_port(port: int | None = None) -> str:
    """查看端口占用情况。不传 port 列出所有监听端口。"""
    request_id = uuid.uuid4().hex[:8]
    if port is None:
        cmd = "ss -tlnp"
    else:
        try:
            port = int(port)
        except (ValueError, TypeError):
            return f"无效端口: {port!r}"
        cmd = f"ss -tlnp | grep ':{port} '"
    output = _run_command(cmd, request_id=request_id)
    _log("check_port", request_id, command=cmd, result="success",
         output_len=len(output))
    return output
```

把 `check_process` 函数体替换为：

```python
@tool
def check_process(sort_by: str = "memory", limit: int = 20) -> str:
    """查看进程列表和资源占用。sort_by: 'memory' 或 'cpu'。"""
    request_id = uuid.uuid4().hex[:8]
    try:
        limit = int(limit)
    except (ValueError, TypeError):
        return f"无效 limit: {limit!r}"
    sort_flag = "%cpu" if sort_by == "cpu" else "%mem"
    cmd = f"ps aux --sort=-{sort_flag} | head -n {limit + 1}"
    output = _run_command(cmd, request_id=request_id)
    _log("check_process", request_id, command=cmd, result="success",
         output_len=len(output))
    return output
```

在 `check_log` 函数体开头（`request_id = ...` 之后、`cmd_parts = ...` 之前）插入 lines 校验：

```python
    try:
        lines = int(lines)
    except (ValueError, TypeError):
        return f"无效 lines: {lines!r}"
```

- [ ] **Step 4: 运行，确认通过**

Run: `python -m pytest tests/test_tools.py -v`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add tools.py tests/test_tools.py
git commit -m "fix: 专用工具数值参数 int() 校验 (漏洞6)"
```

---

## Task 7: 修正 `agent.py` 系统提示词

把"对动态参数用 shlex.quote 转义"改为准确表述：专用工具参数由工具层自动转义，execute_command 命令需 LLM 自行确保安全。

**Files:**
- Modify: `agent.py:41`

- [ ] **Step 1: 修改提示词**

把 `SYSTEM_PROMPT` 中这一行：

```
- 对用户输入的动态参数使用 shlex.quote() 转义，防止命令注入
```

替换为：

```
- 专用工具的参数由工具层自动转义，无需你处理；使用 execute_command 时，确保命令整体安全、避免把不可信内容直接拼入命令
```

- [ ] **Step 2: 验证**

Run: `git diff agent.py`
Expected: 仅该行改动；人工确认表述准确。
（此为提示词文案，无自动化测试。）

- [ ] **Step 3: Commit**

```bash
git add agent.py
git commit -m "docs: 修正系统提示词中 shlex.quote 表述，与工具层转义保持一致"
```

---

## Task 8: 已知绕过登记表

记录本阶段延后的对抗性向量，作为下一阶段架构升级的输入。

**Files:**
- Create: `docs/security/known-bypasses.md`

- [ ] **Step 1: 创建 `docs/security/known-bypasses.md`**

```markdown
# 已知绕过登记表

本表记录当前正则/启发式安全层**无法可靠拦截**的对抗性向量。当前阶段（2026-05-28 加固）刻意不处理这些，留作下一阶段架构升级（命令解析 + 二进制白名单 + 受限执行环境）的依据。

> 适用前提：威胁模型为「防对抗用户」。对「防误伤的诚实 LLM」，现有正则护栏已足够。

| 向量 | 示例 | 为何抓不住 | 下一阶段建议缓解 |
|---|---|---|---|
| 正则混淆 | `r""m -rf /`、`\rm -rf /` | 正则按字面匹配 `rm`，引号/转义破坏字面（注：posix tokenize 已能还原部分引号混淆，但非全部） | tokenize 后取解析出的实际可执行名做判定 |
| 变量/命令替换 | `$(echo rm) -rf /`、`$X /` | 替换在 bash 运行时发生，审查时不可见 | 受限执行环境 / 禁用替换 / 静态展开 |
| 编码绕过 | `echo cm0gLXJmIC8=｜base64 -d｜bash` | 解码在运行时发生 | 二进制白名单 + 禁止管道入 shell |
| 文件读取器启发式盲区 | `dd if=/etc/shadow`、`python -c "open(...)"`、`grep x < /etc/shadow` | 不在读取器集合 / 重定向不经命令名 | 受限执行环境 + 路径级权限（LSM / 降权） |
| 符号链接指向敏感文件 | `ln -s /etc/shadow /tmp/x; cat /tmp/x` | 路径匹配不解析符号链接 | 运行时按真实 inode 鉴权 / 降权执行 |
| 引号内空白被规范化 | `grep 'a  b' f` | tokenize+rejoin 把多空白压成单空白 | 仅影响展示，不影响风险判定；可忽略 |

## execute_command 的固有限制

`execute_command(command: str)` 接收 LLM 拼好的整串命令，工具层无法定位其中的"动态参数"，故无法在工具层强制 `shlex.quote`。这部分安全依赖：(1) 本安全层的命令分级审查；(2) 系统提示词对 LLM 的指导。专用工具（check_*/network_check）则在工具层强制转义，是更可靠的防线。
```

- [ ] **Step 2: Commit**

```bash
git add docs/security/known-bypasses.md
git commit -m "docs: 新增已知绕过登记表，作为下阶段架构升级依据"
```

---

## 收尾验证

- [ ] **全量测试**

Run: `python -m pytest -v`
Expected: `tests/test_safety.py` 与 `tests/test_tools.py` 全部 PASS。

- [ ] **回归对照计划验证场景**

人工对照 `docs/plan/AiOps-Plan.md` 末尾 13 个场景的预期风险等级，确认 `review_command` 行为一致（已被 Task 3/4 的参数化用例覆盖）。
