import subprocess
import uuid
from pathlib import Path

from langchain_core.tools import tool

from safety import review_command, review_file_path, RiskLevel, FileReview
from logger import OpsLogger


_ops_logger: OpsLogger | None = None


def set_ops_logger(logger: OpsLogger):
    global _ops_logger
    _ops_logger = logger


def _log(tool_name: str, request_id: str = "", **kwargs):
    if _ops_logger:
        _ops_logger.log_tool_call(tool=tool_name, request_id=request_id, **kwargs)


def _run_command(command: str, timeout: int = 30, request_id: str = "") -> str:
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path.home()),
        )
        output = (result.stdout + result.stderr).strip()
        if len(output) > 5000:
            output = "...\n" + output[-4997:]
        return output if output else "(无输出)"
    except subprocess.TimeoutExpired:
        return f"命令超时（{timeout}秒）"
    except Exception as e:
        return f"执行异常: {e}"


@tool
def execute_command(command: str, confirmed: bool = False) -> str:
    """执行任意 shell 命令。需安全审查，高风险命令需用户确认。

    当 confirmed=False 时执行安全检查，如需确认则返回风险提示而非执行命令。
    收到用户确认后，再次调用本工具并设置 confirmed=True 以实际执行。
    """
    request_id = uuid.uuid4().hex[:8]
    result = review_command(command)

    if result.risk_level == RiskLevel.BLOCKED:
        _log("execute_command", request_id, command=command, risk="blocked",
             action="blocked", result="blocked", error=result.message)
        return f"[拦截] {result.message}"

    if result.require_confirm and not confirmed:
        _log("execute_command", request_id, command=command,
             risk=result.risk_level.value, action="pending_confirm")
        return (
            f"[需要确认] 风险等级: {result.risk_level.value.upper()}\n"
            f"{result.message}\n"
            f"命令: {command}\n"
            f"请询问用户是否确认执行此命令。用户确认后，再次调用 execute_command(command, confirmed=True)。"
        )

    _log("execute_command", request_id, command=command,
         risk=result.risk_level.value, action="executed")
    output = _run_command(command, request_id=request_id)
    _log("execute_command", request_id, command=command,
         risk=result.risk_level.value, action="executed", result="success",
         output_len=len(output))
    return output


@tool
def read_file(path: str, head: int | None = None, tail: int | None = None, confirmed: bool = False) -> str:
    """读取文件内容。支持 head/tail 参数限制行数。需路径审查。

    当 confirmed=False 时执行路径审查，如需确认则返回警告而非读取。
    收到用户确认后，再次调用本工具并设置 confirmed=True 以实际读取。
    """
    request_id = uuid.uuid4().hex[:8]
    review = review_file_path(path)

    if review == FileReview.DENY:
        _log("read_file", request_id, path=path, risk="blocked",
             action="blocked", result="blocked")
        return f"[拦截] 禁止读取敏感文件: {path}"

    if review == FileReview.WARN and not confirmed:
        _log("read_file", request_id, path=path, risk="warn",
             action="pending_confirm")
        return (
            f"[需要确认] 文件 '{path}' 可能包含敏感信息。\n"
            f"请询问用户是否确认读取。用户确认后，再次调用 read_file(path, confirmed=True)。"
        )

    try:
        file_path = Path(path).expanduser()
        if not file_path.exists():
            return f"文件不存在: {path}"
        if file_path.stat().st_size > 1024 * 1024:
            return f"文件过大（>{1024*1024} 字节），请使用 head/tail 参数读取部分内容"

        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        if tail is not None:
            lines = lines[-tail:]
        elif head is not None:
            lines = lines[:head]

        output = "\n".join(lines)
        if len(output) > 5000:
            output = "...\n" + output[-4997:]

        _log("read_file", request_id, path=path, result="success",
             output_len=len(output))
        return output
    except Exception as e:
        _log("read_file", request_id, path=path, result="error", error=str(e))
        return f"读取失败: {e}"


@tool
def check_service(name: str) -> str:
    """查看 systemd 服务状态（is-active / is-enabled / status）。"""
    request_id = uuid.uuid4().hex[:8]
    parts = []
    for sub in ["is-active", "is-enabled"]:
        out = _run_command(f"systemctl {sub} {name}", request_id=request_id)
        parts.append(f"{sub}: {out}")
    status_out = _run_command(f"systemctl status {name} --no-pager", request_id=request_id)
    parts.append(f"status:\n{status_out}")
    output = "\n".join(parts)
    _log("check_service", request_id, command=f"systemctl status {name}",
         result="success", output_len=len(output))
    return output


@tool
def check_port(port: int | None = None) -> str:
    """查看端口占用情况。不传 port 列出所有监听端口。"""
    request_id = uuid.uuid4().hex[:8]
    cmd = "ss -tlnp" if port is None else f"ss -tlnp | grep ':{port} '"
    output = _run_command(cmd, request_id=request_id)
    _log("check_port", request_id, command=cmd, result="success",
         output_len=len(output))
    return output


@tool
def check_disk(path: str | None = None) -> str:
    """查看磁盘使用情况。不传 path 显示所有挂载点。"""
    request_id = uuid.uuid4().hex[:8]
    cmd = "df -h" if path is None else f"df -h {path}"
    output = _run_command(cmd, request_id=request_id)
    _log("check_disk", request_id, command=cmd, result="success",
         output_len=len(output))
    return output


@tool
def check_process(sort_by: str = "memory", limit: int = 20) -> str:
    """查看进程列表和资源占用。sort_by: 'memory' 或 'cpu'。"""
    request_id = uuid.uuid4().hex[:8]
    sort_flag = "%cpu" if sort_by == "cpu" else "%mem"
    cmd = f"ps aux --sort=-{sort_flag} | head -n {limit + 1}"
    output = _run_command(cmd, request_id=request_id)
    _log("check_process", request_id, command=cmd, result="success",
         output_len=len(output))
    return output


@tool
def check_log(
    unit: str | None = None,
    since: str = "1h",
    lines: int = 100,
) -> str:
    """查看系统日志。优先 journalctl，不可用时回退到 /var/log/。"""
    request_id = uuid.uuid4().hex[:8]

    # 尝试 journalctl
    cmd_parts = ["journalctl", "--no-pager", f"-n {lines}"]
    if unit:
        cmd_parts.append(f"-u {unit}")
    if since:
        cmd_parts.append(f"--since '{since}'")
    cmd = " ".join(cmd_parts)
    output = _run_command(cmd, request_id=request_id)

    if "No journal files were found" in output or "command not found" in output:
        # 回退到 /var/log/
        log_file = "/var/log/syslog"
        if not Path(log_file).exists():
            log_file = "/var/log/messages"
        if Path(log_file).exists():
            cmd = f"tail -n {lines} {log_file}"
            output = _run_command(cmd, request_id=request_id)
        else:
            output = "未找到可用的日志源（journalctl 不可用，/var/log/syslog 和 /var/log/messages 均不存在）"

    if len(output) > 2000:
        output = "...\n" + output[-1997:]

    _log("check_log", request_id, command=cmd, result="success",
         output_len=len(output))
    return output


@tool
def network_check(target: str, method: str = "ping") -> str:
    """网络诊断。method: 'ping'（连通性）、'curl'（HTTP 状态）、'traceroute'（路由追踪）。"""
    request_id = uuid.uuid4().hex[:8]

    if method == "curl":
        cmd = f"curl -sS -o /dev/null -w 'HTTP Status: %{{http_code}}\\nTime: %{{time_total}}s\\n' --max-time 10 {target}"
    elif method == "traceroute":
        cmd = f"traceroute -m 15 {target}"
    else:
        cmd = f"ping -c 4 {target}"

    output = _run_command(cmd, request_id=request_id)
    _log("network_check", request_id, command=cmd, result="success",
         output_len=len(output))
    return output


ALL_TOOLS = [
    execute_command,
    read_file,
    check_service,
    check_port,
    check_disk,
    check_process,
    check_log,
    network_check,
]
