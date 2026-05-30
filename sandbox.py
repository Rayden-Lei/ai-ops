"""沙箱包装层：bwrap 优先，firejail 备选，都不可用时透传。

仅对 execute_command 中 SAFE/LOW 风险的自动执行流程套沙箱（防御深度，
LLM 误判"安全"的命令也跑在受限环境里）。MEDIUM/HIGH 经用户确认后绕过沙箱
执行——确认本身已是闸门，且只读 / 的沙箱会让合法 systemctl restart 之类
失败。

沙箱策略（最小可用）：
- bwrap: `--ro-bind / /`（整盘只读）+ `--dev`/`--proc`/`--tmpfs /tmp`
  （新 dev/proc 与可写 tmpfs），网络默认共享（curl/ping 仍可用），
  `--die-with-parent` 防孤儿。
- firejail: `--read-only=/etc,/usr,...` 标记关键写路径只读。
"""

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxStatus:
    backend: str | None
    available: bool

    @property
    def description(self) -> str:
        if self.available:
            return f"沙箱已就绪 ({self.backend})"
        return "沙箱未启用（未检测到 bwrap / firejail）"


_cached_status: SandboxStatus | None = None


def detect() -> SandboxStatus:
    """检测可用沙箱后端，模块级缓存。"""
    global _cached_status
    if _cached_status is not None:
        return _cached_status
    for backend in ("bwrap", "firejail"):
        if shutil.which(backend):
            _cached_status = SandboxStatus(backend=backend, available=True)
            return _cached_status
    _cached_status = SandboxStatus(backend=None, available=False)
    return _cached_status


def reset_cache() -> None:
    """测试钩子：清掉检测缓存。"""
    global _cached_status
    _cached_status = None


# 沙箱内必须保持只读的关键系统路径（firejail 用；bwrap 整盘 --ro-bind / 已覆盖）
_READONLY_PATHS = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64", "/opt")


def wrap_argv(shell_cmd: str) -> tuple[list[str], bool]:
    """把 `bash -c CMD` 包进沙箱 argv。

    返回 (argv 列表, sandboxed bool)。沙箱不可用时返回原始 ["bash","-c",CMD], False。
    """
    status = detect()
    if not status.available:
        return ["bash", "-c", shell_cmd], False

    if status.backend == "bwrap":
        argv = [
            "bwrap",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--die-with-parent",
            "bash", "-c", shell_cmd,
        ]
        return argv, True

    if status.backend == "firejail":
        argv = ["firejail", "--quiet", "--noprofile"]
        for p in _READONLY_PATHS:
            argv.append(f"--read-only={p}")
        argv.extend(["bash", "-c", shell_cmd])
        return argv, True

    return ["bash", "-c", shell_cmd], False
