#!/usr/bin/env python3
"""AiOps - AI 运维助手主程序入口"""

import argparse
import json
import os
import re
import readline
import signal
import sys
import uuid
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markdown import Heading, Markdown
from rich.text import Text

from agent import create_agent
from logger import OpsLogger
from tools import set_ops_logger

# Rich 控制台
console = Console()

# 颜色名称（用于 rich 标记）
GREEN = "green"
RED = "red"
YELLOW = "yellow"
GRAY = "dim"

# 标题里的 emoji 常被终端字体渲染成豆腐块，渲染时一并去掉
_HEADING_EMOJI_RE = re.compile(
    "[\U0001f300-\U0001faff\U00002600-\U000027bf\U0001f1e6-\U0001f1ff"
    "\U00002b00-\U00002bff\U0000fe0f\U00002190-\U000021ff]"
)


class _LeftHeading(Heading):
    """rich 默认把标题居中；这里改为左对齐，并剥离标题里的 emoji。"""

    def __rich_console__(self, console, options):
        text = self.text
        text.justify = "left"
        plain = _HEADING_EMOJI_RE.sub("", text.plain).rstrip()
        heading = Text(plain, style=self.style_name)
        if self.tag == "h2":
            yield Text("")
        yield heading


class LeftMarkdown(Markdown):
    """标题左对齐、标题去 emoji 的终端 Markdown 渲染。"""

    elements = {**Markdown.elements, "heading_open": _LeftHeading}


def load_config(config_path: str | None = None) -> dict:
    default_config = {
        "api_key": "",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "max_turns": 25,
        "command_timeout": 30,
        "log_max_size_mb": 10,
        "log_backup_count": 5,
        "color_output": True,
    }

    # 全局配置（resolve 解析 symlink）
    global_config_path = Path(__file__).resolve().parent / "config.json"
    if global_config_path.exists():
        with open(global_config_path, encoding="utf-8") as f:
            default_config.update(json.load(f))

    # 用户级配置
    user_config_path = Path.home() / ".aiops" / "config.json"
    if user_config_path.exists():
        with open(user_config_path, encoding="utf-8") as f:
            default_config.update(json.load(f))

    # 命令行指定
    if config_path and Path(config_path).exists():
        with open(config_path, encoding="utf-8") as f:
            default_config.update(json.load(f))

    # 环境变量优先
    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key:
        default_config["api_key"] = env_key

    return default_config


def setup_user_dir():
    user_dir = Path.home() / ".aiops"
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "logs").mkdir(exist_ok=True)
    (user_dir / "conversations").mkdir(exist_ok=True)


def _conversations_dir() -> Path:
    d = Path.home() / ".aiops" / "conversations"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_session(session_id: str, messages: list, title: str = ""):
    """保存会话到 conversations/<uuid>.jsonl，第一行为 meta 头。"""
    path = _conversations_dir() / f"{session_id}.jsonl"
    now = datetime.now().isoformat(timespec="seconds")

    # 读取已有 meta 行获取 created_at
    created_at = now
    if path.exists():
        with open(path, encoding="utf-8") as f:
            first = f.readline().strip()
            if first:
                try:
                    old_meta = json.loads(first)
                    created_at = old_meta.get("created_at", now)
                except json.JSONDecodeError:
                    pass

    # 生成标题：取第一条用户消息前 50 字符
    if not title:
        for m in messages:
            if m.get("role") == "user":
                title = m["content"][:50].replace("\n", " ")
                break

    meta = {
        "type": "meta",
        "id": session_id,
        "created_at": created_at,
        "updated_at": now,
        "title": title or "(无标题)",
        "message_count": len(messages),
    }

    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(meta, ensure_ascii=False) + "\n")
        for m in messages:
            entry = {"type": m["role"], "content": m["content"]}
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_session(session_id: str) -> list | None:
    """加载指定会话的 messages 列表。"""
    path = _conversations_dir() / f"{session_id}.jsonl"
    if not path.exists():
        return None
    messages = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("type") == "meta":
                continue
            messages.append({"role": entry["type"], "content": entry["content"]})
    return messages if messages else None


def list_sessions(limit: int = 20) -> list[dict]:
    """扫描 conversations 目录，返回按时间倒序排列的会话列表。"""
    sessions = []
    for path in _conversations_dir().glob("*.jsonl"):
        try:
            with open(path, encoding="utf-8") as f:
                first = f.readline().strip()
                if not first:
                    continue
                meta = json.loads(first)
                if meta.get("type") != "meta":
                    continue
                sessions.append(meta)
        except (json.JSONDecodeError, OSError):
            continue
    sessions.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return sessions[:limit]


def save_history(command: str):
    history_path = Path.home() / ".aiops" / "aiops_history"
    with open(history_path, "a", encoding="utf-8") as f:
        f.write(command + "\n")


def load_history() -> list[str]:
    history_path = Path.home() / ".aiops" / "aiops_history"
    if history_path.exists():
        try:
            lines = history_path.read_text(encoding="utf-8").strip().splitlines()
            return lines[-100:]
        except UnicodeDecodeError:
            # 历史文件损坏，删除重建
            history_path.unlink()
    return []


def print_colored(text: str, color: str, use_color: bool):
    if use_color:
        console.print(f"[{color}]{text}[/{color}]", highlight=False)
    else:
        console.print(text, highlight=False)


def handle_ctrl_c(signum, frame):
    raise KeyboardInterrupt


def _stream_agent(agent, messages: list, recursion_limit: int) -> str:
    """流式输出 token，实时用 rich 渲染 markdown（Live 原地更新）。"""
    from rich.live import Live

    full_response = ""
    is_final_reply = False
    seen_tool_call_msg = False

    with Live(console=console, refresh_per_second=15, vertical_overflow="visible") as live:
        for chunk, metadata in agent.stream(
            {"messages": messages},
            config={"recursion_limit": recursion_limit},
            stream_mode="messages",
        ):
            if not hasattr(chunk, "content"):
                continue
            if metadata.get("langgraph_node") == "tools":
                continue

            content = chunk.content or ""
            tool_calls = getattr(chunk, "tool_calls", [])

            if tool_calls:
                seen_tool_call_msg = True
                is_final_reply = False
                continue

            if seen_tool_call_msg and not is_final_reply and content:
                is_final_reply = True
                # 工具调用前的旁白与最终答案之间补空行，否则会拼成一行，
                # 导致最终答案开头的 "# 标题" 变成行中字面 # 而非标题
                if full_response and not full_response.endswith("\n"):
                    full_response += "\n\n"
            if not seen_tool_call_msg:
                is_final_reply = True
            if not is_final_reply:
                continue

            if content:
                full_response += content
                # 每收到一个 token 就更新 Live 显示
                live.update(LeftMarkdown(full_response))

    return full_response


def _resume_interactive(agent, config: dict, recursion_limit: int):
    """-r 模式：列出历史会话，用户选择后恢复。"""
    use_color = config.get("color_output", True)
    sessions = list_sessions(limit=20)

    if not sessions:
        print_colored("没有历史对话", RED, use_color)
        return

    print_colored("历史对话列表：\n", GREEN, use_color)
    for i, s in enumerate(sessions, 1):
        time_str = s.get("updated_at", "?")
        title = s.get("title", "(无标题)")
        count = s.get("message_count", 0)
        print(f"  {i:3d}  {time_str}  {title}  ({count} 条消息)")
    print()

    while True:
        try:
            choice = input("选择序号恢复 (q 取消): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice.lower() == "q":
            return

        if not choice.isdigit():
            print_colored("请输入数字序号", YELLOW, use_color)
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(sessions):
            print_colored(f"序号超出范围 (1-{len(sessions)})", YELLOW, use_color)
            continue

        sid = sessions[idx]["id"]
        messages = load_session(sid)
        if messages:
            run_interactive(agent, config, recursion_limit, session_id=sid, messages=messages)
        else:
            print_colored("该会话为空", RED, use_color)
        return


def run_single(agent, query: str, use_color: bool, recursion_limit: int = 21) -> int:
    try:
        _stream_agent(agent, [{"role": "user", "content": query}], recursion_limit)
        return 0
    except Exception as e:
        print_colored(f"\n执行异常: {e}", RED, use_color)
        return 1


def run_interactive(agent, config: dict, recursion_limit: int = 21,
                    session_id: str | None = None, messages: list | None = None):
    use_color = config.get("color_output", True)
    history = load_history()

    # 会话管理
    if session_id is None:
        session_id = uuid.uuid4().hex[:12]
    if messages is None:
        messages = []

    if messages:
        print_colored(f"已恢复会话 ({len(messages)} 条消息)\n", GREEN, use_color)
        for m in messages:
            if m["role"] == "user":
                console.print(f"[bold]aiops>[/bold] {m['content']}")
            else:
                console.print(LeftMarkdown(m["content"]))
            print()

    print_colored("AiOps 已启动，输入命令开始对话", GREEN, use_color)
    print_colored("输入 exit/quit/Ctrl+D 退出，!! 重复上一条命令，history 查看历史", GRAY, use_color)
    print()

    # readline 提供正确的行编辑支持（退格、光标移动等）
    readline.parse_and_bind("tab: complete")

    while True:
        try:
            # 用 readline.input() 正确处理转义码
            user_input = input("aiops> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue

        # 处理 Ctrl+C 在输入后的情况
        if user_input == "\x03":
            continue

        # exit/quit
        if user_input.lower() in ("exit", "quit"):
            break

        # history
        if user_input == "history":
            for i, cmd in enumerate(history[-20:], 1):
                console.print(f"  {i:3d}  {cmd}")
            continue

        # !! 重复上一条
        if user_input == "!!":
            if history:
                user_input = history[-1]
                console.print(f"  {user_input}")
            else:
                console.print("没有历史命令")
                continue

        # !n 执行历史第 n 条
        if user_input.startswith("!") and user_input[1:].isdigit():
            idx = int(user_input[1:]) - 1
            if 0 <= idx < len(history):
                user_input = history[idx]
                console.print(f"  {user_input}")
            else:
                console.print(f"历史命令编号超出范围 (1-{len(history)})")
                continue

        history.append(user_input)
        save_history(user_input)

        try:
            messages.append({"role": "user", "content": user_input})
            ai_content = _stream_agent(agent, messages, recursion_limit)

            if ai_content:
                messages.append({"role": "assistant", "content": ai_content})

        except KeyboardInterrupt:
            print_colored("\n操作已取消", YELLOW, use_color)
            if messages and messages[-1].get("role") == "user":
                messages.pop()
        except Exception as e:
            print_colored(f"\n执行异常: {e}", RED, use_color)
            if messages and messages[-1].get("role") == "user":
                messages.pop()

    # 退出时自动保存会话
    if messages:
        save_session(session_id, messages)
        print_colored("会话已保存", GRAY, use_color)


def main():
    parser = argparse.ArgumentParser(description="AiOps - AI 运维助手")
    parser.add_argument("query", nargs="*", help="单次模式：直接传入问题")
    parser.add_argument("-C", "--command", help="单次模式：显式传入命令")
    parser.add_argument("-c", "--continue", dest="continue_last", action="store_true",
                        help="继续上次对话")
    parser.add_argument("-r", "--resume", action="store_true",
                        help="选择历史对话恢复")
    parser.add_argument("--config", help="指定配置文件路径")
    parser.add_argument("--no-color", action="store_true", help="禁用颜色输出")
    parser.add_argument("--version", action="version", version="AiOps v0.1.0")
    args = parser.parse_args()

    setup_user_dir()
    config = load_config(args.config)

    if args.no_color:
        config["color_output"] = False

    # 检查 API Key
    if not config.get("api_key"):
        console.print("[red]错误: 未配置 API Key[/red]")
        console.print("请通过以下方式之一配置:")
        console.print("  1. 设置环境变量: export DEEPSEEK_API_KEY=sk-xxx")
        console.print("  2. 编辑配置文件: ~/.aiops/config.json")
        console.print("  3. 编辑全局配置: /root/aiops/config.json")
        sys.exit(1)

    # 初始化日志
    ops_logger = OpsLogger(
        log_max_size_mb=config.get("log_max_size_mb", 10),
        log_backup_count=config.get("log_backup_count", 5),
    )
    set_ops_logger(ops_logger)

    # 创建 agent
    agent, max_turns = create_agent(
        api_key=config["api_key"],
        base_url=config["base_url"],
        model=config["model"],
        max_turns=config.get("max_turns", 10),
    )
    recursion_limit = max_turns * 2 + 1

    # 注册信号处理
    signal.signal(signal.SIGINT, handle_ctrl_c)

    # 单次模式 or 交互模式
    query = args.command or " ".join(args.query) if args.query else None
    if query:
        sys.exit(run_single(agent, query, config.get("color_output", True), recursion_limit))
    elif args.continue_last:
        # -c: 继续最近一次对话
        sessions = list_sessions(limit=1)
        if not sessions:
            print_colored("没有历史对话", RED, config.get("color_output", True))
            sys.exit(1)
        sid = sessions[0]["id"]
        messages = load_session(sid)
        run_interactive(agent, config, recursion_limit, session_id=sid, messages=messages)
    elif args.resume:
        # -r: 选择历史对话
        _resume_interactive(agent, config, recursion_limit)
    else:
        run_interactive(agent, config, recursion_limit)


if __name__ == "__main__":
    main()
