# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

AiOps -- 基于 DeepSeek API + LangChain/LangGraph 的 AI Linux 运维助手。用户通过自然语言描述运维任务，ReAct Agent 自动选择工具执行，并经过安全审查层把关。Python 3.10+。

## 常用命令

```bash
# 安装依赖（无 requirements.txt，依赖列表见 setup.sh）
pip install langchain langchain-openai langgraph rich

# 交互模式运行
python aiops.py

# 单次模式
python aiops.py "查看磁盘占用"
python aiops.py -C "查看磁盘占用"

# 会话管理
python aiops.py -c          # 继续上次对话
python aiops.py -r          # 选择历史对话恢复

# 执行 setup.sh 后可用 ai 别名代替 python aiops.py
```

无测试套件和 lint 配置。手动验证场景见 docs/plan/AiOps-Plan.md 末尾。

## 架构

```
用户输入 → aiops.py（CLI 循环）→ agent.py（ReAct Agent）
  → 工具选择 → [safety.py 安全审查（仅危险操作）] → tools.py 执行
  → logger.py 审计日志 → Agent 总结 → rich 控制台输出
```

### 模块职责

| 模块 | 职责 |
|---|---|
| `aiops.py` | 主入口、CLI 交互循环（`aiops>` 提示符）、会话持久化（JSONL）、命令历史、rich 流式输出 |
| `agent.py` | 通过 `langgraph.prebuilt.create_react_agent` 构建 ReAct Agent，包含中文系统提示词 |
| `tools.py` | 8 个工具，通过 `ALL_TOOLS` 列表导出；子进程封装 `_run_command()`，30s 超时，5000 字符截断 |
| `safety.py` | 独立安全审查层：`review_command()`（5 级风险）和 `review_file_path()`（allow/warn/deny） |
| `logger.py` | `OpsLogger` 类，JSON Lines 格式写入 `~/.aiops/logs/ops.log`，10MB 轮转，5 个备份 |
| `config.json` | 全局配置；用户级覆盖在 `~/.aiops/config.json`；环境变量 `DEEPSEEK_API_KEY` 优先级最高 |

### 安全审查层

仅 `execute_command` 和 `read_file` 经过 `safety.py`，其余 6 个 `check_*`/`network_check` 工具为只读操作，直接放行。

- **命令风险分级**：BLOCKED（如 `rm -rf /`、`mkfs`）> HIGH（rm 涉及系统路径）> MEDIUM（`systemctl restart`、`kill`）> LOW > SAFE
- **文件路径审查**：DENY（`~/.ssh/`、`/etc/shadow`）> WARN（`*.pem`、`*.key`）> ALLOW
- **交互式命令**（vim、top、mysql）始终 BLOCKED（子进程无 TTY）

### 确认流程

当工具调用需要确认时，`execute_command` 返回 `[需要确认]` 消息而非执行命令。Agent 随后向用户询问确认；用户确认后 Agent 以 `confirmed=True` 重新调用，绕过安全门禁执行。

### 运行时数据

用户数据统一存放在 `~/.aiops/` 下：`conversations/`（JSONL 会话归档）、`logs/`（审计日志）、`aiops_history`（readline 历史）、`config.json`（用户级配置覆盖）。

### 关键常量

- 子进程 shell：`/bin/bash`，工作目录：`$HOME`
- 输出截断：5000 字符（保留尾部）
- 默认最大 Agent 轮次：25（LangGraph `recursion_limit = max_turns * 2 + 1`）
- 配置优先级：硬编码默认值 < 全局 `config.json` < 用户 `~/.aiops/config.json` < `--config` 参数 < `DEEPSEEK_API_KEY` 环境变量
