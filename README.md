# AiOps

AI 驱动的 Linux 运维助手。用自然语言描述运维需求，AI 自动理解意图、选择工具、执行命令、分析结果。

基于 DeepSeek API + LangChain/LangGraph 构建 ReAct Agent，内置安全审查层，危险操作自动拦截或要求确认。

## 快速开始

### 安装

```bash
# 一键安装（创建 ai 命令）
./setup.sh

# 或手动安装
pip install langchain langchain-openai langgraph rich
```

### 配置 API Key

```bash
# 方式一：环境变量（推荐）
export DEEPSEEK_API_KEY=sk-xxx

# 方式二：编辑配置文件
vim config.json          # 全局配置
vim ~/.aiops/config.json # 用户级配置（覆盖全局）
```

### 使用

```bash
# 交互模式
ai
aiops> 查看磁盘占用情况
aiops> 哪个进程占用内存最多
aiops> exit

# 单次模式
ai "帮我看下 8080 端口是否被占用"
ai -C "nginx 服务状态怎么样"

# 会话管理
ai -c          # 继续上次对话
ai -r          # 选择历史对话恢复
```

## 功能特性

**8 个内置工具** — AI 根据意图自动选择：

| 工具 | 功能 | 示例 |
|------|------|------|
| `check_disk` | 磁盘使用情况 | "磁盘占用怎么样" |
| `check_process` | 进程资源占用 | "哪个进程吃内存最多" |
| `check_port` | 端口占用情况 | "8080 端口被谁占了" |
| `check_service` | systemd 服务状态 | "nginx 跑着没" |
| `check_log` | 系统日志查看 | "最近有没有报错" |
| `network_check` | 网络诊断 | "ping 一下 google.com" |
| `read_file` | 文件读取 | "看下 nginx 配置" |
| `execute_command` | 执行任意命令 | "重启 nginx 服务" |

**安全审查** — 危险操作自动拦截：

```
ai 帮我格式化 /dev/sdb     → [拦截] 命令被安全策略拦截
ai 帮我看下 /etc/shadow    → [拦截] 禁止读取敏感文件
ai 帮我重启 nginx          → [需要确认] 中风险操作，等待用户确认
ai 查看磁盘占用             → 直接执行，无需确认
```

**其他特性**：
- 多轮对话，支持上下文追问
- 会话持久化，可恢复历史对话
- Rich 终端 Markdown 渲染，流式输出
- JSON Lines 审计日志，全程可追溯
- 命令历史（`!!` 重复、`!n` 回溯、`history` 查看）

## 技术栈

| 组件 | 选型 |
|------|------|
| LLM | DeepSeek API（OpenAI 兼容格式） |
| Agent 框架 | LangChain + LangGraph（ReAct Agent） |
| 终端 UI | Rich（Markdown 渲染、流式输出） |
| 语言 | Python 3.10+ |

## 项目结构

```
AiOps/
├── aiops.py        # 主入口、CLI 交互、会话管理
├── agent.py        # ReAct Agent 构建 + 系统提示词
├── tools.py        # 8 个工具定义
├── safety.py       # 安全审查层（命令风险分级 + 路径审查）
├── logger.py       # JSON Lines 审计日志
├── config.json     # 全局配置
├── setup.sh        # 安装脚本
└── docs/
    ├── design.md   # 详细设计文档
    └── plan/
        └── AiOps-Plan.md  # 实施计划
```

## 配置

```json
{
  "api_key": "sk-xxx",
  "base_url": "https://api.deepseek.com",
  "model": "deepseek-chat",
  "max_turns": 25,
  "command_timeout": 30,
  "log_max_size_mb": 10,
  "log_backup_count": 5,
  "color_output": true
}
```

配置优先级：硬编码默认值 < `config.json` < `~/.aiops/config.json` < `--config` 参数 < `DEEPSEEK_API_KEY` 环境变量

## 文档

- [详细设计文档](docs/design.md) — 架构设计、工具参数规格、安全审查规则、运行时机制
- [实施计划](docs/plan/AiOps-Plan.md) — 模块职责、实施步骤、验证场景
