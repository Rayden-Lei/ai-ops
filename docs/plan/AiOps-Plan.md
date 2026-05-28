# AI 运维助手 — 实施计划

## Context
在 Linux 服务器上搭建一个基于 DeepSeek API + LangChain 的 AI 运维助手。用户在终端输入 `ai <需求>`，AI 自动理解意图、执行 shell 命令、分析结果，支持多轮对话和 ReAct 循环。

## 技术选型
- **LLM**: DeepSeek API（OpenAI 兼容格式）
- **Agent 框架**: LangChain + LangGraph（现代 ReAct Agent 实现）
- **终端 UI**: Rich（Markdown 渲染、彩色输出、流式显示）
- **语言**: Python 3.10+
- **包管理**: pip

## 依赖
```
langchain>=0.2
langchain-openai>=0.1
langgraph>=0.2
rich
```

## 架构设计

### 工作流程（ReAct 循环）
```
用户输入 → [Reason] AI 分析意图 → [Act] 选择并调用工具 → [Observe] 获取结果
    ↑                                                          ↓
    └──────────── 如需要，继续推理执行更多操作 ←────────────────┘
                                                          最终输出总结
```

### 文件结构
```
AiOps/
├── aiops.py            # 主入口：CLI 交互循环、会话持久化、命令历史、rich 流式输出
├── agent.py            # ReAct Agent 构建 + 系统提示词
├── tools.py            # 8 个工具定义，通过 ALL_TOOLS 导出
├── safety.py           # 独立安全审查层：命令风险分级 + 文件路径审查
├── logger.py           # OpsLogger 类，JSON Lines 审计日志
├── config.json         # 全局配置（API key、模型、超时、日志轮转等）
├── setup.sh            # 一键安装脚本（创建 ai 命令）
├── README.md           # 使用说明
└── docs/
    └── plan/
        └── AiOps-Plan.md   # 本文档
```

## 核心实现

### 1. Agent 工具定义（tools.py）
8 个工具，按职责分为两类：

**需安全审查（经过 safety.py）：**
- `execute_command(command, confirmed?)` — 执行任意 shell 命令，高风险需确认
- `read_file(path, head?, tail?, confirmed?)` — 读取文件内容，敏感路径需确认

**只读工具（直接放行）：**
- `check_service(name)` — 查看 systemd 服务状态（is-active / is-enabled / status）
- `check_port(port?)` — 查看端口占用（ss -tlnp），不传 port 列出所有
- `check_disk(path?)` — 查看磁盘使用（df -h），不传 path 显示所有挂载点
- `check_process(sort_by?, limit?)` — 查看进程列表，默认按内存排序，返回 20 条
- `check_log(unit?, since?, lines?)` — 查看系统日志，优先 journalctl，不可用时回退到 /var/log/
- `network_check(target, method?)` — 网络诊断，method: ping / curl / traceroute

**子进程封装 `_run_command()`：**
- 使用 `subprocess.run(["bash", "-c", command])` 执行
- 工作目录：`$HOME`
- 超时控制：默认 30s
- 输出截断：5000 字符（保留尾部）

### 2. 安全审查层（safety.py）
独立模块，提供两个审查函数：

**`review_command(command)` — 命令风险分级（5 级）：**
- **BLOCKED**：`rm -rf /`、`mkfs`、`dd if=... of=/dev/`、fork 炸弹 — 直接拦截
- **HIGH**：rm 涉及系统路径（/etc、/usr 等）— 需用户确认
- **MEDIUM**：`systemctl stop/restart`、`kill`、`crontab -e`、`apt install` — 需确认
- **LOW**：一般写入操作 — 直接执行
- **SAFE**：只读命令 — 直接执行
- **交互式命令**（vim、top、mysql 等）始终 BLOCKED（子进程无 TTY）

**`review_file_path(path)` — 文件路径审查（3 级）：**
- **DENY**：`~/.ssh/`、`/etc/shadow`、`/proc/*/mem`、含 private/secret/credential 的路径
- **WARN**：`*.pem`、`*.key`、bash/zsh history
- **ALLOW**：其余路径

### 3. 确认流程
当 `execute_command` 或 `read_file` 需要确认时：
1. 工具返回 `[需要确认]` 消息（含风险等级和详情），**不执行命令**
2. Agent 将风险信息展示给用户，询问是否确认
3. 用户确认 → Agent 以 `confirmed=True` 重新调用，绕过安全门禁执行
4. 用户拒绝 → Agent 告知已取消

### 4. ReAct Agent（agent.py）
```python
from langgraph.prebuilt import create_react_agent

agent = create_react_agent(
    model=llm,           # DeepSeek ChatOpenAI (temperature=0)
    tools=ALL_TOOLS,     # 8 个工具
    prompt=SYSTEM_PROMPT
)
```

`create_react_agent` 自动实现：
- Reasoning：AI 分析用户意图，优先选择专用工具（如查磁盘用 check_disk）
- Acting：调用对应工具
- Observing：获取工具输出，决定是否继续
- 循环直到任务完成，最大轮次 25（`recursion_limit = max_turns * 2 + 1`）

### 5. 系统提示词（agent.py SYSTEM_PROMPT）
核心规则：
- 优先使用专用工具，减少 execute_command 的使用
- 对修改性操作先解释将要做什么
- 输出过长时做摘要
- 使用中文回复，Markdown 格式
- 不猜测命令输出，必须实际执行
- 知识性问题直接回答，不调用工具
- 用户意图不明确时先追问再行动
- 明显有害的请求直接拒绝
- 动态参数使用 `shlex.quote()` 转义防注入
- 输出使用 Markdown 表格、列表、粗体等格式

### 6. 审计日志（logger.py）
- `OpsLogger` 类，JSON Lines 格式写入 `~/.aiops/logs/ops.log`
- 每条日志：timestamp、level、tool、command/path、risk_level、action、result、error
- 日志轮转：10MB/文件，保留 5 个备份

### 7. CLI 接口（aiops.py）
```bash
# 单次模式
ai "查看磁盘占用"
ai -C "查看磁盘占用"

# 交互模式（进入 aiops> 提示符）
ai

# 会话管理
ai -c                     # 继续上次对话
ai -r                     # 选择历史对话恢复

# 其他参数
ai --help
ai --version              # v0.1.0
ai --config /path/to/config.json
ai --no-color             # 禁用彩色输出
```

交互模式功能：
- `aiops>` 提示符，支持多轮对话
- readline 命令历史（持久化到 `~/.aiops/aiops_history`）
- `!!` 重复上条输入，`!n` 回溯第 n 条，`history` 显示历史
- Rich Live 流式输出 Markdown 渲染
- `exit` / `quit` / `Ctrl+C` 退出
- 退出时自动保存会话到 `~/.aiops/conversations/*.jsonl`

### 8. 配置文件 config.json
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

**配置优先级**：硬编码默认值 < 全局 `config.json` < 用户 `~/.aiops/config.json` < `--config` 参数 < `DEEPSEEK_API_KEY` 环境变量

### 9. setup.sh 安装脚本
- 检测 Python 3.10+ 版本兼容性
- 安装 Python 依赖（langchain、langchain-openai、langgraph、rich）
- 创建 `/usr/local/bin/ai` 软链接
- 创建用户数据目录 `~/.aiops/`（logs、conversations）
- 设置全局配置文件权限（chmod 600）
- 未检测到 API Key 时提示配置方式

### 10. 运行时数据目录
```
~/.aiops/
├── config.json         # 用户级配置覆盖
├── aiops_history       # readline 命令历史
├── logs/
│   └── ops.log         # JSON Lines 审计日志（10MB 轮转，5 个备份）
└── conversations/
    └── *.jsonl         # 会话归档（含元数据头）
```

## 实施步骤

1. ~~**创建项目结构** — 目录 + config.json + README.md~~ ✅
2. ~~**编写 tools.py** — 8 个工具定义 + 子进程封装~~ ✅
3. ~~**编写 safety.py** — 命令风险分级 + 文件路径审查~~ ✅
4. ~~**编写 agent.py** — ReAct Agent 构建 + 系统提示词~~ ✅
5. ~~**编写 logger.py** — JSON Lines 审计日志~~ ✅
6. ~~**编写 aiops.py** — CLI 交互循环 + 会话管理 + rich 输出~~ ✅
7. ~~**编写 setup.sh** — 依赖安装 + 命令注册~~ ✅
8. ~~**测试验证** — 典型运维场景~~ ✅

## 验证场景
```bash
ai 帮我查看磁盘占用情况          # 应调用 check_disk
ai 哪个进程占用内存最多           # 应调用 check_process
ai 帮我看下 8080 端口是否被占用   # 应调用 check_port
ai nginx 服务状态怎么样           # 应调用 check_service
ai 帮我看下系统日志有没有报错     # 应调用 check_log
ai 帮我 ping 一下 google.com     # 应调用 network_check
ai 帮我看下 nginx 配置文件       # 应调用 read_file
ai 帮我重启 nginx 服务           # 应调用 execute_command + 确认流程
ai 帮我格式化 /dev/sdb           # 应被安全层拦截（BLOCKED）
ai 帮我看下 /etc/shadow          # 应被路径审查拒绝（DENY）
ai 帮我 rm -rf /etc              # 应被拦截（高风险 + 系统路径）
ai 帮我清理 /tmp 下 7 天前的文件  # 应提示风险并要求确认
ai 系统负载怎么样                # 应执行 uptime/top 分析
```
