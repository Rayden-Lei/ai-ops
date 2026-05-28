# AiOps 详细设计文档

AiOps 的架构设计、工具参数规格、安全审查规则、运行时机制等详细文档。项目简介见 [README.md](../README.md)。

## 技术选型

| 组件 | 选型 | 说明 |
|------|------|------|
| LLM | DeepSeek API | OpenAI 兼容格式，性价比高 |
| Agent 框架 | LangChain + LangGraph | 现代 ReAct Agent 实现 |
| 语言 | Python 3.10+ | |

## 依赖

```
langchain>=0.2
langchain-openai>=0.1
langgraph>=0.2
rich
```

## 架构设计

### 整体架构

```
                    ┌─────────────────────────────────────┐
                    │           用户输入 / 输出            │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │        ReAct Agent (LangGraph)       │
                    │   Reason → Act → Observe → 循环      │
                    └──────────────┬──────────────────────┘
                                   │ 工具调用
                    ┌──────────────┴──────────────────────┐
                    │                                      │
          ┌─────────▼──────────┐            ┌─────────────▼─────────────┐
          │  安全审查工具        │            │  只读专用工具              │
          │  execute_command    │            │  check_disk / check_port  │
          │  read_file          │            │  check_service / ...      │
          └─────────┬──────────┘            └─────────────┬─────────────┘
                    │                                      │
          ┌─────────▼──────────┐                           │
          │   安全审查层        │                           │
          │  命令/路径风险分级  │                           │
          │  确认 / 拦截       │                           │
          └─────────┬──────────┘                           │
                    │ 通过审查                              │
                    └──────────────┬───────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │           工具执行层                  │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │           日志记录层                  │
                    │  记录所有工具调用、结果、异常          │
                    └─────────────────────────────────────┘
```

### ReAct 循环

```
用户输入 → [Reason] AI 分析意图 → [Act] 选择工具执行 → [Observe] 获取结果
    ↑                                                          ↓
    └──────────── 如需要，继续推理执行更多命令 ←──────────────────┘
                                                         最终输出总结
```

### 文件结构

```
/root/aiops/                    # 项目目录（安装位置）
├── aiops.py            # 主程序入口 + CLI 交互
├── agent.py            # ReAct Agent 构建（LangGraph）
├── tools.py            # 工具定义（拆分的多个工具）
├── safety.py           # 安全审查层（独立模块）
├── logger.py           # 日志记录模块
├── config.json         # 全局配置（API key、模型名、base_url）
├── setup.sh            # 一键安装脚本
├── README.md           # 项目简介
└── docs/
    └── design.md       # 本文件（详细设计文档）

~/.aiops/                       # 用户数据目录（运行时生成）
├── config.json         # 用户级配置（覆盖全局配置）
├── logs/
│   └── ops.log         # 运行日志
├── aiops_history       # 命令历史
└── conversations/      # 对话存档
```

项目代码在 `/root/aiops/`，用户数据在 `~/.aiops/`。支持多用户独立使用。

## 核心实现

### 1. 工具定义（tools.py）

拆分为多个专用工具，让 AI 更精准地选择：

| 工具名 | 用途 | 需安全审查 |
|--------|------|-----------|
| `execute_command` | 执行任意 shell 命令 | 是 |
| `read_file` | 读取文件内容（只读） | 是（路径审查） |
| `check_service` | 查看 systemd 服务状态 | 否 |
| `check_port` | 查看端口占用情况 | 否 |
| `check_disk` | 查看磁盘使用情况 | 否 |
| `check_process` | 查看进程列表和资源占用 | 否 |
| `check_log` | 读取系统日志（journalctl / /var/log） | 否 |
| `network_check` | 网络诊断，参数：target + method(ping/curl/traceroute) | 否 |

安全审查并非一刀切：只读专用工具（check_* 系列、network_check）本身操作安全，无需经过安全层；`execute_command` 和 `read_file` 因操作范围不可控，必须经过安全层审查。

各工具参数规格：

#### `execute_command`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `command` | str | 是 | — | 要执行的 shell 命令 |

subprocess 执行，超时控制（默认 30s），stdout+stderr 合并，输出截断（max 5000 字符，保留尾部）。检测到交互式命令（vim/top/htop/mysql 等）时拒绝执行并提示用户手动操作。不做特殊字符过滤（`|`、`&&` 等是合法 shell 语法），命令注入防护依赖安全层的模式匹配（见 8.7）。

#### `read_file`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | str | 是 | — | 文件路径 |
| `head` | int | 否 | None | 只读前 N 行 |
| `tail` | int | 否 | None | 只读后 N 行 |

head 和 tail 互斥，同时指定时 tail 优先。受安全层路径审查约束。文件大小限制 1MB。

#### `check_service`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `name` | str | 是 | — | 服务名（如 nginx, docker） |

封装 `systemctl status/is-active/is-enabled`，通常不需要 root，部分受限服务可能信息不完整。

#### `check_port`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `port` | int | 否 | None | 指定端口号，不指定则列出所有监听端口 |

封装 `ss -tlnp`。

#### `check_disk`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | str | 否 | None | 指定挂载点路径，不指定则显示所有 |

封装 `df -h`。

#### `check_process`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `sort_by` | str | 否 | "memory" | 排序字段："memory" 或 "cpu" |
| `limit` | int | 否 | 20 | 返回条数 |

封装 `ps aux --sort=-%mem`（或 `-%cpu`）。

#### `check_log`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `unit` | str | 否 | None | 指定 systemd unit（如 nginx） |
| `since` | str | 否 | "1h" | 时间范围，支持相对时间（"1h", "30m", "1d"）和绝对时间（"2024-01-15"） |
| `lines` | int | 否 | 100 | 返回行数 |

优先使用 `journalctl`，journald 不可用时回退到读取 `/var/log/syslog` 或 `/var/log/messages`（此时 unit 参数无效）。输出超过 2000 字符时自动截取尾部（最新日志更有价值）。

#### `network_check`

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `target` | str | 是 | — | 目标地址（IP 或域名） |
| `method` | str | 否 | "ping" | 诊断方式："ping"（连通性）、"curl"（HTTP 状态）、"traceroute"（路由追踪） |

`method="curl"` 时，`target` 应为完整 URL（如 `http://example.com`），默认 GET 请求，超时 10s。

#### 工具设计原则

`execute_command` 是通用后备工具，专用工具是特定场景的快捷封装。AI 应优先使用语义更明确的专用工具（如查磁盘用 `check_disk` 而非 `df -h`），专用工具无法满足时再使用 `execute_command`。这个约束通过系统提示词实现，而非代码强制——因为运维场景复杂，不能堵死通用能力。

### 2. 安全审查层（safety.py）

独立于工具执行，`execute_command` 和 `read_file` 的调用必须经过安全层审查后才能执行。

#### 2.1 命令风险分级（execute_command）

| 等级 | 处理方式 | 示例 |
|------|----------|------|
| **安全 (safe)** | 直接执行，记录日志 | `df -h`, `ps aux`, `cat /etc/hostname` |
| **低风险 (low)** | 直接执行，记录日志 | `ls`, `grep`, `tail -f` |
| **中风险 (medium)** | 终端显示命令，要求确认，用户可修改后执行 | `systemctl restart nginx`, `kill <pid>` |
| **高风险 (high)** | 终端红色警告，要求二次确认，用户可修改后执行 | `rm -rf /tmp/*`, `chmod 777 /opt/app`, `iptables -F` |
| **禁止 (blocked)** | 直接拦截，不执行 | `rm -rf /`, `mkfs`, `dd of=/dev/sda` |

#### 2.2 风险判定逻辑：命令 + 目标路径

风险判定不是简单的关键字匹配，而是**命令 + 目标路径**组合判断：

**禁止执行（blocked）：**
- `rm -rf /` 或 `rm -rf /*` — 递归删除根目录
- `mkfs.*` — 格式化磁盘
- `dd if=.* of=/dev/` — 直接写磁盘
- `:(){ :|:& };:` — fork 炸弹
- `> /dev/sda` — 覆盖磁盘

**高风险（需二次确认）：**
- `rm -rf` 目标为系统关键路径（`/etc`, `/usr`, `/var`, `/bin`, `/sbin`, `/boot`, `/lib`）
- `chmod 777` / `chown -R` 应用于系统目录
- `shutdown` / `reboot` / `init 0` — 系统关机
- `iptables -F` — 清空防火墙
- `userdel` / `groupdel` — 删除用户/组

**中风险（需确认）：**
- `systemctl stop/restart` — 服务启停
- `kill` / `killall` — 终止进程
- `mv` / `cp -r` 涉及系统目录
- `crontab -e` — 修改定时任务
- `apt/yum install/remove` — 包管理

**安全（无需审查）：**
- `rm -rf /tmp/*`, `rm -rf /var/log/*.old` — 临时目录/日志清理
- `rm -rf ./build`, `rm -rf node_modules` — 项目目录清理
- 所有 `rm` 目标为非系统路径且非隐藏目录

#### 2.3 文件路径审查（read_file）

`read_file` 不限制工具本身，但限制可读路径。规则基于目录级，避免逐个文件遗漏：

**禁止读取（目录级）：**
- `~/.ssh/` 整个目录 — 私钥、公钥、known_hosts 等全部敏感
- `/etc/shadow`, `/etc/gshadow` — 密码哈希
- `/proc/*/mem` — 进程内存
- 路径中包含 `private`、`secret`、`credential` 的文件

**警告读取（需确认，可读但提醒用户）：**
- `*.pem`, `*.key` 文件 — 可能是私钥，也可能是普通配置，让用户确认
- `~/.bash_history`, `~/.zsh_history` — 可能包含敏感命令

**允许读取：**
- 系统配置文件（`/etc/nginx/`, `/etc/mysql/`, `/etc/hosts` 等）
- 日志文件（`/var/log/`）
- 用户项目文件
- `/proc` 下的非内存文件（`/proc/cpuinfo`, `/proc/meminfo` 等）

#### 2.4 审查流程

```python
def review_command(command: str) -> SafetyResult:
    """
    审查命令安全性，返回 SafetyResult(risk_level, message, require_confirm)

    流程：
    1. 检测交互式命令 → 拒绝执行（BLOCKED）
    2. 匹配禁止模式（命令+路径组合）→ 拦截（BLOCKED）
    3. 匹配高风险模式（命令+路径组合）→ 需确认（HIGH）
    4. 匹配中风险模式 → 需确认（MEDIUM）
    5. 默认 → 安全，直接执行（SAFE）
    """

def review_file_path(path: str) -> FileReview:
    """
    审查文件路径是否允许读取。

    返回 FileReview 枚举：
    - ALLOW：允许读取
    - DENY：禁止读取（~/.ssh/、/etc/shadow 等）
    - WARN：警告读取（*.pem、*.key 等，提示用户确认）
    """
```

#### 2.5 确认流程

中风险和高风险命令通过 Agent 对话确认：

1. `execute_command` / `read_file` 返回 `[需要确认]` 消息（含风险等级和详情），**不执行命令**
2. Agent 将风险信息展示给用户，询问是否确认
3. 用户确认 → Agent 以 `confirmed=True` 重新调用同一工具，绕过安全门禁执行
4. 用户拒绝 → Agent 告知已取消，不执行

### 3. 日志记录（logger.py）

所有工具调用都记录到日志，用于审计和问题排查。

#### 日志格式

JSON Lines 格式，每行一条 JSON 记录：

```json
{"timestamp":"2024-01-15T10:30:45","level":"INFO","tool":"execute_command","command":"df -h","risk":"safe","action":"executed","result":"success","output_len":1024}
{"timestamp":"2024-01-15T10:31:02","level":"WARN","tool":"execute_command","command":"rm -rf /tmp/test","risk":"high","action":"confirmed_by_user","result":"success","output_len":256}
{"timestamp":"2024-01-15T10:31:15","level":"ERROR","tool":"execute_command","command":"systemctl restart nginx","risk":"medium","action":"executed","result":"timeout","error":"timeout after 30s"}
{"timestamp":"2024-01-15T10:32:00","level":"INFO","tool":"check_disk","params":{},"action":"executed","result":"success"}
{"timestamp":"2024-01-15T10:33:00","level":"INFO","tool":"read_file","path":"/etc/nginx/nginx.conf","risk":"safe","action":"executed","result":"success"}
```

#### 日志字段

| 字段 | 说明 |
|------|------|
| timestamp | ISO 8601 时间戳 |
| level | 日志级别（INFO/WARN/ERROR） |
| request_id | 请求批次 ID，同一批并行调用共享 |
| tool | 工具名 |
| command/params/path | 调用参数 |
| risk | 风险等级（safe/low/medium/high/blocked） |
| action | 处理方式（executed/confirmed_by_user/blocked/denied_by_user） |
| result | 执行结果（success/error/timeout） |
| output_len | 输出长度（不记录完整输出，防止日志膨胀） |
| error | 错误信息（如有） |

LangGraph 支持 AI 并行调用多个工具（如同时查磁盘和查内存）。同一批并行调用共享 `request_id`，日志中可区分哪些调用属于同一轮推理。

#### 日志配置

- 文件路径：`~/.aiops/logs/ops.log`
- 单文件最大：10MB
- 保留数量：5 个轮转文件
- 格式：JSON Lines（方便后续解析和检索）

### 4. ReAct Agent（agent.py）

```python
from langgraph.prebuilt import create_react_agent

agent = create_react_agent(
    model=llm,           # DeepSeek ChatOpenAI
    tools=tool_list,      # 拆分后的多个工具
    prompt=system_prompt
)
```

`create_react_agent` 自动实现：

- **Reasoning**：AI 分析用户意图，选择合适的工具
- **Acting**：调用选定的工具
- **Observing**：获取工具输出，决定是否继续
- 循环直到任务完成

#### 最大循环轮次

通过 `max_turns`（默认 25）限制 ReAct 循环次数，防止无限循环。LangGraph 的 `recursion_limit = max_turns * 2 + 1`。超过限制时强制终止并告知用户。

### 5. 系统提示词

```
你是一个 Linux 运维助手。你可以使用以下工具来帮助用户完成运维任务：

工具列表：
- execute_command(command, confirmed?): 执行任意 shell 命令（通用工具，需安全审查）
- read_file(path, head?, tail?, confirmed?): 读取文件内容（需路径审查）
- check_service(name): 查看 systemd 服务状态
- check_port(port?): 查看端口占用，不传 port 列出所有
- check_disk(path?): 查看磁盘使用，不传 path 查所有挂载点
- check_process(sort_by?, limit?): 查看进程，默认按内存排序，返回 20 条
- check_log(unit?, since?, lines?): 查看系统日志，默认最近 1 小时 100 行
- network_check(target, method?): 网络诊断，method 为 "ping"/"curl"/"traceroute"，默认 ping

工作方式：
1. 分析用户需求，优先使用专用工具（如查磁盘用 check_disk）
2. 专用工具无法满足时，使用 execute_command
3. 分析工具输出，给出清晰的结论
4. 如需要多步操作，逐步执行并汇总

规则：
- 优先使用专用工具，减少 execute_command 的使用
- 对于修改性操作，先解释将要做什么
- 输出过长时做摘要
- 使用中文回复
- 如果命令执行失败，分析原因并建议解决方案
- 不要猜测命令输出，必须实际执行后根据结果回答
- 对于不需要执行命令的知识性问题（如"什么是 inode"），直接回答，不需要调用工具
- 用户意图不明确时，先追问再行动，不要猜测
- 明显有害的请求（如"删除所有文件"）直接拒绝，不要调用工具
- 对用户输入的动态参数使用 shlex.quote() 转义，防止命令注入

安全确认流程：
当 execute_command 或 read_file 返回 "[需要确认]" 时，说明命令/文件存在风险，需要用户确认。此时你必须：
1. 将风险信息完整展示给用户
2. 明确询问用户是否确认执行
3. 用户确认后，再次调用同一工具并传入 confirmed=True
4. 用户拒绝时，告知已取消，不要自行执行

输出格式（使用 markdown，终端通过 Rich 自动渲染）：
- 使用 markdown 语法组织内容（标题、表格、列表、粗体）
- 用 emoji 增加可读性，但不要放在 # 标题里（会导致渲染错位）
```

### 6. 输出格式

- AI 回复使用 Markdown 格式（标题、表格、列表、粗体），通过 Rich 在终端实时渲染
- 流式输出：使用 `rich.live.Live` 实时更新 Markdown 渲染，逐 token 显示
- 颜色输出（可选，config.json 中 `color_output: true` 开启）：
  - 绿色：操作成功、服务正常
  - 红色：操作失败、服务异常、高风险警告
  - 黄色：中风险确认提示
  - 灰色：辅助信息

### 7. execute_command 运行环境

| 配置项 | 值 | 说明 |
|--------|-----|------|
| Shell | `/bin/bash` | 兼容 bash 语法（`[[ ]]`、`$()` 等） |
| 工作目录 | 用户 home（`$HOME`） | 不在项目目录下执行 |
| 环境变量 | 继承当前进程 | PATH、LANG 等完整继承 |
| 执行身份 | 启动进程的用户 | 通常为 root，需在文档中提醒 |
| 超时 | 30s（可配置） | 超时后 SIGTERM，再等 5s SIGKILL |
| 输出上限 | 5000 字符 | 超出部分截断，保留尾部 |

### 8. 运行时机制

#### 8.1 持续对话模式

- 启动后进入交互循环，显示 `aiops>` 提示符
- 支持多轮追问（"那哪个进程占用最多？"）
- 输入 `exit` / `quit` / `Ctrl+D` 退出
- 保持对话上下文

**Ctrl+C 行为**：
| 场景 | 行为 |
|------|------|
| `aiops>` 提示符下 | 清空当前输入，不退出 |
| 工具执行过程中 | 终止子进程，返回对话（不退出） |
| 安全确认提示时 | 取消当前命令（不退出） |
| 连续按两次 Ctrl+C | 退出程序 |

#### 8.2 对话上下文管理

DeepSeek API 有 context window 限制。多轮对话中工具输出会快速消耗上下文空间。应对策略：

- 工具输出超过 5000 字符时自动截断（保留尾部，重要信息常在末尾）
- `check_log` 输出截取尾部（最新日志更有价值）
- 对话历史超过阈值时，采用**滑动窗口**：丢弃最早 N 轮的工具输出，只保留用户提问和 AI 结论
- `max_turns` 限制单次任务的循环次数，间接控制上下文增长

滑动窗口是默认策略（零成本、零延迟）。如果需要更智能的上下文压缩，可配置调用一次小模型做摘要，但会增加成本和延迟。

#### 8.3 API 异常处理

| 异常 | 处理 |
|------|------|
| 429 Rate Limit | 指数退避重试（最多 3 次），超过后告知用户稍后重试 |
| 500 Server Error | 重试 1 次，失败后告知用户 API 服务异常 |
| 超时 | 重试 1 次，失败后告知用户网络问题 |
| API Key 无效 | 提示用户检查 config.json 中的 api_key |
| 网络不可达 | 提示用户检查网络连接和 base_url 配置 |

#### 8.4 命令执行结果处理

- 输出超过 5000 字符时截断，但保留尾部（重要信息常在末尾）
- 执行超时（30s）后终止进程，返回已有的 stdout/stderr
- 退出码非 0 时记录为 WARN 级别日志
- AI 根据退出码和输出内容判断成功/失败，给出分析

#### 8.5 单次模式与退出码

```bash
# 单次模式
ai "查看磁盘占用"
# 退出码：0 = AI 正常完成任务，1 = AI 执行过程中出错

# 可用于管道脚本
ai "检查 nginx 服务状态" && deploy.sh
```

退出码语义：反映 AI 是否正常工作，而非运维状态。
- 0：AI 正常完成任务（无论结论是"nginx 正常"还是"nginx 已停止"，都是成功执行）
- 1：AI 执行异常（API 调用失败、工具超时、安全层拦截等）

脚本集成时，关注的是"AI 有没有正常工作"，而非"服务器状态如何"。

#### 8.6 交互式命令处理

以下命令需要交互式终端，`execute_command` 会拒绝执行并提示用户手动操作：

```
vim, vi, nano, top, htop, less, more, man, ssh, mysql, psql,
redis-cli, python (REPL), bash (交互模式), apt (交互模式)
```

检测方式：命令首字词匹配交互式命令列表。

#### 8.7 命令注入防护

用户输入可能被 AI 不经转义地拼进命令参数。例如用户说"查一下 google.com; rm -rf /"，AI 可能拼成 `ping google.com; rm -rf /`。

防护策略（三层防线）：

1. **系统提示词**：指导 AI 对用户输入的动态参数使用 `shlex.quote()` 转义，从源头减少注入可能
2. **安全层模式匹配**：对完整命令字符串做危险模式检测（已有），这是核心防线
3. **不做过滤**：`;`、`|`、`&&` 等是合法 shell 语法，`ps aux | grep nginx` 是正常用法，不能因为有注入风险就禁止这些字符

安全层是最终防线，不依赖 AI 行为的正确性。

### 9. 命令历史与对话持久化

#### 9.1 命令历史

- 每次成功执行的命令记录到内存中的历史列表
- 用户输入 `!!` 重复执行上一条命令
- 用户输入 `!n`（如 `!3`）执行历史中第 n 条命令
- 用户输入 `history` 显示最近 20 条命令历史
- 退出时历史写入 `~/.aiops/aiops_history`，下次启动时加载

#### 9.2 对话持久化

- 退出时自动将完整对话保存到 `~/.aiops/conversations/<session_id>.jsonl`
- 每个会话文件首行为 meta 头（id、标题、创建/更新时间、消息数）
- `ai -c` 自动恢复最近一次对话
- `ai -r` 列出最近 20 个历史对话，用户选择恢复

### 10. CLI 接口

```bash
# 持续对话模式（直接运行）
ai
# 进入 aiops> 交互界面

# 单次模式（执行后退出，返回退出码）
ai 查看磁盘占用
ai -C "查看磁盘占用"          # 显式 -C 标志

# 命令行参数
ai --help                      # 帮助信息
ai --version                   # 版本号
ai --config /path/config.json  # 指定配置文件
ai --no-color                  # 禁用颜色输出
```

使用 `argparse` 实现。位置参数（无 `-c` 时）自动识别为单次模式。

### 11. 配置文件 config.json

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

api_key 也支持环境变量 `DEEPSEEK_API_KEY`，优先级高于 config.json 中的值。

**安全提醒**：config.json 包含明文 API Key，setup.sh 创建全局配置时应设置 `chmod 600`。用户级配置继承全局配置，可只覆盖部分字段。

### 12. setup.sh 安装脚本

- 安装 Python 依赖（pip install）
- 创建 `/usr/local/bin/ai` 软链接指向 `aiops.py`
- 检测 Python 版本兼容性
- 首次运行时提示配置 API Key（写入全局 config.json 或设置环境变量 `DEEPSEEK_API_KEY`）
- 全局 config.json 设置 `chmod 600`
- 用户首次运行时自动创建 `~/.aiops/` 目录结构

## 验证场景

```bash
ai 帮我查看磁盘占用情况          # 应调用 check_disk
ai 哪个进程占用内存最多           # 应调用 check_process
ai 帮我看下 8080 端口是否被占用   # 应调用 check_port
ai nginx 服务状态怎么样           # 应调用 check_service
ai 帮我看下系统日志有没有报错     # 应调用 check_log
ai 帮我 ping 一下 google.com     # 应调用 network_check
ai 帮我看下 nginx 配置文件       # 应调用 read_file
ai 帮我重启 nginx 服务           # 应调用 execute_command + 中风险确认（可修改）
ai 帮我清理 /tmp 下 7 天前的文件  # 应调用 execute_command，风险为 safe（/tmp 下操作）
ai 帮我格式化 /dev/sdb           # 应被安全层拦截（blocked）
ai 帮我看下 /etc/shadow          # 应被 read_file 路径审查拒绝
ai 帮我 rm -rf /etc              # 应被安全层拦截（高风险 + 系统路径）
```
