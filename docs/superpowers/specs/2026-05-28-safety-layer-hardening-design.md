# 安全层加固 — 设计文档

- 日期：2026-05-28
- 方向：加固 + 测试 `safety.py`（项目下一阶段第一项）
- 威胁模型：分层 —— 本阶段把正则护栏做扎实并补齐测试，对抗性绕过向量登记留作下一阶段架构升级的依据

## Context

AiOps 的核心卖点是"敢让 AI 执行 shell 命令"，其信任基础是 `safety.py` 安全审查层。但当前该层是纯正则规则，存在若干真实结构性漏洞，且零测试覆盖——改动任意一条正则都没有回归保障。本阶段在不改变工具层接口的前提下，重构 `review_command` 为命令分解式审查、补齐文件路径与跨工具防护、建立 pytest 测试套件，并记录延后处理的对抗性绕过向量。

## 当前已识别漏洞

1. **复合命令不拆分**：`review_command` 对整串做 `pattern.search`。BLOCKED 规则 `rm\s+(-[a-zA-Z]*[rf]){1,2}\s+/\s*$` 要求 `/` 在行尾，因此 `rm -rf / ; echo done` 被判为 SAFE 放行。
2. **跨工具绕过路径审查**：文件保护仅在 `read_file`，但 `execute_command("cat /etc/shadow")` 的 `review_command` 不检查路径，直接放行。
3. **交互式检测只看首词**：`shlex.split(stripped)[0]`，导致 `sudo vim`、`echo x; vim` 漏过。
4. **`.ssh` 仅覆盖 `~/` 和 `/root/`**：`/home/alice/.ssh/id_rsa` 不在 DENY 名单。
5. **shlex.quote 空头支票**：系统提示词承诺"对动态参数用 shlex.quote 转义"，但工具层未实现，且对 `execute_command` 这种整串命令本就难以强制。

## 范围

**改：**
- `safety.py` 内部逻辑（保持公共函数签名与返回类型不变）
- 新增 `tests/test_safety.py`
- 新增测试基建：`requirements-dev.txt`、`pytest.ini`
- 新增 `docs/security/known-bypasses.md`（已知绕过登记表）
- 修正 `agent.py` 系统提示词中关于 shlex.quote 的不实表述

**不改：**
- 工具接口：`review_command(command) -> SafetyResult`、`review_file_path(path) -> FileReview` 的签名与返回类型保持不变，`tools.py` 几乎零改动
- `logger.py`、`aiops.py` CLI、agent 的整体逻辑

**非目标（记入登记表，留作下一阶段）：**
- 沙箱 / 容器隔离
- 二进制白名单
- bash AST 解析
- 对抗性混淆识别（`r""m`、`\rm`、`$()`、base64、eval 等）

## 架构设计

### 组件与隔离边界

`safety.py` 对外仍只暴露两个纯函数：`review_command` 与 `review_file_path`。本次重构全部发生在模块内部，新增私有辅助函数，互不耦合、可独立测试：

| 函数 | 职责 | 依赖 |
|---|---|---|
| `_split_compound(cmd) -> list[str]` | 用 `shlex`（`punctuation_chars=True`）按 `;`、`&&`、`||`、`|`、换行拆分复合命令，尊重引号 | 仅 shlex |
| `_strip_prefix(sub) -> str` | 剥离子命令开头的 `sudo`、`env VAR=x` 包装 | 无 |
| `_review_one(sub) -> SafetyResult` | 对单个子命令执行现有的「交互→blocked→high→medium→safe」分级逻辑 + 文件读取器路径检查 | `review_file_path` |
| `_max_risk(results) -> SafetyResult` | 聚合多个子命令结果，取最高风险，合并 message | 无 |

### review_command 数据流

```
review_command(cmd):
  if cmd 为空: return SAFE
  try:
      subcmds = _split_compound(cmd)
  except ValueError:                      # 引号不配对等解析失败
      return SafetyResult(HIGH, "命令解析失败，无法完整审查", require_confirm=True)
  results = [_review_one(_strip_prefix(s)) for s in subcmds]
  return _max_risk(results)               # 任一段 BLOCKED → 整体 BLOCKED
```

风险排序（取最高）：`BLOCKED > HIGH > MEDIUM > LOW > SAFE`。
`require_confirm` 取所有子结果的「或」（任一段需确认则整体需确认），但 BLOCKED 不需确认（直接拦截）。

### _review_one 内的文件读取器检查

在现有分级逻辑基础上新增：若子命令首词（剥离 prefix 后）属于文件读取器集合
`{cat, less, more, head, tail, nl, od, xxd, strings, tac, view}`，
则对其每个非选项参数（不以 `-` 开头的 token）调用 `review_file_path`：
- 命中 DENY → 升级为 BLOCKED（与 `read_file` 的 DENY 拦截行为一致）
- 命中 WARN → require_confirm

**这是启发式防护**，明确不覆盖 `dd if=/etc/shadow`、`python -c "open(...)"`、重定向读取等——记入登记表。

### review_file_path 加固

- `.ssh` DENY 覆盖扩展为：`~/.ssh/`、`/root/.ssh/`、`/home/*/.ssh/`
- 匹配前先 normalize 路径，解析 `..`（使用 `os.path.normpath`，不解析符号链接以避免触发文件系统访问）
- 其余 DENY / WARN 规则保持不变

## 错误处理 / fail-safe

- **tokenize 失败**（`shlex` 抛 `ValueError`，如引号不配对）→ 不放行，返回 `HIGH + require_confirm`，message "命令解析失败，无法完整审查"
- **空命令** → SAFE（保持现状）
- 原则：审查层遇到无法理解的输入时，向「更安全」一侧倾斜（require_confirm），绝不静默放行、绝不崩溃

## 测试

`tests/test_safety.py`，pytest 参数化，覆盖：

- **规则矩阵**：BLOCKED / HIGH / MEDIUM / SAFE 各类代表命令
- **计划验证场景**：`docs/plan/AiOps-Plan.md` 末尾的 13 个场景对应的预期风险等级
- **新增结构性用例**：
  - 复合命令逐段审查（`rm -rf / ; echo done` → BLOCKED；`ls && systemctl restart nginx` → MEDIUM）
  - 跨工具路径（`cat /etc/shadow` → BLOCKED；`cat ~/.ssh/id_rsa` → BLOCKED）
  - 交互式（`vim`、`top`、`sudo vim`、`echo x; vim` → BLOCKED）
  - 解析失败（引号不配对 → HIGH + require_confirm）
- **文件路径三级**：DENY（`~/.ssh/id_rsa`、`/root/.ssh/`、`/home/alice/.ssh/`、`/etc/shadow`、含 private/secret/credential）、WARN（`*.pem`、`*.key`、`.bash_history`）、ALLOW（普通路径）
- **rm 安全目标**：`/tmp/x`、`./x`、`~/x`、相对路径 → 不拦截

**实现顺序（TDD）**：先按目标行为写测试（现有代码会在新漏洞上失败），再重构 `safety.py` 直至全绿。

## 测试基建

- `requirements-dev.txt`：`pytest`
- `pytest.ini`：`[pytest]` 段设 `testpaths = tests`
- 沿用项目「pip、无 pyproject」风格，不引入 pyproject.toml

## 已知绕过登记表

`docs/security/known-bypasses.md`，逐条记录延后的对抗性向量。每条含：向量描述、为何正则/启发式抓不住、下一阶段建议缓解。初始条目：

| 向量 | 为何抓不住 | 下阶段建议缓解 |
|---|---|---|
| 正则混淆 `r""m -rf /`、`\rm`、`"rm" -rf /` | 正则按字面匹配 `rm`，引号/转义破坏字面 | tokenize 后取解析出的实际可执行名 |
| 变量/命令替换 `$(echo rm) -rf /`、`$X /` | 替换在 bash 运行时发生，审查时不可见 | 受限执行环境 / 禁用替换 / 解析展开 |
| 编码绕过 `echo cm0gLXJmIC8=｜base64 -d｜bash` | 解码在运行时发生 | 二进制白名单 + 禁止管道入 shell |
| 文件读取器启发式盲区 `dd if=/etc/shadow`、`python -c "open(...)"`、`< /etc/shadow` | 不在读取器集合 / 重定向不经命令名 | 受限执行环境 + 路径级 LSM/权限 |
| 符号链接指向敏感文件后读取 | 路径匹配不解析符号链接 | 运行时按真实 inode 鉴权 / 降权执行 |

## 实施步骤概览

1. 建测试基建（`requirements-dev.txt`、`pytest.ini`）
2. 写 `tests/test_safety.py`（TDD，对目标行为，先红）
3. 重构 `safety.py`：`_split_compound` / `_strip_prefix` / `_review_one` / `_max_risk` + 文件读取器检查 + `review_file_path` 加固 + 解析失败 fail-safe
4. 跑测试至全绿
5. 写 `docs/security/known-bypasses.md`
6. 修正 `agent.py` 提示词中 shlex.quote 表述
