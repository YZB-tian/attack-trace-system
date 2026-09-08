# Linux 日志模块（collectors/linux）

把 Linux 主机日志（auth.log/syslog 与 auditd）原始文本行归一为公共模型 `NormalizedEvent`。

**跨模块输出只能是 `NormalizedEvent`**（`source_type="host_log"`、`source="auth.log"` 或 `"auditd"`）。

## 覆盖需求点

| 需求 | 实现 |
|---|---|
| 时间序列对齐 | syslog 无年份/无时区时间戳补全为带时区 ISO 8601（含跨年回退）；auditd epoch 时间戳转带时区 ISO 8601；支持 per-host `clock_offset` 修正 |
| 日志范式解析 | 兼容 RFC3164、RFC5424（均含 `<PRI>` 前缀）、完整 ISO、auditd `type=... msg=audit(epoch.ms:seq): ...`（含 `node=` 前缀）四种头部 |
| 关键信息提取 | 用户（`user`）、进程（`process.pid/ppid/name/path`）、文件/命令（`object`，含 EXECVE 命令行）、源 IP/端口（`src_ip/src_port`） |
| 登录会话重建 | login/logout 事件在 `metadata.session_id` 携带会话标识，供下游 correlation 重建；配对能力在 `tests/test_linux.py` 中验证 |

## 输入

```python
from collectors.linux import normalize_linux_records

events = normalize_linux_records(
    records,            # Iterable[Dict]：每条 {"raw": "<原始行>"} 或纯字符串
    task_id="task_demo_001",
    clock_offset=None,  # 可选 {hostname: 偏移秒数}
    tz_offset_hours=8,  # 默认 +08:00
    year=None,          # 默认当前年份（仅 auth.log 用）
    default_host=None,  # auditd 本地行不含主机名时的默认 hostname
)
```

`records` 示例（按行首自动识别来源：`type=` 或 `node=... type=` 开头走 auditd，否则走 auth.log；`<PRI>` 前缀自动剥离）：

```python
[
    {"raw": "Sep  8 10:00:00 webserver01 sshd[1234]: Accepted password for root from 10.10.0.10 port 52000 ssh2"},
    {"raw": "type=SYSCALL msg=audit(1609459201.123:459): ... syscall=59 ... exe=\"/usr/bin/whoami\"", "host": "webserver01"},
]
```

## 输出

`list[NormalizedEvent]`，`host_id` 统一从 `config/assets.json` 反查（未命中为 `null`，原始 hostname 进 `metadata.raw_hostname`）。

私有 action 动词映射（供下游 detection 使用）：

| auth.log 事件 | action |
|---|---|
| `Accepted password/publickey for X` | `login_success` |
| `Failed password/publickey/keyboard-interactive for X` | `login_failure` |
| `sudo: ... COMMAND=...` | `sudo_exec` |
| `su: (to root) X` | `user_switch` |
| `session opened for user X` | `session_open` |
| `session closed for user X` | `logout` |
| `Received disconnect from ...` | `disconnect` |
| `Disconnected from user X ...` | `logout` |
| 其他未分类 | `auth_log` |

| auditd 事件类型 | action |
|---|---|
| `USER_AUTH`（`res=success` / 其他） | `login_success` / `login_failure` |
| `USER_LOGIN` | `session_open` |
| `USER_LOGOUT` / `USER_END` | `logout` |
| `SYSCALL`（`syscall=59`=execve / 其他） | `process_exec` / `syscall` |
| `EXECVE` | `command_args` |
| `PATH` | `file_access` |
| `CONFIG_CHANGE` | `config_change` |
| 其他未分类 | `audit_event` |

## 运行与测试

```bash
python scripts/validate_contracts.py   # 契约校验
pytest -q                              # 含 tests/test_linux.py
```

## 登录会话重建

跨模块输出**只有 `NormalizedEvent`**：login/logout 事件已携带会话关联信息
（`user`、`src_ip`、`metadata.session_id`），完整会话时间线/攻击链聚合由
`correlation` 模块负责。会话配对能力在 `tests/test_linux.py` 中作为测试辅助验证。

## 已知限制

1. auth.log 的 syslog 时间戳无年份/无时区：默认按「当前年 + `+08:00`」补齐，并做跨年回退（补出的时间明显晚于当前则回退一年）；跨主机时钟偏差仍需外部提供真实 `clock_offset`。
2. auditd 本地日志行不含主机名：需由 records 的 `host`/`hostname` 字段、`default_host` 或行首 `node=HOST` 前缀提供，否则 `host_id` 为 `null`。
3. auditd 字段里的用户多为数值 UID（`auid`/`id`），未做 UID→用户名映射（需 `/etc/passwd` 或资产字典，属外部数据）；因此 `USER_LOGIN` 的 `session_open` 事件 user 为数值 UID，与 `USER_AUTH`/`USER_END` 的 `acct` 用户名口径不一致，跨事件配对请优先用 `metadata.session_id`（audit 会话 `ses`）。
4. EXECVE 的 argv 拼接为空格分隔的命令行，原始引号分组在拼接中丢失（精确原文见 `raw_event`）。
5. 发行版措辞差异：覆盖 Debian/Ubuntu/RHEL/CentOS 常见格式，不保证覆盖所有变体。
6. 会话配对为启发式（按 user FIFO），且仅在同一批 `records` 内有效，跨批次长会话由 correlation 处理。
7. 真正「统一时钟源」属采集基础设施（NTP），本模块只做解析层时间归一与偏移修正。
