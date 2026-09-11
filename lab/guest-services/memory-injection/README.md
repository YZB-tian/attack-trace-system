# Windows memory-injection experiment scripts

在 Windows Server 2025 核心服务器（192.168.80.60）上验证内存注入检测。

| 脚本 | 作用 |
| --- | --- |
| `40-check-sysmon.ps1` | 检查 Sysmon、审计策略、WinRM、Defender 状态 |
| `41-sysmon-config.xml` | Sysmon 配置：ProcessCreate、CreateRemoteThread、notepad 的 ProcessAccess |
| `42-install-sysmon.ps1` | 静默安装 Sysmon 并确认服务与日志 |
| `43-inject.ps1` | 受控注入：OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread，写入的只是 3 字节返回桩 |
| `44-collect-sysmon.ps1` | 导出 Sysmon 与 Security 事件为 JSON |

客户机账号：`Administrator` / `__LAB_PASSWORD__`。结果与限制见
`docs/memory-injection-verification.md`。
