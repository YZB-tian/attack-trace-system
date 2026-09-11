# 内存注入检测验证（Windows，2026-09-10）

本文件记录在 Windows Server 2025 核心服务器（06-WindowsServer-Core /
`coreserver01`，192.168.80.60）上安装 Sysmon、执行受控进程内存注入并验证检测的实验。
目的是补齐「内存行为分析：检测进程内存中的异常代码注入」的要求。

## 1. 监控与实验

| 环节 | 做法 |
| --- | --- |
| 遥测 | 在目标机安装 Sysmon 15.22，配置启用 ProcessCreate、CreateRemoteThread，并对 `notepad.exe` 启用 ProcessAccess |
| 注入 | PowerShell 通过 P/Invoke 调用 `OpenProcess`(0x1F0FFF) → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`，写入的只是 `31 C0 C3`（`xor eax,eax; ret`）三字节返回桩，不会执行有害载荷 |
| 证据 | Sysmon 事件 1/8/10 导出为 JSON，随实验包归档 |

## 2. 观测结果

| 记录 | 内容 |
| --- | --- |
| Sysmon 10（ProcessAccess） | `powershell.exe` → `notepad.exe`，`GrantedAccess 0x1f3fff`，18:41:35.860Z |
| Sysmon 8（CreateRemoteThread） | `powershell.exe` → `notepad.exe`，新线程 4340，18:41:35.890Z |
| 对照（同一窗口） | Windows Defender `MsMpEng.exe` 对同一进程多次访问，权限为 `0x1000/0x1410`（只读类），未被规则命中 |

导入后该任务产生 1 条告警：

| 规则 | ATT&CK | 事件数 | 置信度 |
| --- | --- | ---: | ---: |
| `HOST-WIN-PROCESS-INJECTION` | T1055（tactic: stealth） | 1 个 CreateRemoteThread + 同源 ProcessAccess 证据 | 0.85 |

```powershell
python scripts/import_memory_injection.py --evidence-dir D:\AttackTraceLab\evidence\memory-injection-20260910T184200Z --output runtime/memory-injection --task-id task_memory-injection-20260910T184200Z --run-id memory-injection-20260910T184200Z --stix runtime/stix/enterprise-attack.json
```

## 3. 限制

1. 受靶场防火墙策略限制（服务器区只允许办公区访问 TCP445），无法从 Kali 或办公区
   真正远程投递载荷，本次注入由实验人员在目标机上以受控方式执行；**不构成远程入侵**。
2. 规则要求「远程线程创建」，并按同源 ProcessAccess 补充证据；调试器、EDR、
   无障碍工具也会创建远程线程，告警文本已注明需要人工复核。
3. Sysmon 是在实验前新装并配置的，配置只覆盖 `notepad.exe` 的 ProcessAccess，
   因此本实验的 ProcessAccess 记录不是全量数据。
4. 未做反射式 DLL 加载（reflective loading）与代码注入后的行为分析；把注入桩换成
   真实载荷属于后续实验。
5. 同一套规则在公开数据集上的表现见 `docs/public-dataset-validation.md`：加入
   `csrss.exe`/`dwm.exe` 源进程白名单后，T1055 候选从 22 条降到 1 条；此前的高候选数
   说明单独依赖 CreateRemoteThread 的精确率有限，白名单是必需的。
