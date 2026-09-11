# 公开企业内网攻击数据集验证：APT29 Evals Day 1（2026-09-10）

课程要求「收集互联网中企业内网攻击行为数据集，针对数据集环境开展恶意攻击行为
溯源分析」。本文件记录用**公开企业内网数据集**对本项目默认主机规则的独立验证。

## 1. 数据来源与合规

| 项 | 内容 |
| --- | --- |
| 数据集 | OTRF Security-Datasets / Mordor，`datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` |
| 场景 | MITRE Evaluations 2020 的 APT29 仿真，Windows 域环境（`UTICA.dmevals.local` 等主机，WEF 汇聚） |
| 内容 | 196,081 条 JSONL：Sysmon（164,435）、Security、PowerShell 操作日志等 |
| 许可 | 仓库为公开研究数据集（Detection Hackathon）；本项目只在本地 `runtime/datasets/` 使用，未提交到 Git |
| 访问 | `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` |

同时保留此前已验证的两份 IoT-23 与 RITA 上游日志结论（见
`correlation/PUBLIC_DATA_VALIDATION.md`）。本次新增的是**企业内网域环境**数据。

## 2. 验证方法

`scripts/validate_public_apt29.py` 只把 Sysmon 的 ProcessCreate(1)、
CreateRemoteThread(8)、ProcessAccess(10) 转成公共 `NormalizedEvent`，交给
`detection.host_rules.detect_host`，**不使用数据集标签作为输入**。

| 统计 | 值 |
| --- | ---: |
| 读取记录 | 196,081 |
| 转换事件（ID 1 / 8 / 10） | 39,831（450 / 95 / 39,286） |
| 运行时间 | 约 4 秒（单进程，含 53 MB STIX 加载） |

## 3. 结果

| 规则 | ATT&CK | 告警数 |
| --- | --- | ---: |
| `HOST-WIN-PROCESS-INJECTION` | T1055 | 1 |
| `HOST-WIN-LOLBIN-EXECUTION` | T1218 | 5 |
| `HOST-WIN-LSASS-MEMORY-ACCESS` | T1003.001 | 2 |
| 合计 | | **8** |

仿真计划（`emulationplans/apt29.xlsx`，day1）记录了 **44 个技术名称**。对照关系：

- `Credential Dumping` 在计划中，`HOST-WIN-LSASS-MEMORY-ACCESS` 命中 2 次，方向一致。
  该规则带进程白名单（lsass/csrss/services/svchost/Defender 等），未加白名单时是 4 条，
  说明白名单显著影响精确率。
- `Process Injection` **不在** day1 计划中。首轮该规则产生 22 条候选，逐条核对后
  20 条是 `csrss.exe → <新进程>`、1 条是 `dwm.exe → csrss.exe`——这是 Windows 创建
  进程/窗口时的正常行为，也是 CreateRemoteThread 规则最常见的误报来源。加入
  `csrss.exe`、`dwm.exe` 源进程白名单后降到 **1 条**，剩下的正是
  `powershell.exe → lsass.exe`，与 `Credential Dumping` 计划一致，同时被
  `HOST-WIN-LSASS-MEMORY-ACCESS` 命中，两条规则相互印证。
- `System Binary Proxy Execution` 也不在计划中，规则仍产生 5 条候选；计划里有
  `Remote File Copy` 与 `Obfuscated Files or Information`，用 `certutil` 下载载荷
  属于这类行为，因此这 5 条**可能是真阳性**，但没有逐事件标签无法确认。
- `PowerShell` 在计划中，但默认的 `HOST-WIN-POWERSHELL-ENCODED` 规则未命中，
  说明攻击者未使用 `-enc/EncodedCommand`，属于**规则覆盖缺口**。

## 4. 复现

```powershell
# 下载（约 14 MB 压缩包，解压后 385 MB）
curl.exe -sL -o runtime/datasets/apt29_evals_day1_manual.zip https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip
Expand-Archive -LiteralPath runtime/datasets/apt29_evals_day1_manual.zip -DestinationPath runtime/datasets/apt29_day1 -Force
python scripts/validate_public_apt29.py --output runtime/public-apt29 --stix runtime/stix/enterprise-attack.json
```

## 5. 限制

1. 只有主机侧记录被转换；该数据集同日的网络 PCAP（SCRANTON/NASHUA）未纳入本轮验证，
   网络规则在企业数据上的独立验证仍待补。
2. 数据集没有逐事件标签，本文件用仿真计划的**技术清单**做方向性对照，
   不能据此计算精确的准确率/召回率。
3. Windows 日志的 UID/账户未映射到本地资产表，事件 `host_id` 为 `null`，
   `metadata.dataset_host` 保留原始主机名；这不影响主机规则的判定。
4. 数据集规模与形态与自建靶场差异较大，结论不能直接外推到真实企业网络。
