# 公开数据验证与本轮修改报告

日期：2026-09-09。分支：`feature/network-correlation`。公共接口修改：**否**。未提交、未推送。

版本说明：以下是本次公开数据实测时的记录。随后 HTTP/ICMP 功能补充与 85 项测试的结果另见 HTTP_ICMP_HANDOFF.md；新增采集脚本未在本机 Zeek 执行，不把后续合成样例计入本报告的真实日志数量。

## 结论

本轮完整解析 **831,970 条**公开/上游日志，对其中 **62,359 条**运行完整的标准化、检测、图关联、TraceResult 和 JSON Schema 校验。修复了日志格式兼容、正常 NTP 误报、短十六进制 DNS 查询漏报，以及高重复流量下不必要的事件比较。

**当前仍不能宣称通用 C&C 检测合格。** 两份 IoT-23 的 C&C 标签覆盖率都为 0；本轮 DNS 改进在用于发现问题的同一上游样本验证，尚无独立真实 DNS 留出集效果证明。零误报同时伴随零 C&C 检出，不能用总体准确率掩盖这一点。

## 数据来源与选择范围

1. [IoT-23 官方说明](https://www.stratosphereips.org/datasets-iot23)：直接下载场景 CTU-IoT-Malware-Capture-34-1（Mirai）和 CTU-IoT-Malware-Capture-8-1（Hakai）的官方 `bro/conn.log.labeled`。两份文件全部用于验证，包含 4,104 条正常标签连接。未下载或运行恶意二进制。
2. [RITA 上游测试日志](https://github.com/activecm/rita/tree/1317d70ce00319782c0983c7d9033b9290e58e95/test_data/dnscat2-ja3-strobe-agent)：从用户已下载的本地 Git 对象库提取固定提交中的 conn/dns/http 三个 gzip 文件，随后只解压日志。GitHub 原始文件下载遇到 Windows 吊销检查服务离线，未关闭 TLS 校验；因此这部分是本地上游文件复用，不冒称本轮重新联网下载。
3. RITA 三份日志**全部解析**：conn 455,536、dns 315,682、http 27,204 条。完整流水线使用固定第一小时 `[1517336042.090842, 1517339642.090842)`，起点为 conn 首条记录，选择不依赖告警结果或标签。选中 conn 16,458、dns 10,892、http 1,461，共 28,811 条；**没有对其余时段运行检测与图关联**。
4. RITA 数据是上游集成测试素材，包含导出/Agent 标记，缺少独立逐流真值。其结果只用于格式兼容和行为检测冒烟验证，不等同标准公开评测集，也不计算准确率或召回率。
5. CIC DNS-EXF 下载入口需要个人信息登记；独立 Somfy 正常场景目录的直链/握手未成功。本轮未提交个人信息，未使用这些数据，正常对照来自上述 IoT-23 自带 Benign 标签。

IoT-23 标签只由评估脚本读取，并在标准化前移除；其中一个版本把末尾标签用三个空格而非制表符分隔，已通过专门转换处理。原始文件保持原样，派生输入位于各场景 `clean/`。原始行号在转换前后保持一致。所有数据集 IP 未擅自登记为靶场资产，未知 host_id 保持 null。

## 检测结果

| 样本 | 输入范围 | 修改前 | 修改后 |
|---|---|---|---|
| IoT-23 Mirai 34-1 | 全部 23,145 条连接 | 4 个 Beacon 候选，覆盖 111 条正常连接 | 0 个候选，正常连接误报覆盖 0 |
| IoT-23 Hakai 8-1 | 全部 10,403 条连接 | 51 个 Beacon 候选，覆盖 1,372 条正常连接 | 0 个候选，正常连接误报覆盖 0 |
| RITA 固定第一小时 | 28,811 条 conn/dns/http 事件 | 原始解析器三份文件均在第 9 行报错；修复解析后旧检测规则输出 0 | 2 个 DNS 可疑通信窗口，覆盖 3,252 条 `dnsc.r-1x.com` 查询 |

IoT 指标以**去重告警证据中的连接**为单位，而非告警窗口或主机。C&C 为正类、Benign 为负类；Mirai 的 14,394 条 DDoS 和 122 条扫描不混入该二分类分母。一般 C&C 标签不保证流量具有 Beacon 周期特征。

- Mirai：正常标签 1,923；误报覆盖率从 111/1,923 = **5.77%** 变为 0；C&C 共 6,706 条，前后均 0 条覆盖。
- Hakai：正常标签 2,181；误报覆盖率从 1,372/2,181 = **62.91%** 变为 0；C&C 共 8,222 条，前后均 0 条覆盖。
- 修改后没有预测正类，precision 记录为 null（无定义），不是 100%。两场景的 C&C recall 均为 0。
- 旧规则对照通过关闭本轮新增的 NTP 过滤和短十六进制 DNS 条件复现；标签仍不进入检测器。场景用于回顾式配对比较，不宣称严格盲测。

漏报检查：Hakai 8,222 条 C&C 全为 S0，应用层发送字节为 0 或缺失；Mirai 6,706 条包含 5,065 条 S0，另有 1,641 条带 IRC service 的连接。当前规则要求非零稳定请求大小、持续的周期性，不能覆盖所有失败重试、IRC 通信或抖动 C2。不能仅凭这些目标 IP 或端口写死告警以提高样本分数。详情保存于 `output/public_validation/c2_miss_analysis.json`。

RITA 告警通过官方 STIX 映射到 T1071.004。其图输出 34,426 个节点、86,143 条边，主候选链只有 1 个有证据阶段；初始入侵点为 null。两份 IoT 图也没有凭空补出入侵点。网络流量中不存在主机提权/认证证据，因此本轮不能验证完整企业攻击链或 APT 归因。

## 本轮逐文件改动

| 文件 | 本轮改动 |
|---|---|
| collectors/network/adapter.py | 兼容字面量 `\\t` 分隔符与单个空行尾字段；每个文件只解析一次绝对路径，保留来源行号 |
| collectors/network/README.md | 说明格式兼容和数据集标签转换边界 |
| detection/network_rules.py | 新增可关闭的窄 NTP 形态过滤；新增短十六进制 TXT 的持续量、唯一性、后缀集中度组合条件，不包含样本域名/IP |
| detection/README.md | 记录新条件、配置开关、误报与漏报边界 |
| correlation/service.py | 按实际证据字段建立候选索引；五元组只查询涉及进程的候选，保留 30 秒限制，再执行原来的证据判定 |
| correlation/validate_public_data.py | 新增可复现评估入口、标签隔离、来源/SHA-256、修复前后指标、四类输出的 Schema 和引用校验 |
| correlation/pipeline.py | 更新完成提示，避免仍笼统声称未做公开数据验证 |
| tests/test_network_correlation.py | 新增 5 项测试：RITA 格式、IoT 标签隔离、NTP 过滤边界、短 DNS 正反例、索引与穷举关联结果一致 |
| correlation/README.md | 补评估入口和索引说明 |
| correlation/VALIDATION.md | 更新测试数量与待完成范围 |
| correlation/IMPLEMENTATION_REVIEW.md | 更新早期清单中的公开数据验证状态，保留仍缺的全组验收项 |
| correlation/PUBLIC_DATA_VALIDATION.md | 本报告 |

这是相对本次“下载数据集验证”请求的修改清单。之前的网络适配器、STIX、Sigma、demo、攻击图/路径第一版仍在当前功能分支中，已有清单见 IMPLEMENTATION_REVIEW.md。其他组员目录和禁止修改的公共对象均未改。

## 验证与性能

- **69 passed**。默认 pytest 临时目录出现 WinError 5；改用模块 output 下的新临时目录并关闭 pytest 缓存后全部通过。未改系统目录权限。
- `scripts/validate_contracts.py` 全部通过。
- 新生成 62,359 个 NormalizedEvent、2 个 Alert、3 个 AttackGraph、3 个 TraceResult 全部通过不可变公共 Schema + FormatChecker；图端点和证据引用均存在。
- `git diff --check` 通过；schemas、公共 models/enums、资产配置、前端公共类型/API 和其他组员目录无差异。
- Mirai 场景在候选索引进一步收紧前端到端约 369.8 秒，收紧后约 **19.9 秒**（包含检测、图、校验及写文件）；Hakai 约 9.7 秒。不是单独检测耗时或严格基准测试。前后 Mirai 节点 23,194、边 46,290 一致，另有索引对比穷举的行为回归测试。密集同进程/同会话图仍可能很大。

## 复现与产物

在项目根目录运行（当前机器数据和解压文件均已准备好）：

```powershell
.\.venv\Scripts\python.exe -u -m correlation.validate_public_data --stix ../security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json
.\.venv\Scripts\python.exe scripts/validate_contracts.py
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=correlation/output/pytest-public-validation-new
```

换机器时，先创建 `correlation/output/public_validation/iot34`、`iot8`、`rita` 三个目录，从以下路径取原文件，核对下表 SHA-256；RITA 三个 gzip 以 Python `gzip` 解压成同目录 conn.log/dns.log/http.log。无需 Zeek 才能读这些发布方生成的日志。

- IoT 前缀：`https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`，后接对应 `CTU-IoT-Malware-Capture-{34或8}-1/bro/conn.log.labeled`，分别保存到 iot34/iot8。
- RITA 源位置为上述固定提交链接中的三个 gzip；本机提取方式为 Python `subprocess.check_output(['git', '-C', '../security-trace-projects/rita', 'show', '<固定提交>:test_data/dnscat2-ja3-strobe-agent/<文件>'])`，使用 `Path.write_bytes` 保存，避免 PowerShell 文本重定向损坏二进制。

| 原文件 | 字节 | SHA-256 |
|---|---:|---|
| iot34/conn.log.labeled | 2926718 | d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e |
| iot8/conn.log.labeled | 1431000 | 4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a |
| rita/conn.log.gz | 17428246 | e51c4fb337d70ca0a6983387e83e6d81e229d89bcb36df659562030ba6604c5b |
| rita/dns.log.gz | 15646353 | 426c1afb18289038171fc54f4eea4dab9dfead5c505b6cd0b353b72627655640 |
| rita/http.log.gz | 2287964 | 62f2d0209c47e60be66125f1ce1760f6ee05f1693bc34c43a22936df58e85aad |

STIX SHA-256：`c0c463e0c303f62bd7442a80c8ee2f9ea5f19c8268c50f9dcfd36d78a8d18985`；内容更新可能影响技术映射，复现时应保留输入版本。

机器可读报告：`correlation/output/public_validation/report.json`。三个场景的 `result/` 各有 normalized_events.json、alerts.json、attack_graph.json、trace_result.json。原文件、派生输入、机器报告均位于模块忽略的 output 中，**不会随普通 git 提交上传数据集**；本报告与评估脚本可交付组员。评估输入是 Zeek 日志及官方 STIX，跨模块输出仍仅使用公共四类对象，指标报告为模块内部评估产物。

## 当前可以交付与还缺什么

可交付：本模块离线程序、合成多源示例、真实公开网络日志验证记录、可复现脚本和接口通过证据。

尚缺：独立真实 DNS 留出样本、HTTP/ICMP 隐蔽通信真实正例、覆盖失败重试/IRC/抖动的更广 C2 分析、主机认证与行为的多源关联效果；课程的八节点靶场、后端/前端接入、真实多 Agent 与现场演示仍需全组联调。不能用本报告替代这些验收项。
