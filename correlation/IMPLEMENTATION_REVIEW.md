# 源码检查与实施范围（2026-09-08）

本次负责网络流量、网络检测、ATT&CK 数据接入和攻击链关联。复用既有公共对象、API 和目录，不修改其他组员采集器、agents、后端、前端。分支：feature/network-correlation。

## 开始时的代码情况

| 要求 | 开始时状态 | 处理方式 |
|---|---|---|
| 统一事件、告警、图、溯源对象 | 已有模型、Schema、Mock，49 项测试通过 | 直接复用；新产物也验证 Schema |
| Windows 标准化 | 已有基础适配器 | 不重复写；需负责人修正 EventID 2/4689 被映射 process_create、22 被映射 network_connect，以及 Windows 路径名在 Linux 下的解析 |
| Linux 和主机行为标准化 | 两个入口都返回空列表 | 其他组员实现，本模块接收其 NormalizedEvent |
| 网络标准化、检测、关联 | 空入口或 NotImplementedError | 本次实现 |
| Agent 指纹、C2、APT、溯源摘要 | 已有确定性实现和手工知识库 | 保留，交付真实图给负责人；本次 STIX 指标作为新的可复用数据来源，不修改其私有实现 |
| 大模型多 Agent | 未发现 LLM 调用和角色协调 | 全组必需项，尚未完成，不把普通函数称为 LLM Agent |
| 后端流水线 | 主要读取 Mock，POST 只存事件 | 由后端负责人调用离线分析入口里的 analyze，公共路径不变 |
| 公开数据集 | 原 darpa_e3_dataset.py 明确为“风格模拟”；后续已验证两份 IoT-23 和 RITA 上游日志 | 实测范围、漏报与待补验证见 PUBLIC_DATA_VALIDATION.md，模拟数据仍不能算真实数据 |
| 八节点靶场 | 仅有八节点资产配置 | 不能计为已搭建、已采集或已验证 |

## 六个参考项目应读的内容

以下路径均相对各第三方项目根目录。没有复制第三方实现或修改第三方工作区。

| 项目 | 已核对的文件/目录 | 使用方式 | 无需研究 |
|---|---|---|---|
| Zeek | scripts/base/protocols/conn/main.zeek、dns/main.zeek、http/main.zeek | 读取 conn.log、dns.log、http.log 的 JSONL 或有头部的 TSV；以 uid 连接会话和应用事务 | C++ 核心、完整 PCAP/协议解析器、编译器和插件系统 |
| RITA | importer/dns.go、analysis/analysis.go、analysis/beacons.go；辅助定位 importer/zeektypes/dns.go | DNS 查询及子域数量、分桶评分；Beacon 时间间隔、MAD、大小与持续性等统计思路。本项目用独立的轻量多特征规则，不宣称算法等价 | ClickHouse 数据库、Docker 系统、全套 UI、完整迁移 |
| SysmonForLinux | outputxml.cpp:FormatSyslogString、sysmonforlinux.c:processProcessCreate/processFileDelete、test/linuxRules.cpp | XML 中 System/EventID、Computer、EventData/Data 的字段；ProcessGuid、PID、父进程、Image、用户、文件和网络关系供采集负责人参考 | eBPF、内核模块、驱动、安装器、性能测试 |
| Sigma | rules/windows/process_creation/、rules/windows/network_connection/、rules/windows/file/、rules/linux/process_creation/；实读 proc_creation_win_certutil_download.yml | 显式选择少数规则，读取 id/title/level/logsource/detection/tags；attack.tNNNN(.NNN) 查 STIX | 全仓转换、云和身份平台等无关规则 |
| ATT&CK STIX | enterprise-attack/enterprise-attack.json，README.md/USAGE.md 作索引 | attack-pattern=技术；intrusion-set=组织；tool/malware=软件；relationship 用 uses/subtechnique-of 连接。它们在同一 bundle，不是各自独立文件 | mobile、ics 以及全部历史版本 |
| GraphHunter | core/graph-engine/src/entity.rs、relation.rs、graph.rs:search_temporal_pattern；platform/canonical/src/project/mod.rs | 参考事件转实体三元组、时间有向边、证据来源和时间单调路径；自己实现轻量图 | GNN 训练、Rust 引擎移植、Tauri、微服务和性能优化 |

RITA 特别说明：最初工作区文件未展开，已先用 `git show HEAD:...` 只读检查。用户随后补齐源码，本轮已再次直接读取 analysis/analysis.go、analysis/beacons.go，与此前对象内容核对。没有执行 checkout/restore 或修改参考仓库。读到的提交为 1317d70ce00319782c0983c7d9033b9290e58e95。

DNS 评分代码实际在 RITA analysis/analysis.go 的 C2 OVER DNS 分支（SubdomainCount 和 calculateBucketedScore）；不要将本项目的 entropy 组合公式误写为复制自 RITA。Beacon 文件中的 getTimestampScore、calculateStatisticalScore 分别提供间隔、偏斜与 MAD 思路。

## 数据契约的兼容处理

- 提示词中的 Unified Event 是现有 NormalizedEvent；Detection Event 是现有 Alert。没有建立第二套字段。
- 原文建议的 SPAWN/READ/WRITE/CONNECT 等不新增为枚举，使用 process_spawn/file_access/network_connect/related_to，并把具体动作保留到 attributes.kind。
- 协议字段在 metadata.zeek；数据来源在 metadata.raw_reference；字节计数仅在 conn 事件，HTTP/DNS 事件保留 session_event_id 引用。
- ICMP 的 id.orig_p/id.resp_p 是 type/code，存 metadata.zeek.icmp_type/icmp_code，公共端口为 null。
- ATT&CK 的父技术放 technique_id，子技术放 subtechnique_id；名称和 tactic 从输入的官方 STIX 查询。不认识的技术保留未解析提示，不造名字。
- 图中事件用现有 other 节点并标记 attributes.kind=event；阶段和候选路径使用现有 TraceResult。此临时的确定性 TraceResult 供离线联调，LLM 负责人可复用其证据摘要。
- 本模块的 metadata/attributes 扩展约定已写入 README；后续其他模块使用时需一起遵循。它们不是公共模型字段变更。

## 开发顺序

P0：公共对象兼容、Zeek 读取和会话、STIX 查询、证据攻击图、时间路径、离线集成入口。

P1：DNS/HTTP/ICMP/Beacon 基础检测、少量 Sigma 规则适配、APT Jaccard、正常对照和交付示例。三类隐蔽信道是最终必交功能，P1 表示开发顺序。

P2：更复杂的统计/模型、更多规则、图数据库、性能扩展；目前不做。

独立的全组验收必需项：主机采集器完善、认证和提权证据、八节点靶场、大模型多 Agent、后端/前端接入。公开网络日志已完成选定样本实测，真实多源攻击链和更多隐蔽协议正例仍待补充，详见 PUBLIC_DATA_VALIDATION.md。不能把这些未完成项归入可选 P2，也不能用合成示例替代。

## 新增与修改的代码

- collectors/network/adapter.py：读取、标准化、会话查询。
- detection/network_rules.py：四种候选通信检测与可解释评分。
- detection/attack_stix.py：官方知识索引和精确技术 ID Jaccard。
- detection/sigma_subset.py：小型显式规则解释器，不支持的语法报错。
- detection/service.py：保留 detect(events) 入口，通过 ATTACK_STIX_PATH 可选加载知识。
- correlation/service.py：实体和时间关系，保留 build_attack_graph(task_id, events, alerts)。
- correlation/paths.py：候选路径及确定性结果，缺失阶段不填充。
- correlation/pipeline.py：读现有事件、Zeek、告警、选定 Sigma，串联并验证新输出。
- correlation/demo.py：33 条合成事件的端到端示例，不预填告警/图。
- tests/test_network_correlation.py：关键反例和新产物契约校验。

## 已知实质限制

目前是离线、启发式、证据驱动的课程实现，不等价于全面检测系统。正常更新、遥测、备份也可能周期通信；评分不是概率。DNS 使用词法后缀集中度，没有 eTLD+1 公共后缀库。Zeek 默认 HTTP 日志看不到 HTTPS 明文，ICMP 默认汇总日志不提供载荷熵、载荷变化或包级周期性。缺少这些特征时明确标注。

攻击图只依据输入事实和已有告警关联。文件访问后出现网络流量不证明文件内容已外传。初始入侵、横向移动、提权、收集和外传的专门语义优先依赖上游告警；缺少主机/认证证据时不会自动补齐。关联候选不等于同一攻击者。未知主机的进程不会按 PID 强行合并；已知 PID 无 GUID 时依赖可见创建事件和关联窗口。

本次没有接管 agents 模块、实现真实 LLM 多 Agent、修改公共 API 或把后端 Mock 偷换为分析结果。课程整体完成仍需上述组员联调与实测。
