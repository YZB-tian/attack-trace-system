# 攻击链关联模块

输入：`NormalizedEvent` + `Alert`
输出：`AttackGraph`

所有边必须通过 evidence_event_ids / evidence_alert_ids 保留证据引用。

## 已实现的离线处理链

Zeek JSONL/TSV + 其他组员的 NormalizedEvent → 网络/Sigma 检测 → 官方 STIX 映射 → AttackGraph → 候选攻击链和 APT Jaccard → 确定性 TraceResult。

后端通过 `correlation.pipeline.analyze` 分析导入事件，不再默认读取 Mock。真实靶场导入见 `collectors/LAB_IMPORT.md`。未改动 agents 模块；本模块的 TraceResult 是可复核的离线结果，`attribution.llm_used=false`，不能当作大模型多 Agent 已完成。

## 安装和运行（在 attack-trace-system 根目录）

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# 仅使用 --sigma-rule 时需要此可选依赖
.\.venv\Scripts\python.exe -m pip install -r detection/requirements.txt

# 小型合成示例：实际运行解析、检测、关联，不预填告警或攻击图
.\.venv\Scripts\python.exe -m correlation.demo --stix ../security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json --output correlation/output/demo

# 重放示例的输入；替换路径即可接入真实 Zeek 输出和组员标准事件
.\.venv\Scripts\python.exe -m correlation.pipeline --task-id task_network_demo --zeek-dir correlation/output/demo/synthetic_inputs --events correlation/output/demo/synthetic_inputs/host_events.json --stix ../security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json --output correlation/output/replay
```

CLI 的 `--stix` 必须指向官方 bundle，不偷偷回退到手工 APT 库。可多次传 `--sigma-rule <规则.yml>`，只加载显式指定规则。`--alerts <告警.json>` 接入其他检测组员的 Alert；`--window-seconds 900` 配置关联窗口。事件必须属于同一 task_id。

输出只有公共对象：normalized_events.json、alerts.json、attack_graph.json、trace_result.json。示例额外写 PROVENANCE.txt 明示合成来源。输入日志无任何真实攻击流量，不能代替公开数据集和八节点靶场验证。

## 测试

```powershell
.\.venv\Scripts\python.exe scripts/validate_contracts.py
.\.venv\Scripts\python.exe -m pytest -q
```

新增测试验证正常/可疑流量、异常输入、重复计数、跨任务、PID 复用、悬空引用、Sigma 子集、STIX 和新生成结果的 Schema。CLI 和 demo 也在写结果前验证新产物。

## 图与路径约定

- Host ID 只来自资产或上游标准事件；进程按主机+GUID 合并，缺 GUID 时根据可见创建事件区分 PID 生命周期。缺少身份依据时不强行合并。
- `other` 节点的 `attributes.kind=event` 表示事件证据锚点；参与时间关联、主机行为或没有足够实体事实的事件继续保留。没有跨事件关联作用的网络观察收进实体 `attributes.event_observations`，保留 event_id、timestamp、alert_ids、technique_ids；Trace 同时兼容这两种存放方式。文件按主机+路径区分。
- `related_to` 边的 `attributes.kind=event_correlation` 是候选时间关联；包含 reasons、time_delta_seconds 和证据 IDs。实体事实边与攻击候选边明确区分。
- 关联依据：相同进程实例、父子进程、同主机文件、跨来源五元组（30 秒内）、相同 Zeek 会话、连接+认证、目标主机的登录用户+进程。只同主机、同用户、同目标 DNS/IP 或时间接近不够。
- `TraceResult.attack_chain` 只呈现证据最强的一个候选路径；其他独立路径在 `attribution.candidate_paths`，不会强行串联。最多输出 20 条路径，避免组合爆炸。
- APT Jaccard 仅使用主候选路径的确切技术 ID，父子技术不模糊合并，未知/废弃技术不编造。结果明确为行为相似度。
- 初始入侵点仅由置信度至少 0.6 的 initial-access 告警支持；没有就返回 null。横向移动、提权、收集、外传的专业阶段依赖上游对应告警。阶段名称不用于伪造时间顺序。
- 先读文件再发网络请求只构成待核查路径，不能证明该文件内容外传。
- `attribution.path_analysis` 列出已有告警支持的横向移动、提权、收集、外传候选边；`data_access_to_network_candidates` 列出同一路径的文件读写和网络事件，始终标明 content_transfer_proven=false。
- C2 候选实体保留 first_seen/last_seen、connected_hosts、domains（由同 uid 的 HTTP host 提供）和 risk_score。
- 相同实体、关系、动作及服务上下文的重复事实边聚合，所有 evidence IDs 取并集；不同时间、源端口、会话及置信度逐条保存在边的 `attributes.observations`。目的端口、协议或关联原因不同的关系不强行合并。顶层 timestamp 为首次观察，confidence 为最大值，具体值以 observations 为准。

## 组员交接

公开数据复现入口：`python -m correlation.validate_public_data --stix <官方 STIX 文件>`。下载、文件校验值、实际结果和限制见 [PUBLIC_DATA_VALIDATION.md](PUBLIC_DATA_VALIDATION.md)。该入口完整分析两份 IoT-23，完整解析 RITA 三类日志，再对固定第一小时运行检测与关联。与上面的合成 demo 分开保存。

关联分析按进程、文件、会话、认证端点和用户建立候选索引，再执行原有证据判定。五元组候选仍须涉及主机进程，且最长 30 秒，避免同一端点大量重复流量形成无意义两两比较。密集的真实同进程/同会话关系仍可能产生较多边；这不是无限规模性能保证。

主机负责人提供带时区时间、资产 host_id、准确 action、进程和父进程信息；尽量在 raw_event 保留 ProcessGuid/ParentProcessGuid 和命令行。认证/提权负责人提供实际事件与有证据的 Alert。后端负责人接入 analyze；Agent 负责人使用图和候选链摘要补大模型协调；前端负责人按现有 API 展示。

完整的六项目阅读清单、已有问题、P0/P1/P2 和剩余验收项见 [IMPLEMENTATION_REVIEW.md](IMPLEMENTATION_REVIEW.md)。公共接口修改：否。

HTTP/ICMP 离线功能补充、Zeek 可选增强脚本、正反例交付见 [HTTP_ICMP_HANDOFF.md](HTTP_ICMP_HANDOFF.md)。运行 `python -m correlation.protocol_demo --stix <官方STIX文件>` 可生成 50 条合成事件并验证四类公共输出，默认输出至 correlation/output/protocol_demo。该示例不能替代真实流量和靶场验收。

## 2026-09-10 主机默认检测与图降噪

`analyze(task_id, events)` 现在默认运行网络检测及两个内置 Windows/Linux 主机规则，调用方式不变。可选 Sigma 仍显式加载，不会默认扫描整个 Sigma 仓库。

运行 `python -m correlation.host_demo` 可生成 Windows/Linux 正反例及 10 条 Beacon 回归输入；无需额外 STIX 下载。详细输入字段、结果、后端快照 HTTP 验证及其他组待办见 [HOST_GRAPH_HANDOFF.md](HOST_GRAPH_HANDOFF.md)。上述历史说明中的 Mock 后端指 dev 当前版本；真实后端在 `origin/integration/backend-pipeline`，需要后端负责人合入部署。
