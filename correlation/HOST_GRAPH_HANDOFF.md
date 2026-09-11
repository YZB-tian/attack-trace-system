# 二组：主机默认检测与攻击图降噪交付

日期：2026-09-10。分支：feature/host-detection-graph-noise，基于 dev 8a3f695。

## 范围

只修改 detection、correlation 及对应 tests。公共接口修改：否。未修改 schemas、common/models.py、common/enums.py、config/assets.json、前端、后端、agents 或其他组采集器。未自动合并或推送。

输入为公共 NormalizedEvent（以及原有可选 Alert）；输出仍为 Alert、AttackGraph、TraceResult。既有函数签名、API、公共字段、ID 前缀保持不变。

## 图节点为什么多

原 correlate 无条件给每条输入事件建立一个 type=other、label=action 的事件节点，并连接 observed_on。其作用是时间关联和 Trace 的证据锚点。原事实边的 ID 又包含 event_ids，所以不同事件的同一网络关系不会聚合。

因此这些不是十个不同的“network_connect 实体”，而是十条动作观察。对于没有任何跨事件关联边的重复网络观察，单独占据图顶点并非必要；对于真正参与关联的观察，直接删除会破坏 Trace。

## 保留、聚合与证据

| 内容 | 本次处理 |
|---|---|
| Host、Process、User、File、IP、Domain | 保留实体语义和原身份边界；不因标签相同就合并 |
| 已知资产的 Host/IP | 继续按公共资产表解析成同一 Host；不猜测未知 IP 属于哪个主机 |
| 进程 | 同主机 GUID/可证明生命周期合并；PID 复用或身份不确定时继续分开 |
| 文件、用户 | 不跨主机强行合并；文件按主机和路径区分 |
| C2 | 保留“IP+端口+协议”的候选服务角色；普通 IP 是地址实体，两者不直接合并，更不把候选标成确认攻击者 |
| Technique | 有真实 Alert.mitre 映射时保留，作为分类实体 |
| 参与 event_correlation 的事件节点 | 全部保留，包括进程、文件、登录、同 Zeek 会话等关联依据 |
| 主机动作/缺少网络实体事实的节点 | 保留，不删除只剩动作证据的事件 |
| 无跨事件关联作用的网络动作节点 | 移入主体实体 attributes.event_observations；时间、event_id、alert_ids、technique_ids、host_id 等继续保留 |
| 同语义重复关系 | 聚合 evidence_event_ids/evidence_alert_ids；每次观察时间、源端口、会话、置信度、原属性在 attributes.observations 中保留 |

不同目标端口、协议、动作、域名或关联原因不强行合并。边 timestamp 表示首次观察，confidence 取最高值；细节见 observations。observed_on 表示观察归属，不应解释成未知 IP 的资产所有权证明。

## 优化前后实测

未收到前端 E2E 的原始 JSON。本次构造一份结构相同的可重复样本：10 条相隔 60 秒、固定大小的网络事件，host_id=officepc01、源 IP=10.10.2.50、目的 IP=198.51.100.20、目的端口 443，源端口和会话逐次变化。通过真实 detect_network 得到 1 条 NET-BEACON，未预填告警。

| 指标 | 原实现 | 优化后 |
|---|---:|---:|
| 输入事件 | 10 | 10 |
| NET-BEACON | 1 | 1 |
| 节点 | 14 | 4 |
| other 动作节点 | 10 | 0 |
| 总边数 | 30 | 3 |
| related_to / observed_on | 10 | 1 |
| network_connect | 10 | 1 |
| c2_communication | 10 | 1 |

保留的 4 个节点为 1 Host、2 IP、1 C2。源 IP 不在资产表中，不能把它强行合并到 officepc01。每条聚合边都包含全部 10 条事件及该告警引用。会话 ID、源端口、时间均逐条核验保留。候选路径、Trace 总证据与优化前相同。NET-BEACON 本身不从周期性推断具体 ATT&CK 技术，因此此案例 Trace.status=completed，但 attack_chain 阶段数仍为 0；未编造阶段。

`tests/test_graph_compaction.py` 通过暂时关闭末尾压缩步骤生成原图对照，可复现上述数量；同时验证同会话关联、进程/文件链、不同服务、不同域名、Trace 无悬空实体引用及乱序重放。

## 主机检测结果

默认入口 `analyze(task_id, events)` 和 `detection.service.detect(events)` 已接入两个主机规则，不需要后端显式选择 Sigma。Sigma 原有显式加载方式保留。

| 输入案例 | 默认 Alert.rule_id | 节点 / 边 | Trace 阶段 |
|---|---|---|---:|
| Windows PowerShell 编码启动命令 | HOST-WIN-POWERSHELL-ENCODED | 5 / 4 | 1 |
| Linux auditctl 关闭审计命令 | HOST-LINUX-AUDIT-DISABLE | 5 / 4 | 1 |
| Windows 普通 Get-Date | 无 | 4 / 3 | 0 |
| Linux auditctl 查询状态 | 无 | 4 / 3 | 0 |

两个正例的 5 个节点为 Host、User、Process、事件证据锚点、Technique。保留主机事件锚点用于后续进程/登录关联。Windows 映射 T1059.001 / execution，Linux 映射 T1685.004 / defense-impairment；来源为本地官方 STIX 摘录及 SHA-256，不要求部署者再下载整个参考仓库。

Windows 测试任务 task_host_windows、事件 evt_windows_positive；命令内容是编码的 `Write-Output 'course-demo'`，只作为检测输入。Linux 测试任务 task_host_linux、事件 evt_linux_positive；输入对象 object.type=command、object.name 包含 `/sbin/auditctl -e 0`，同样只作为文本，不执行。

验收测试还实际调用 Windows/Linux 采集器，将 Sysmon 风格记录及 auditd EXECVE 文本转成 NormalizedEvent，再自动通过上述链路；没有修改采集器。没有命令参数的 SYSCALL 单行无法确定 auditctl 的具体操作，不据此报警。

## 使用和产物

在项目根目录、安装原有 requirements.txt 后运行，无新增必需依赖：

```powershell
.\.venv\Scripts\python.exe -m correlation.host_demo
```

生成目录 `correlation/output/host_graph_demo/`，包含 windows、linux、windows_normal、linux_normal、beacon 五组；每组有：

- normalized_events.json：可直接 POST /api/events 的公共输入数组。
- alerts.json：真实检测生成的公共 Alert。
- attack_graph.json：实际构建并降噪的图。
- trace_result.json：实际 Trace 输出。

总报告 report.json。全部为合成数据，不能称为真实靶场采集或恶意样本覆盖率评估。编码 PowerShell 和审计配置修改可能是合法运维；告警为待核查候选，未确认执行成功。默认仅两条窄规则，不代表全量主机检测。

## 后端联调和其他组待办

已读取并运行后端集成分支 `origin/integration/backend-pipeline` 的 backend/main.py 快照，提交 `32d23c977a8bdef4163ec92bef9a53e6d175dc47`。快照导入本次二组实现，在本地 127.0.0.1 随机端口启动真实 FastAPI 服务，通过 HTTP POST /api/events，再 GET alerts、attack-graph、trace、tasks；上述五案例全部通过，并校验五类公共 Schema、图引用、Trace 实体引用及重复提交幂等。服务验证后自动关闭。

可重复运行（需要该 Git ref 已 fetch 到本地）：

```powershell
.\.venv\Scripts\python.exe -m correlation.backend_smoke --backend-ref origin/integration/backend-pipeline
```

输出 `correlation/output/backend_host_graph/`，各组保存真实 API 返回的 Alert/Graph/Trace/TaskStatus 和提交输入，附 report.json。此脚本仅读取并执行明确选择的仓库后端快照，不更改 backend 文件，不执行示例中的主机命令。它不是浏览器前端 E2E。

必须由其他组处理：

1. 后端负责人将已有真实集成分支合入或部署，再同步本次二组分支并重启服务。当前 dev 的 backend/main.py 仍是 Mock；只更新二组代码、却运行 Mock 后端，不会自动进入分析链。集成分支已经调用 analyze，无需新增 API 或修改入参。
2. 前端负责人用真实 API 重新验收展示；如果 UI 想展示聚合次数、源端口/会话明细，可读取 observations/event_observations。这是可选展示增强，不要求增加公共字段。

其他采集器没有必须改动项。更完整 Linux 进程身份关联需要同主机 audit_seq 的 SYSCALL/EXECVE 关联出 PID/可执行文件/命令参数，可由采集负责人后续完善；目前采用既有 command_args 输入可以完成单事件检测。

## 修改清单

最终验证：公共契约检查通过，完整测试 **168 passed**（原 dev 139 项，加本轮 29 项）；git diff --check 通过。命令：

```powershell
.\.venv\Scripts\python.exe scripts/validate_contracts.py
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=correlation/output/pytest-host-graph-final
```

重复执行 pytest 时可更换 basetemp 的末级目录名，避免本机临时目录权限影响验证。

- detection/host_rules.py、host_techniques.json：两个默认规则及可追溯映射。
- detection/service.py、correlation/pipeline.py：默认接入主机检测。
- correlation/compact.py、service.py、paths.py：保守图降噪及 Trace 兼容读取。
- correlation/host_demo.py、backend_smoke.py：公共输入/输出演示和真实 HTTP 验证。
- tests/test_host_detection_pipeline.py、test_graph_compaction.py：正反例、上游采集器适配、证据保存及完整链路回归。
- detection/README.md、correlation/README.md、本交付说明：输入、运行、验收及边界。

公共模型和其他组代码未修改。历史公开数据、HTTP/ICMP 靶场验证没有在本轮扩展；已有进程/文件强关联图仍可能较密，本次没有删掉语义上必要的关联关系。
