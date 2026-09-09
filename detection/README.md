# 检测与 ATT&CK 映射模块

输入：`list[NormalizedEvent]`
输出：`list[Alert]`

规则/模型内部实现可自由选择，但 `Alert` 字段不可私改。

## 网络检测

`detect(events)` 保持原函数签名；设置 ATTACK_STIX_PATH 后自动查官方数据。更完整的离线调用用 correlation.pipeline（要求显式 --stix）。

- DNS：长标签、高熵、不同标签比例、词法后缀集中度、TXT 与频率组合。至少 8 条，至少两个主要异常特征；词法后缀不等同于注册域。
- HTTP：长 URI、高熵长查询参数、重复大 POST/PUT 与周期性。默认日志没有 HTTPS 明文，不声称解密；不恢复请求体内容。
- ICMP：包数、IP 层字节、平均包长、速率、持续时间组合。没有载荷熵就明确 payload_entropy_available=false；不把连接间隔当作包级间隔。
- Beacon：足够样本和持续时间、间隔 MAD/CV、稳定请求大小。只报周期通信候选，不凭周期性断定攻击者或具体 ATT&CK 技术。

2026-09-09 公开日志验证后的修正：

- DNS 增加短十六进制 TXT 组合条件：同窗口至少 100 条、跨度至少 min_span，16–63 字符十六进制标签（熵至少 2.5）占比、不同标签比例、TXT 比例、词法后缀集中度均至少 0.8。不硬编码测试域名。`detect_short_hex_dns=false` 可关闭。
- Beacon 默认排除源/目标端口都为 123、UDP、双向应用层字节均为 48 的 NTP 形态窗口，修复正常校时误报。`suppress_ntp_shaped_beacons=false` 可关闭；这不是协议验证，可能漏掉刻意模仿此形态的通信。端口相同但其他大小的流量仍评估。
- 两份 IoT-23 的 C&C 流标签覆盖率仍为 0，不能把误报减少说成 C&C 检测已经合格。完整数据、口径和结果见 `correlation/PUBLIC_DATA_VALIDATION.md`。HTTP/ICMP 尚无本轮独立真实正样本效果验证。

评分是可解释的启发式风险，不是校准概率。Alert.evidence_summary 为 JSON 文本，包含实际特征值、样本量和 score_kind。技术名来自 STIX；未配置知识时 mitre=null 并保存未解析的规则技术 ID。

可选 `--network-config` JSON 支持 window_seconds、min_samples、min_span、risk_threshold、allowed_domains、allowed_destinations。窗口按每组首条事件开始，按源/目标/协议/动作分组，防止跨任务混合；DNS 不按源临时端口分组。正常遥测/备份可能满足统计特征，应在靶场样本上调参并建立明确白名单。

## Sigma 子集

仅通过 --sigma-rule 显式指定 YAML 文件，不导入全仓，不复制规则。可选依赖安装 `python -m pip install -r detection/requirements.txt`。

支持字段等值/通配符、contains/startswith/endswith/all，选择器 AND、选择器列表 OR，以及 condition 的 and/or/not、括号、1/all of。相关 process_creation/file_event/network_connection；product 必须与源事件匹配。不支持的条件、正则、聚合、编码修饰符和服务专属规则报错。

已选读并验证的规则示例是 rules/windows/process_creation/proc_creation_win_certutil_download.yml，使用 tags 中技术 ID 经 STIX 查名称和 tactic。一条规则多个技术时输出多条 Alert，以适应现有单个 mitre 对象，不更改 Schema。产品标识优先 metadata.os，其次资产表 os，再次明确的 source；raw_event 保留命令行。

## 官方知识索引

AttackKnowledge 读取官方 STIX bundle，过滤 revoked/deprecated，提供技术名称、描述、战术、父技术、相关组织/软件，以及 Group→Technique 的精确 Jaccard。缺数据不退回手工编造知识；相似度不等于确认归因。

运行和测试入口见 correlation/README.md。公共接口修改：否。

## HTTP / ICMP 后续补充

详细实现和最新验证见 `correlation/HTTP_ICMP_HANDOFF.md`。HTTP 现在要求编码参数/路径数据持续变化，支持可选高熵请求体采样，保留周期大上传分析；固定令牌、单次上传和 CONNECT 本身不作为隐蔽通信证据。ICMP 区分 Echo 与错误报文，支持 IPv6、载荷采样模式与统计候选模式，修复观察跨度和告警结束时间，并避免同会话重复使用包样本和 conn 总量报警。

NetworkConfig 新增 http_min_encoded_length、http_large_upload_bytes、icmp_min_packets、icmp_min_average_bytes、icmp_payload_entropy，默认值见交付说明。旧 DNS、NTP 配置继续有效。新评分函数在 protocol_features.py，公共 detect 签名与 Alert 结构不变。

新增 50 条明确标记的合成交付示例与协议测试；截至此次补充为 85 passed。独立真实协议效果与 Zeek 增采脚本执行仍待靶场验证，没有将合成数据算作真实数据。
