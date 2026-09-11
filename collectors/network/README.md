# 网络流量模块

负责离线 PCAP/网络会话/边界日志解析。
**跨模块输出必须是 `NormalizedEvent`。**
保留 src_ip/src_port/dst_ip/dst_port/network.protocol/network.session_id。

已实现 Zeek `conn.log`、`dns.log`、`http.log` 的 JSONL 和有 `#fields/#types` 头部的 TSV。调用 `load_zeek_logs(directory, task_id)`，或 `normalize_network_records(records, task_id)`；直接传 records 时可用 `_log_type=conn/dns/http` 指明来源。不支持任意格式的边界日志。

不重新实现抓包或 PCAP 解析。实际采集由安装好的 Zeek 在授权靶场运行，例如 Linux 的 `zeek -r capture.pcap LogAscii::use_json=T` 或 `zeek -i <接口> LogAscii::use_json=T`。本机未执行 Zeek 抓包或编译。读取日志不需要安装 Zeek Python 库。

额外约定：

- `metadata.zeek` 保留查询域名、HTTP host/URI/方法/大小、包数、duration/end_time 等输入已有字段。
- `metadata.raw_reference` 保留文件绝对路径和行号；raw_event 保留原始记录，不制造缺失值。
- 会话 ID 按 task+采集目录+uid 命名空间生成；事件 ID 按任务和原记录（含来源）确定，原路径原内容重复导入可去重。相同内容来自不同路径不会被当作同一证据。
- HTTP/DNS 关联到 conn 时保留 `metadata.session_event_id`。bytes_in/out 只计 conn；host_id 优先取源资产，否则取目标资产。计数字节方向相对 host_id，双方均不在资产表时相对 originator，并记录 bytes_perspective。
- ICMP 的 type/code 保留 metadata，src_port/dst_port 为 null。没有 duration 就不捏造 end_time。
- query_sessions 支持 IP、任一通信端资产 host_id、带时区时间区间相交查询，返回连接 NormalizedEvent。
- 资产区划优先使用 config/assets.json；未知端点的方向仅在 Zeek 提供 local_orig/local_resp 时确定，否则为 null。

未知格式、缺时间/端点、无时区、负数大小、非法端口报错，不静默丢行。本版未处理压缩日志、日志轮转目录批量导入或跨传感器 UID 对齐。

公开数据验证后补充：兼容 RITA 导出日志的 `#separator \\t` 写法和单个空行尾分隔列，额外非空列仍报错；文件绝对路径每个文件只解析一次。IoT-23 的特殊混合空格标签列由 `correlation.validate_public_data.prepare_iot` 单独转换并剥离标签，标签不输入检测器。gzip 由评估准备步骤解压，本适配器本身仍不处理压缩文件。

运行示例和测试见 correlation/README.md。公共接口修改：否。

## HTTP / ICMP 增强输入

新增可选 `icmp_payload.log` 支持，由本模块 `zeek/protocol-evidence.zeek` 提供 Echo 类型、方向、载荷采样长度/熵/SHA-256。反向包转换实际 src/dst，通过 uid 关联 conn，字节总量仍只统计 conn。相应标准事件的 action 为 `icmp_echo`。默认 http.log 可增加请求体采样长度、熵和哈希；无增强字段时仍能分析原有日志。

该脚本只使用 Zeek 已解析事件，不实现 PCAP 解析；本机未安装 Zeek，采集脚本尚未执行验证。Python 读取、检测与关联已经通过模块测试。完整字段、运行方式和限制见 `correlation/HTTP_ICMP_HANDOFF.md`。
