# 网络流量模块

负责离线 PCAP/网络会话/边界日志解析。
**跨模块输出必须是 `NormalizedEvent`。**
保留 src_ip/src_port/dst_ip/dst_port/network.protocol/network.session_id。
