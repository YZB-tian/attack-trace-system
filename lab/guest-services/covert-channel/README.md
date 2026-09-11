# Covert-channel experiment scripts (DNS / HTTP / ICMP)

在隔离靶场内生成三类隐蔽信道的正例流量与静默反例，并采集证据。

| 脚本 | 运行位置 | 作用 |
| --- | --- | --- |
| `30-dns-tunnel-server.py` | C2 模拟器 192.168.56.40（root） | 最小 DNS 服务端，用 TXT 记录回应查询标签 |
| `31-covert-positive.sh` | 192.168.56.30 | 130 次 DNS 隧道查询 + 24 次带编码参数的 HTTP 请求 |
| `31b-covert-negative.sh` | 192.168.56.30 | 普通 DNS、普通 HTTP 轮询、小 ping 反例 |
| `32-icmp-tunnel.py` | 192.168.56.40（root） | 正例：160 个 400 字节随机载荷 Echo；反例：30 个小 ping |
| `34-capture-start.sh` / `35-capture-stop.sh` | 08-Ubuntu-Sensor（root） | 在 ens160 上按需抓包 |
| `36-dns-server-start.sh` | C2 模拟器（root） | 启动 DNS 服务端并记录 PID |
| `38-zeek-covert.sh` | Kali | 用仓库内 Zeek 与 `protocol-evidence.zeek` 离线解析抓包 |

结果与限制见 `docs/covert-channel-verification.md`。
