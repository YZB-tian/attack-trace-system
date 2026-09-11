# 隐蔽信道检测验证：DNS / HTTP / ICMP 正反例（2026-09-10）

本文件记录靶场内自建的隐蔽信道正例与静默反例实验，用于补齐「隐蔽信道检测」
要求。所有流量都发生在隔离网段内，检测使用**未修改**的默认规则。

## 1. 实验设计

| 通道 | 正例流量 | 反例流量 |
| --- | --- | --- |
| DNS 隧道 | 192.168.56.30 向 192.168.56.40:53 发起 130 次 TXT 查询，首个标签为 32 位随机十六进制，`tunnel.attacktrace.lab` 后缀固定 | 6 次普通 A 查询（web01/mail01/core01 等常规主机名） |
| HTTP 隐蔽信道 | 192.168.56.30 向 192.168.56.40:8080 发起 24 次 GET，每次带 260 位随机十六进制查询参数，间隔 8 秒 | 24 次无参数普通请求（/healthz、/tasks） |
| ICMP 隧道 | 192.168.56.40 向 192.168.56.30 发送 160 个 400 字节随机载荷的 Echo 请求（对端原样回显，双向高熵） | 30 个小载荷 ping |

采集：08-Ubuntu-Sensor 在 VMnet2 上抓包（1706 包 / 322 KB）；Zeek 7.0.11 离线解析，
加载仓库内 `collectors/network/zeek/protocol-evidence.zeek` 以取得 ICMP 载荷熵与
HTTP 请求体度量。该脚本首次实际执行时发现 `sub_bytes(..., as int)` 类型转换在
Zeek 7 不受支持，已修正为直接传 count 参数。

## 2. 结果

| 任务 | 窗口（UTC） | 事件 | 告警 |
| --- | --- | ---: | --- |
| `task_covert-positive-20260910T183500Z` | 18:28:00 - 18:34:00 | 675 | `NET-DNS-TUNNEL`(T1071)、`NET-HTTP-COVERT`(T1071)、`NET-ICMP-TUNNEL`(T1095) ×2、`NET-BEACON` ×2 |
| `task_covert-negative-20260910T183500Z` | 18:34:20 - 18:38:30 | 226 | 无 |

正例中三类隐蔽信道全部命中；反例（普通 DNS、普通 HTTP 轮询、小 ping）零告警，
说明默认阈值没有把常规运维流量误判为隧道。

第一轮实验（run `covert-channel-20260910T182000Z`）HTTP 未被检出，原因是查询参数
只有 120 个十六进制字符、请求行长度低于规则的长 URI 门槛，`token_score` 为 0.6498，
略低于 0.65 阈值。第二轮把参数加长到 260 字符后命中。这条边界值得在报告中说明：
**规则对短编码载荷的灵敏度有限**，短消息型 HTTP 隐蔽信道可能漏报。

## 3. 复现命令

```powershell
python scripts/import_covert_channel.py --evidence-dir D:\AttackTraceLab\evidence\covert-channel-20260910T183500Z --output runtime/covert-positive --task-id task_covert-positive-20260910T183500Z --run-id covert-channel-20260910T183500Z --start 2026-09-10T18:28:00+00:00 --end 2026-09-10T18:34:00+00:00 --stix runtime/stix/enterprise-attack.json
python scripts/import_covert_channel.py --evidence-dir D:\AttackTraceLab\evidence\covert-channel-20260910T183500Z --output runtime/covert-negative --task-id task_covert-negative-20260910T183500Z --run-id covert-channel-20260910T183500Z --start 2026-09-10T18:34:20+00:00 --end 2026-09-10T18:38:30+00:00 --stix runtime/stix/enterprise-attack.json
```

生成端脚本在 `D:\AttackTraceLab\guest-services\covert-channel\`（DNS 服务端、
正例/反例流量脚本、ICMP 生成器、传感器抓包与 Zeek 解析脚本）。

## 4. 限制

1. 三个通道是自建的教学实现，不是 iodine/dnscat2/icmpsh 等真实工具；检测的是
   **流量形状**，不能证明工具归属。
2. HTTP 与 DNS 正例在同一窗口，`NET-BEACON` 也因 ICMP/DNS 的稳定间隔被顺带触发，
   属于规则的宽泛性，需要人工复核。
3. 反例只覆盖了少量常规流量形态（普通查询、健康检查、小 ping），不能代表全部
   企业背景流量；真实环境仍需按现场样本调参与白名单。
4. HTTPS 内容不解密，Zeek 只能看到连接元数据；`protocol-evidence.zeek` 的请求体
   度量仅对明文 HTTP 有效。
