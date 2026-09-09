# HTTP / ICMP 功能补充与交付说明

日期：2026-09-09。分支：`feature/network-correlation`。

## 本轮范围与结论

补齐基于 Zeek 日志的 HTTP/ICMP 离线特征分析、告警证据、正常对照、配置入口，以及接入现有图关联的处理链。公共接口修改：**否**。未修改其他组员代码，未提交或推送。

按用户最新要求，**本轮不使用 Orthrus 数据验证**。已经把 Orthrus 源码浅克隆到 `../security-trace-projects/orthrus`，但没有下载大型 DARPA/OpTC 数据库，也没有安装或运行 Orthrus。它适合主机事件与溯源图研究，不能直接补足当前 HTTP/ICMP 载荷检测验证。

Python 离线功能已通过模块测试与公共契约检查。新增 Zeek 增强采集脚本依据本地 Zeek 源码中的事件签名编写，**本机未安装 Zeek 可执行程序，尚未在 Zeek 环境执行或通过其语法检查**。不能把 Python 侧测试结果表述为采集脚本或真实靶场已验证。下一步在小组 Zeek 环境运行该脚本并接入真实日志。

## 已补的能力

### HTTP

- 同时检查查询参数和路径段中的长十六进制/Base64 形态数据；结合持续时间、数据变化比例、URI 长度和周期性判断。
- 相同的长令牌重复出现，不再单凭长度和熵触发该分支；普通浏览、单次大上传和普通 CONNECT 不直接报隐蔽通信。
- 检测持续的大 POST/PUT/PATCH 上传，结合周期和请求/响应字节方向比例。正常备份和遥测也可能符合，仍需明确业务白名单。
- 增强日志提供请求体采样长度、熵和 SHA-256 时，可检查体积较小但周期稳定、内容持续变化的高熵请求体。普通 `http.log` 没有这些字段时，只运行现有可用特征。
- 畸形 URL 或过多查询字段不会让整个检测批次崩溃；有告警时记录 malformed_uri_count。HTTP 正文不恢复、不解密 HTTPS，也不把统计异常认定为已证实外传。

### ICMP

- 按 Echo 类型区分请求和应答；支持 ICMPv4 与 ICMPv6，包括 Zeek 对 IPv6 仍记录 `proto=icmp` 的输入。
- 排除 Destination Unreachable 等 ICMP 错误报文，避免把其中引用的原始包当成隧道内容。
- 只有 conn.log 时，依据包量、平均 IP 包长、速率发出**统计异常候选**，evidence_level=flow_statistics；不伪造载荷熵。
- 修复多条连接观察跨度：以最早开始至最晚结束计算，避免低估持续时间、高估速率；告警结束时间也包含连接结束时间。
- 有增强 ICMP 样本时，使用采样熵、内容变化比例和采样数量；普通 Ping 的固定填充及仅时间戳变化的低熵数据不触发载荷分支。
- 有足够载荷样本的会话优先使用载荷证据，不再对同一会话重复报一条 conn 汇总告警。样本不足时仍保留统计分析。
- 反向 Echo 的实际 src/dst 正确转换；仍按 task、采集目录、Zeek uid 关联 conn；包样本不重复累计 network.bytes_in/out。

### 输入质量与证据

拒绝负数包量/长度、非有限数字、超出 0–8 的熵、非法 SHA-256、采样长度大于载荷长度，以及缺少必填测量的增强 ICMP 日志。保留输入原记录、路径、行号、uid 和实际特征值。熵和哈希针对采样内容，不能据此恢复原始文件内容。

## 输入与输出

输入：普通 Zeek conn.log、dns.log、http.log；可选增强 `icmp_payload.log` 和 http.log 中的采样字段。支持 JSONL 和带字段/类型头的 TSV。

跨模块输出仍为：NormalizedEvent、Alert；随后进入已有 AttackGraph 和离线 TraceResult。规则 ID 保持 NET-HTTP-COVERT、NET-ICMP-TUNNEL；有官方 STIX 时分别映射 T1071.001、T1095。新增 `action=icmp_echo` 是现有自由字符串字段的模块内动作约定，不改变公共枚举或 API。

普通 http.log 可继续使用。增强字段属于模块日志输入和 metadata.zeek，不要求上游主机组填充，也不新增公共对象字段。

## 在已有 Zeek 环境采集

脚本位置：`collectors/network/zeek/protocol-evidence.zeek`。

在单独的日志输出目录内，使用该脚本和授权靶场 PCAP，例如：

```bash
zeek -r /path/to/capture.pcap /path/to/attack-trace-system/collectors/network/zeek/protocol-evidence.zeek LogAscii::use_json=T
```

这条命令需要在已经安装 Zeek 的环境执行。本机没有执行上述命令。

脚本保留 Zeek 自己的协议解析与 HTTP 请求状态，最多取每个请求体前 1024 字节、每个 ICMP Echo 载荷前 512 字节计算特征。只写长度、熵、采样哈希，不把正文样本写进日志。icmp_payload.log 按 Echo 包写记录，流量繁忙时需控制采集时段及日志留存；本模块未实现生产规模采样调度。

输出主要增强字段：

| 日志 | 字段 |
|---|---|
| http.log | ats_body_sample_len、ats_body_entropy、ats_body_sha256 |
| icmp_payload.log | ts、uid、id、proto、is_orig、icmp_type/code、echo_id/seq、payload_len、payload_sample_len、payload_entropy、payload_sha256 |

网络组用现有命令分析产生的目录：

```powershell
.\.venv\Scripts\python.exe -m correlation.pipeline --task-id task_protocol_lab --zeek-dir <Zeek日志目录> --stix ../security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json --output correlation/output/protocol_lab
```

## 独立交付示例与测试

```powershell
.\.venv\Scripts\python.exe -m correlation.protocol_demo --stix ../security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json
.\.venv\Scripts\python.exe scripts/validate_contracts.py
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=correlation/output/pytest-protocol-review
```

示例位于 `correlation/output/protocol_demo`，共 **50 条明确标注的合成事件**，不是 PCAP、公开数据集或 Zeek 实采结果。实际执行解析、检测、STIX 映射和图关联；每个案例生成四类公共对象并校验 Schema 与证据引用。

| 案例 | 实际输出 |
|---|---|
| 持续变化的 HTTP 编码参数 | 1 条 NET-HTTP-COVERT |
| 周期性变化的高熵 HTTP 请求体 | 1 条 NET-HTTP-COVERT |
| 重复使用的固定 HTTP 令牌 | 0 条告警 |
| 变化的高熵 ICMP 载荷采样 | 1 条 NET-ICMP-TUNNEL |
| 普通 Ping 填充 | 0 条告警 |

测试结果：**85 passed**，包含新增 16 个参数化测试实例；公共示例契约验证通过。原多源合成 demo 重跑仍为 33 条事件、2 条告警、42 个节点、229 条边。测试覆盖正常对照、畸形 URL、异常测量、配置与白名单、反向 Echo、IPv6、时间跨度、去重以及与现有关联模块的接入。

可选 `--network-config` JSON 新增参数：

```json
{
  "http_min_encoded_length": 64,
  "http_large_upload_bytes": 65536,
  "icmp_min_packets": 100,
  "icmp_min_average_bytes": 256,
  "icmp_payload_entropy": 6.2
}
```

已有 min_samples（默认 8）、min_span（120 秒）、window_seconds（1800 秒）、risk_threshold（0.65）、allowed_domains、allowed_destinations 继续有效。评分是可解释启发式，不是校准概率。

## 本轮修改文件

- collectors/network/adapter.py：增强字段接入和校验、ICMP 包方向、可选日志加载。
- collectors/network/zeek/protocol-evidence.zeek：新增可选增强采集脚本，待 Zeek 环境验证。
- detection/protocol_features.py：新增 HTTP、ICMP 特征分析。
- detection/network_rules.py：接入特征、类型隔离、配置、会话去重与结束时间修正。
- correlation/protocol_demo.py：新增可运行的小型交付示例。
- tests/test_http_icmp.py：新增协议正反例与集成测试。
- tests/test_network_correlation.py：原 HTTP 正例改用变化数据；原 ICMP 正例补准确 Echo 类型，避免把错误样本当成正例。
- 三个模块 README、VALIDATION.md、PUBLIC_DATA_VALIDATION.md 及本说明：更新能力、验证边界和交付入口。

## 仍有的边界

新增功能的独立真实 HTTP/ICMP 正样本验证、Zeek 脚本执行验证和八节点全组联调尚未完成。正常的随机化 Ping、加密文件上传、合法遥测可能满足统计特征；低熵命令、缓慢通信、加密不可见内容、位于采样范围之外的数据可能漏报。当前结果只提供待核查的异常与证据，不确认攻击者身份，也不自动阻断流量。

此前 IoT-23 的 C2 漏报未在本轮扩展处理。此前公开数据报告属于当时版本的实测记录，本轮没有用新增合成案例替代公开验证，也没有重跑 Orthrus 或扩大数据集下载。
