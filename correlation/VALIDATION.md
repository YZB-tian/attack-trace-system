# 本轮验证记录

验证日期：2026-09-09。分支：feature/network-correlation。

## 结果

| 项目 | 实际结果 |
|---|---|
| 原有测试基线 | 修改前 49 passed |
| 最终 pytest | HTTP/ICMP 补充后 85 passed（之前 69 + 新增 16 个测试实例）；本机使用模块 output 下的独立 basetemp，绕开旧临时目录权限问题 |
| scripts/validate_contracts.py | 所有原有公共示例通过 |
| 新生成的四类公共对象 | demo 和 pipeline 写入前均通过 JSON Schema + FormatChecker |
| 独立重放 | 四份 JSON 除 generated_at 外完全一致；不同事件输入顺序的回归测试也通过 |
| git diff --check | 通过 |
| 受保护目录/文件 | schemas、common/models.py、common/enums.py、config/assets.json、前端公共类型/API 均无差异 |
| 其他组员模块 | backend、agents 无修改；Windows/Linux/主机行为采集器无修改 |
| Git 操作 | 已创建功能分支；未提交、未推送 |

## 合成示例

运行命令见 README.md。输出在 correlation/output/demo/；独立重放在 correlation/output/replay/。output 被模块 .gitignore 排除，不污染公共 testdata。

- 输入：33 条明确标注的合成事件，其中 20 条来自本地示例 conn.log/http.log，13 条为标准主机事件。
- 实际计算结果：2 条告警、42 个图节点、229 条证据边。
- 输出 10 条候选路径，主路径只有实际映射到的 Command and Control/T1071.001 阶段，不补齐不存在的攻击阶段。
- 10 条文件访问后通信的候选记录；content_transfer_proven 全为 false。
- 没有初始入侵证据，initial_access_entity_id 为 null。
- APT 只使用主候选路径技术集合做 Jaccard；llm_used=false。

本示例不是 DARPA 或其他真实公开数据集，不是八节点靶场采集，也没有证明真实外传或组织归因。

## 参考数据实测

- 已直接读取补齐的 RITA analysis/analysis.go 和 analysis/beacons.go，未复制/修改源码。
- 官方 ATT&CK bundle 过滤废弃/撤销条目后，当前索引为 697 个技术和 176 个组织；数量随输入版本而变。
- 本地官方 Sigma 的 certutil 下载规则通过真实 YAML 解析和正反例验证，得到 T1027/T1105 两条映射，正常本地操作不命中。只匹配字符串，未执行样例命令。

## 尚未完成的全组验收工作

真实主机采集与认证/提权证据、八节点靶场验证、后端/前端真实流水线接入、大模型多 Agent 协调及现场演示材料。公开网络日志验证现已完成本轮选定样本，详见 PUBLIC_DATA_VALIDATION.md；C&C 漏报、真实 HTTP/ICMP 正样本以及多源完整攻击链效果仍待补足。已有 Agent 的手工知识库和原 Windows 适配器问题见 IMPLEMENTATION_REVIEW.md，交给各负责人处理。

本轮交付的边界是网络、检测和关联模块的可运行离线第一版，不能将此记录表述为课程全部要求已完成。

后续 HTTP/ICMP 离线功能、50 条合成正反例及 Zeek 增强脚本的待验证状态见 HTTP_ICMP_HANDOFF.md。Orthrus 仅克隆参考源码，按用户要求不下载或使用其大型数据集；85 项 Python 测试通过不代表 Zeek 脚本或全组靶场已验证。
