# LLM / 多 Agent 溯源分析模块

推荐输入：`AttackGraph`、`Alert` 和必要事件摘要。
输出：`TraceResult`。

LLM 只能做分析/解释/关联辅助，必须保留 evidence ID，不能凭空生成不存在的证据。
