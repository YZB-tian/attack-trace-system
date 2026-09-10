# LLM / 多 Agent 溯源分析模块

推荐输入：`AttackGraph`、`Alert` 和必要事件摘要。
输出：`TraceResult`。

LLM 只能做分析/解释/关联辅助，必须保留 evidence ID，不能凭空生成不存在的证据。

## DeepSeek evidence review

`deepseek.py` implements two sequential, separate-context roles: analyst, then
reviewer. The reviewer sees the same minimized evidence and the untrusted draft.
This is a small two-role workflow using one model, not independent model consensus.
Neither role has tools or authority to change alerts, stages, or attacker identity.

Set `LLM_API_KEY` and `LLM_MODEL` in local `.env` (ignored by Git), or environment.
The endpoint is pinned to `https://api.deepseek.com/chat/completions`; custom
`LLM_BASE_URL` values are not used. No key is sent to a configurable destination.

```powershell
python scripts/review_deepseek.py --events runtime/lab/normalized_events.json --task-id task_beacon-20260910T153854Z --output runtime/deepseek-review.json
$env:ATS_LLM_REVIEW_FILE=(Resolve-Path runtime/deepseek-review.json).Path
# Start/restart backend with this environment to show the supplementary review.
```

Each explicit run makes at most two calls, no automatic retries, 90-second timeout
per call, 1800 output tokens per role. Usage is recorded in the local result.
Review at most 120 events, prioritizing alert evidence then timestamp. This is
biased sampling, not proof about excluded events. Packet contains temporary event
IDs, UTC/offset timestamps, temporary host labels, allowlisted actions, alert
membership and controlled-emulation flags. Raw logs, commands, usernames, IPs,
file contents and original host/event identifiers are not sent. Citations are
translated back locally. Do not remove this boundary to enrich prompts casually.

Results with unknown evidence IDs, malformed JSON, failed requests, or incomplete
responses are rejected. Output replaces atomically only after validation; on
failure previous output remains. API reads do not invoke DeepSeek. Evidence
digest mismatch or invalid cache falls back to deterministic analysis. Only model
review is applied to the current baseline; cached detection results never replace it.
Citation existence is validated, not semantic truth: human review remains required.

Backend currently supports one configured review file, so only its matching task
receives the supplement. Other tasks retain normal deterministic results. The
public API and TraceResult schema remain unchanged; details are in attribution.llm_review.
