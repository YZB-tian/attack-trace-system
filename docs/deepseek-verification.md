# DeepSeek integration verification

2026-09-11: explicit two-role review is implemented and live-tested on
`task_beacon-20260910T153854Z` (22 real controlled-experiment events).

- DeepSeek `deepseek-flash`: analyst then reviewer in separate request contexts.
  The final run made two requests totaling 5059 tokens, as reported by the API.
  An earlier integration run used 5050 tokens; neither run is a free/local model.
- Request minimization excludes raw logs, usernames, IP addresses, file contents,
  commands and original event/host IDs. Temporary event references are translated
  locally. Timestamps and action categories still leave the machine.
- Model findings cite supplied evidence, pass schema validation, and are explicitly
  supplemental hypotheses needing human review. Model calls cannot alter detected
  stages, alerts, initial-access identity or C2 identity.
- Backend trace API and browser display the review. Other task remains deterministic.
  Persisted event count remains 922. API refresh performs no model calls.
- 193 Python tests passed, one optional test skipped, one existing dependency warning.
  Existing public contract examples passed. Current actual TraceResult validated
  against the shared schema before the local result was published.
- Independent review identified stale-cache overwrite and original-ID privacy
  issues; both fixed with regression tests. Invalid/stale cache falls back to the
  current baseline, and only supplemental model review is applied.

Local result: `runtime/deepseek-review.json`; screenshot: `runtime/deepseek-ui.png`.
Neither credentials nor raw evidence are committed. The CLI reads local `.env`;
the server requires `ATS_LLM_REVIEW_FILE` in its process environment. Deployment
steps and limitations are in agents/README.md.

This closes the initial live-model integration gap, not the entire assignment.
Only one task review file is configured, at most 120 selected events per review,
and the two roles use the same model. Full-chain and public-dataset validation
remain separate. Citation existence checks cannot guarantee semantic correctness.
