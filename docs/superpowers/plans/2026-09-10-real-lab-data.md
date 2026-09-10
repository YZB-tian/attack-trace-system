# Real lab data integration

Approved scope: use existing controlled-emulation evidence before collecting
additional experiments. Preserve public contracts and eight asset IDs. Raw
evidence and credentials stay local; publish code and reproducible instructions.

1. Add regression tests for empty API, atomic ingestion, and Windows exports.
2. Implement verified, time-bounded lab import with stable source references.
   Reuse Windows/Linux adapters; parse PCAP with Scapy, never call it Zeek.
3. Persist successful event batches locally; rebuild analysis on startup.
4. Select actual tasks in the UI; disclose controlled-emulation limitations.
5. Validate contracts, Python/frontend tests, real import and HTTP/UI roundtrip.
6. Commit and push feat/real-lab-data, without raw or normalized private logs.

Acceptance: repeat imports do not duplicate evidence; hash mismatches fail;
failed batches do not partially commit; no mock fallback; raw source provenance
is retained; unsupported evidence formats and scope gaps are reported.

Not included: real compromise, privilege escalation, memory injection, proven
Web-to-Office compromise, complete eight-node intrusion, live multi-agent LLM,
or calibrated attacker attribution. Existing captures alone cannot prove these.
