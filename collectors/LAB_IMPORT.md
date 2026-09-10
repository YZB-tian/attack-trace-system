# Local course evidence import

Input: a course evidence directory with manifest.json, office-timeline.json and
sha256-manifest.json. Output: shared NormalizedEvent objects and a local import
report. Public schemas and endpoint paths are unchanged.

From the repository root:

```powershell
python -m pip install -r requirements.txt
python scripts/import_lab.py --evidence-dir D:\AttackTraceLab\evidence\course-20260910T133450Z --output runtime/lab
$env:ATS_EVENTS_FILE = "$PWD/runtime/lab/normalized_events.json"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Run the frontend using its README. The first available task is selected
automatically. A task can also be selected with `?task=task_course-20260910T133450Z`.

The API is for trusted local use only: no authentication, one process/worker.
ATS_EVENTS_FILE enables persistence and startup analysis. Without it the API is
memory-only. A failed batch commits nothing. Never point it at original evidence.
The importer output is a snapshot: do not overwrite a running server's store;
for another collection, normalize to a separate directory and POST those events
to the existing /api/events endpoint, then keep using the server's store.

Supported inputs: nested Windows Security JSON exports, OPNsense live JSON
(explicit +08:00 interpretation of naive timestamps), service JSONL, Linux auth,
strace completed numeric-return records, Scapy TCP/UDP directional observations.
Every imported event retains file/hash/record provenance. Original source files
are never edited. Hashes verify consistency with the local manifest, not signed
authenticity. Evidence must remain immutable during import.

The exact manifest start through Office completion bounds the import. Historical
rows are excluded. Same-window administrative activity can remain: membership
is not a claim of attacker causality. PCAP aggregates directional five-tuples,
does not reconstruct TCP sessions or claim connection success, and does not
count captured bytes as application payload. Unsupported packets/strace lines
are counted. EVTX originals, orchestrator reports and other files remain archived
and are listed as not normalized; EVTX/PowerShell contents are not silently read.

The lab has eight configured assets; evidence-producing hosts and observer
nodes are different concepts. Office actions were separately orchestrated;
Web-to-Office compromise, real escalation, injection, full intrusion and live
LLM multi-agent analysis are not verified. Zero alerts is a valid detector
result, not proof of no attack, and no alerts are fabricated from scenario labels.

Normalized/raw evidence can contain credentials and must stay in ignored runtime
directories, not GitHub. Synthetic regression examples are in tests/test_lab_import.py.

```powershell
python -m pytest -q
python scripts/validate_contracts.py
```
