# Real lab integration verification (2026-09-10)

Scope: first-stage integration, not completion of all course requirements.
Public models, schemas and API paths are unchanged. Eight asset IDs are retained;
actual addresses/Windows hostnames and OS types replace example configuration.

Local bundle: course-20260910T133450Z, controlled_emulation.
All 21 manifest-listed files passed size and SHA-256 verification before import.
Window: 2026-09-10T13:34:50.236330Z through 13:35:14.676690Z.

| Source | Imported events |
| --- | ---: |
| Windows Security JSON exports | 53 |
| Linux auth.log | 13 |
| Completed numeric-return strace records | 763 |
| Lab service records | 17 |
| OPNsense boundary records | 26 |
| Directional PCAP observations | 28 |
| Total | 900 |

Excluded: 1,242 parsed records outside the window, 16 records from other run IDs,
116 out-of-window packets. Unparsed: one auth line, 11 strace lines, ten
unsupported packets. Nine files retained but not normalized are listed in the
local import report (including EVTX originals and orchestrator reports).

Observed subject host IDs: seven. The switch/sensor is capture-observer metadata,
not an eighth compromised host. No fabricated event is added to make eight.

Current default detector output: **zero alerts and zero candidate attack paths**.
The evidence graph contains 1,721 nodes and 2,005 edges, not 1,721 physical hosts.
This validates ingestion and evidence display, not detection recall or a complete
attack-chain reconstruction. Additional experiments/rule evaluation remain needed.

Checks performed:
- Python: 185 passed, one existing optional test skipped; one dependency deprecation warning.
- Frontend: 19 tests passed; production build passed.
- Existing contract examples passed; 903 actual API objects passed JSON schemas.
- Repeated real POST accepted zero new records, total remained 900.
- Restart restored the data; persistence and failure rollback have regression tests.
- Browser: actual task auto-selection, no empty-task HTTP requests, source/hash
  details, trace scope, graph node inspector, desktop and 390px layouts checked.
- Independent review found a Windows subject/target logon mismatch; fixed and tested.

Raw/normalized evidence and screenshots remain local under ignored directories.
No credentials, raw EVTX, PCAP or private log payloads are included in this commit.
See collectors/LAB_IMPORT.md for reproducible import and run commands.
