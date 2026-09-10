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

First-run default detector output: **zero alerts and zero candidate attack paths**.
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

## Follow-up: bounded periodic communication

Run `beacon-20260910T153854Z` is a separate controlled experiment, not an
extension of the first run's time window. Evidence remains local at
`D:\AttackTraceLab\evidence\beacon-20260910T153854Z`.

- Web `192.168.60.30` sent 11 benign HTTP POST requests to the existing lab
  simulator `192.168.56.40:8080/beacon`, at 20-second intervals. All returned 200.
- Actual connection window: 2026-09-10 15:38:56 to 15:42:16 UTC, approximately
  200 seconds. tcpdump captured 132 packets and reported zero kernel drops.
- Zeek 7.0.11 parsed the PCAP offline with JSON logging and `-C` (skip checksum
  validation for virtualized capture). The PCAP was not fabricated or relabeled.
- The existing Zeek adapter produced 11 connection and 11 HTTP events. Existing
  default rules, with no threshold changes, produced one `NET-BEACON` alert,
  backed by all 11 connection events. Median interval was approximately 20s.
- This is a periodic-communication candidate, **not proof of malicious C2 or a
  successful compromise**. The rule has no MITRE technique assignment. This
  experiment does not establish a complete attack chain or eight compromised nodes.
- Shared JSON schemas validated all 22 events, the alert, graph and trace.
  API ingestion accepted 22 events; combined local store contains 922. Repeating
  the same ingestion accepted zero events. Existing 900 events remain intact.
- Browser verification showed the separate task, 22 events, one alert, controlled
  experiment notice and 11 evidence references. Screenshot is retained locally
  at `runtime/beacon-alert.png`. Python regression: 185 passed, one skipped.

The evidence directory contains the PCAP, request results, capture statistics,
Zeek conn/http logs, capture script, version record and SHA-256 manifest.
Derived normalized events, alert, graph and trace are in
`runtime/beacon-20260910T153854Z`. No raw evidence or credentials are published.
