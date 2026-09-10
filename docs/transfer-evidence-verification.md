# Transfer evidence verification, 2026-09-11

This is controlled synthetic-data verification, not an intrusion claim.

All 21 original files in course-20260910T133450Z passed their existing SHA-256
manifest. Retrieved Web and Office synthetic source files match the hashes
recorded during that experiment. Original evidence was not rewritten.

- Web: receiver content UTF-8 bytes equal the source file bytes. The receiver
  record is normalized event `evt_c1c84af1c3a7ac575a3f1caa`.
- Office: receiver text equals the staged file after ignoring its UTF-8 BOM
  and trailing newlines, but the bytes differ. The old declared hash refers to
  the staged file, not transmitted text. Receiver event:
  `evt_6295ec5ca4ceb86e93dfe884`.
- Neither workflow uploaded its staged archive; both sent text in JSON.
  Archive exfiltration must not be inferred from a preceding archive operation.

The local Office exercise script now records `sha256` over the UTF-8 content,
separately records `source_file_sha256`, and declares `hash_scope=content_utf8`
and `transfer_kind=text_not_archive`. No shared application schema was changed.
The credential-bearing orchestration script remains outside GitHub.

Live validation `hashcheck-20260910T160711Z` sent the existing synthetic fixture
from Office to the isolated simulator. Sender hash, receiver-declared hash and
independently recomputed receiver-content hash agreed. A preliminary verification
attempt serialized a PowerShell extended string as an object; the verification
script was corrected to use plain text and rerun. This failed attempt is not
counted as successful transfer validation; its receiver record remains retained.

Local results: D:\AttackTraceLab\evidence\transfer-verification-20260911
contains source samples, verification.json, sender/receiver records and
live-verification.json. This follow-up was not imported as a new attack chain;
the application event count remains 922.

## Other inspection findings

The repository already has public-data validation code and a historical report
in correlation/PUBLIC_DATA_VALIDATION.md. The raw datasets and derived outputs
were not present in this checkout and have not been rerun in this checkpoint.
The historical report documents zero C&C recall on its two IoT-23 scenarios;
that limitation must remain visible in the final evaluation.

agents/service.py performs deterministic fingerprint/infrastructure/behavior
analysis. Merely calling these functions does not demonstrate LLM multi-agent
coordination. A configured model service and evidence-grounded evaluation remain
required; no remote model call was made in this checkpoint.
