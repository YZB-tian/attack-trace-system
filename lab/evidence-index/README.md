# Published evidence index

This is the publishable slice of the laboratory evidence: the derived analysis
output of every run, the manifests that hash the original captures, and the live
Zeek logs from the second exploitation run. Raw captures, EVTX exports, shadow
dumps and recovered passwords stay on the operator machine (see
`../images-and-datasets.md` and the repository `.gitignore`).

`file-list.json` records the exact file list with size and SHA-256 for every file
below.

| Directory | Events | Alerts produced |
| --- | ---: | --- |
| `exploit-chain/` | 556 | NET-IRC-BACKDOOR-EXPLOIT, HOST-LINUX-INTERNAL-SSH-LOGIN, HOST-LINUX-SUDO-TO-ROOT, NET-INTERNAL-SENSITIVE-UPLOAD |
| `exploit-chain-c2-window/` | 44 | NET-BEACON, HOST-LINUX-INTERNAL-SSH-LOGIN |
| `exploit-chain2/` | 738 | NET-IRC-BACKDOOR-EXPLOIT, HOST-LINUX-INTERNAL-SSH-LOGIN, HOST-LINUX-SUDO-TO-ROOT, NET-INTERNAL-SENSITIVE-UPLOAD |
| `exploit-chain2-c2window/` | 89 | NET-BEACON, HOST-LINUX-INTERNAL-SSH-LOGIN, HOST-LINUX-SUDO-TO-ROOT |
| `kernel-monitor/` | 1145 | HOST-LINUX-SUDO-TO-ROOT, HOST-LINUX-SENSITIVE-FILE-ACCESS |
| `kernel-monitor2/` | 929 | HOST-LINUX-SUDO-TO-ROOT, HOST-LINUX-SENSITIVE-FILE-ACCESS |
| `memory-injection/` | 38 | HOST-WIN-PROCESS-INJECTION |
| `covert-positive/` | 675 | NET-DNS-TUNNEL, NET-HTTP-COVERT, NET-ICMP-TUNNEL, NET-BEACON |
| `covert-negative/` | 226 | none (negative control) |
| `beacon-20260910T153854Z/` | 22 | NET-BEACON (earlier controlled experiment) |
| `lab/` | 922 | none (first controlled batch) |
| `public-apt29/` | - | HOST-WIN-PROCESS-INJECTION, HOST-WIN-LSASS-MEMORY-ACCESS, HOST-WIN-LOLBIN-EXECUTION (8 candidates over 196,081 records) |
| `network-zeek-live/` | - | live sensor logs from the second run: conn/dns/http/irc/ssh |
| `combined-store/` | 5362 | the merged persisted store, 11 tasks |
| `evidence-manifests/` | - | the origin SHA-256 manifests of each raw evidence package |

Each run directory keeps the same four artefacts where they exist:
`normalized_events.json` (the shared event objects), `alerts.json`,
`attack_graph.json` and `trace_result.json`.

## Redactions

Sixteen occurrences in three files were replaced by `<redacted-credential>`:
they are raw `auth.log`/`syslog` lines that record the operator creating the
forensics account (`... echo 'labforensics:<password>' | chpasswd`) inside the
first controlled batch and the second exploitation run. Only the secret itself
was replaced; the command, user, timestamps, event IDs and every other field are
unchanged, so the derived analysis is the same as the original run.

## Deliberately excluded

| Excluded | Why | How to regenerate |
| --- | --- | --- |
| Raw `*.pcap`, `*.pcapng` | contain the plaintext configuration sessions and lab credentials | re-capture the exercise; the importer only needs Zeek logs |
| `*.evtx`, shadow dumps, john output | host secrets and password hashes | re-export from the lab hosts after a run |
| `covert-positive/attack_graph.json` (43.6 MB) and `kernel-monitor2/attack_graph.json` (26.4 MB) | large derived files, reproducible in seconds | re-run the matching `scripts/import_*.py` command in `docs/covert-channel-verification.md` / `docs/kernel-monitor-verification.md` |
| VM disks, ISOs, Mordor dataset, STIX bundle, Zeek package | 1.9 GB - 20 GB per file, or third-party downloads | see `../images-and-datasets.md` for sources and SHA-256 |
