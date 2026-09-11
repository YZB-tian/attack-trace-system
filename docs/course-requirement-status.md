# Course requirement acceptance status

Updated 2026-09-10 after the real-exploitation, covert-channel, kernel-monitor,
memory-injection and public-dataset work. This checklist separates what has
evidence from what still does not. It is not a claim that every requirement is
complete.

## Requirement matrix

| Assignment requirement | Evidence | Remaining acceptance |
| --- | --- | --- |
| Windows/Linux logs and normalization | Linux auth/syslog, Windows Security/Sysmon; time normalization with an explicit `metadata.time_basis` per event, entity extraction and login sessions with source IP (two real exploitation runs: 157 and 217 in-window Linux auth events) | Windows-side session timeline for the exploitation chain; measured cross-host clock skew |
| Kernel-wide syscall monitoring | bpftrace tracepoints (execve/openat/connect/sendto) on Ubuntu Web during a controlled post-exploitation sequence; 494-733 records per run (docs/kernel-monitor-verification.md) | Not full-call persistence; Metasploitable2 has no eBPF/auditd, so the exploited hosts have no syscall-level evidence |
| Process/file behaviour chains | `/proc` sampling on Kali, syscall evidence on Ubuntu, Sysmon ProcessCreate/ProcessAccess on Windows | No long-running process-tree baseline; PID reuse handling depends on visible creation events |
| Memory injection / reflective loading | Sysmon CreateRemoteThread + write-capable ProcessAccess on Windows Server 2025; `HOST-WIN-PROCESS-INJECTION` (T1055) alert (docs/memory-injection-verification.md) | Reflective loader not exercised; injection ran through the lab admin channel because the firewall allows no attack path into the server zone |
| Packet capture and network sessions | Sensor VMnet2 captures plus Zeek 7.0.11; the second exploitation run used a live sensor (`zeek -i ens160`) producing conn/dns/http/irc/ssh logs during the experiment | HTTPS is not decrypted; the sensor covers the VMnet2 segment only |
| DNS/HTTP/ICMP covert channels | Positive and negative controls for all three channels: positives raise `NET-DNS-TUNNEL`, `NET-HTTP-COVERT`, `NET-ICMP-TUNNEL`; negatives raise nothing (docs/covert-channel-verification.md) | Hand-built tunnels, not mature tools; no HTTPS body inspection; short encoded payloads are below the HTTP rule threshold |
| Complete intrusion chain using open-source tools | Two real exploitation runs: UnrealIRCd backdoor (CVE-2010-2075) via Metasploit, offline credential cracking, SSH lateral movement, sudo escalation, collection, C2 beaconing and real ~1.1 MB chunked exfiltration; the second run collects evidence with a dedicated `labforensics` account outside the attack window and excludes operator accounts in the rules (docs/exploit-chain-verification.md) | Kernel-level and memory evidence comes from companion runs (`docs/kernel-monitor-verification.md`, `docs/memory-injection-verification.md`) because the exploited images are 2.6.24 |
| ATT&CK and cross-host attack path | Official STIX bundle wired in; the runs produce initial-access T1190, lateral-movement T1021, privilege-escalation T1548, exfiltration T1041 and collection T1005 stages with evidence IDs; `initial_access_entity_id` resolves; the second run resolves the C2 through a lab DNS name, so `dns_query`/`http_request` events carry the C2 domain and the graph contains domain nodes and edges | Stage ordering is not asserted; APT similarity is behaviour similarity only (best 0.2, not attribution) |
| Attacker/APT matching | Deterministic fingerprints on the real chain (6 tool candidates, 8 IPs, 5 hosts, 4 techniques), C2 domain/IP correlation from the lab DNS and the receiver logs, and no APT match at confidence 0.0 | Tool fingerprints are keyword heuristics (chisel/cobalt_strike are unverified candidates); registry/WHOIS history does not exist for a self-built C2 and is not claimed |
| Collection-to-transfer tracing | `data_access_to_network_candidates` = 10 on the kernel-monitor task (same PID reads `/etc/shadow` then connects to the C2) | `content_transfer_proven` stays false; the exploit-chain hosts have no file-access telemetry |
| LLM multi-agent coordination | DeepSeek analyst + reviewer over the full exploit-chain task: 2 calls, 16,901 tokens, 4 findings; model cannot alter stages/alerts/identity; prompt excludes raw logs, IPs, usernames and commands | One model in two roles is not independent consensus; sampling capped at 120 events |
| Public enterprise attack dataset | OTRF Mordor APT29 Evals Day 1 (196,081 records, 39,831 converted, 8 candidate alerts in ~4 s) plus the earlier IoT-23 and RITA validations (docs/public-dataset-validation.md) | No per-event labels, so precision/recall are not computed; the T1218 candidates are unconfirmed either way |
| Open-source comparison / innovation | docs/open-source-comparison.md compares capability dimensions and states the claims that do **not** hold | No same-environment deployment comparison against RITA/Arkime/Security Onion |

## Verified application data

- `task_course-20260910T133450Z`: 900 controlled-emulation events.
- `task_beacon-20260910T153854Z`: 22 controlled-emulation events, one NET-BEACON.
- `task_exploit-chain-20260910T170757Z`: 556 events, 5 alerts, ATT&CK stages and a
  resolved initial-access entity; `-c2` scoped task adds one NET-BEACON.
- `task_exploit-chain-20260911T044921Z`: 738 events (zeek 416 / auth.log 217 /
  attack tooling 69 / C2 receiver 36), 5 alerts, initial-access T1190, and the C2
  reached through the lab DNS name `c2.attacktrace.lab`; the `-c2` scoped task
  adds one NET-BEACON over 11 stable 20-second beacons.
- `task_kernel-monitor-20260910T181500Z` / `...T183000Z`: 1145 / 929 events with
  kernel tracepoints; the second run yields 10 data-access-to-network candidates.
- `task_memory-injection-20260910T184200Z`: 38 Sysmon events, one T1055 candidate.
- `task_covert-positive-20260910T183500Z`: 675 events, all three tunnel rules；
  the paired negative task has 0 alerts.
- Public dataset: 8 candidate host alerts over APT29 Day 1 (1 T1055, 5 T1218, 2 T1003.001).

Raw evidence, credentials and public dataset copies stay local and are excluded
from Git (`runtime/`, `D:\AttackTraceLab\evidence`).

## Next acceptance order

1. Give the exploited Metasploitable2 hosts kernel-level collection (upgrade the
   image or add a third instrumented victim) so one chain has host-log,
   syscall, network and receiver evidence together.
2. Separate operator activity from attacker activity (dedicated evidence
   account) so lateral-movement and sudo candidates do not include forensics.
3. Tighten the T1055 rule (require write access plus a suspicious call trace)
   before using it on unlabelled enterprise data.
4. Add per-event labels or a second labelled dataset to report precision/recall
   instead of candidate counts.
