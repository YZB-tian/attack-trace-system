# Course requirement acceptance status

Verified against the supplied Word assignment on 2026-09-10. This checklist
distinguishes existing implementation from evidence actually obtained in the lab.
It is not a claim that all assignment requirements are complete.

## Current lab checkpoint

At approximately 15:53-15:57 UTC, eight current VMware nodes were running:
Kali, rebuilt Windows Office, Ubuntu Web, C2 simulator, SMTP service,
Windows Core, OPNsense and Ubuntu inline switch/sensor. Retired clones are not
counted. The Office node is `02-Windows11-Office-Rebuild`.

Fresh guest checks verified Office activation, Security log records and lab-only
IPv4 routes; Web/C2/SMTP services; Web and sensor capture services; two forwarding
office bridge ports. Kali guest management succeeded on retry, with lab-only
routes. Core guest management and Security logging worked. Core evaluation
remaining grace was 13637 minutes (about 9.5 days); do not bypass licensing.

Office-to-Core TCP445 connected and TCP3389 timed out after 2.5 seconds.
The latter is consistent with previous firewall evidence, but no fresh firewall
log was retrieved in this check. OPNsense was confirmed powered on; its internal
health/configuration was not independently re-audited here.

## Requirement matrix

| Assignment requirement | Evidence / current limit | Remaining acceptance |
| --- | --- | --- |
| Eight specified node roles | Eight current VMs; real inline office bridge | Final topology/config export and firewall health check |
| Windows/Linux logs and normalization | 900 first-run real events; Windows audit and Linux auth | Explicit login/logoff session timeline and source-IP validation |
| Time alignment | UTC-aware normalized timestamps; sequential current clock checks | Measured cross-host skew and documented common clock strategy |
| Kernel-wide syscall monitoring | strace covers exercise process and descendants only | Kernel-wide collector coverage is not demonstrated |
| Process and file behavior | Process/file audit and strace evidence | Verify process tree and sensitive-file path in application |
| Memory injection / reflective loading | No actual experiment evidence | Instrumentation and controlled validation remain unverified |
| Packet capture and network sessions | Original PCAP plus genuine Zeek conn/http logs | Validate session linkage across host and boundary sources |
| DNS/HTTP/ICMP covert channels | One periodic HTTP candidate, not proof of a covert channel | Separate positive/negative channel experiments required |
| Complete intrusion chain using open-source tools | Known-credential SSH and separately orchestrated Office actions | No actual vulnerability exploitation, privilege escalation or causal lateral compromise established |
| ATT&CK and cross-host attack path | Entity evidence graph is available | Real-data stage mappings and causal path validation remain incomplete |
| Collection-to-transfer tracing | Synthetic staging/transfer records exist | Demonstrate linked file/process/session/receiver evidence in UI |
| Attacker/APT matching | Controlled lab infrastructure only | No justified real identity/APT attribution; evaluate matching separately |
| LLM multi-agent coordination | Not exercised by deterministic data-import path | Inspect configured agent workflow and validate on real evidence |
| Public enterprise attack dataset | No public-data benchmark verified in this checkpoint | Provenance/licensing, benchmark import and analysis required |
| Open-source comparison / innovation | Not established by lab construction | Evaluation table and defensible comparison required |

## Verified application data

- `task_course-20260910T133450Z`: 900 events; controlled separately orchestrated
  workflows, not a full compromise chain.
- `task_beacon-20260910T153854Z`: 22 events, one NET-BEACON candidate, 11 evidence
  connections over approximately 200 seconds. Existing thresholds unchanged.
- Combined local persisted store: 922 events. Raw evidence is local and excluded
  from GitHub. See real-lab-verification.md for test results and paths.

## Next acceptance order

1. Verify existing process, login-session, file-to-transfer and receiver links
   before generating more copies of already covered data.
2. Implement or validate the missing collection/detection scenarios separately;
   label simulation, real observation and inference explicitly.
3. Validate the required complete intrusion scenario only inside isolated lab
   targets; existing emulation must not be presented as exploitation evidence.
4. Validate public-dataset and multi-agent requirements and produce the final
   comparison/acceptance report. A working lab alone does not satisfy these.
