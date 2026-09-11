# Attack Scenario Matrix

## Baseline Scenario

Purpose:
- Generate host logs, host behavior, and network traffic for malicious-attack traceability analysis in an isolated enterprise-style intranet.

Nodes:
- 01-Kali-Attacker: attack origin
- 03-DMZ-Web-Server: initial-access target
- 04-C2-Server: command-and-control simulation endpoint
- 05-Email-Server: phishing/mail-log evidence source
- 06-Core-Server: internal server and collection target
- 02-Windows-XP: office endpoint
- 07-Firewall-IDS: firewall and IDS event source
- 08-Internal-Switch-Sensor: switch/traffic telemetry source

## Evidence Matrix

| Attack stage | Source node | Target node | Expected evidence |
| --- | --- | --- | --- |
| Reconnaissance | 01 | 03,05,06 | ICMP/TCP flows, ARP records, service banners |
| Initial access | 01 | 03 | Web logs, process execution traces, source IP |
| C2 simulation | 03 | 04 | Periodic HTTP/DNS/ICMP-style traffic, server access logs |
| Lateral movement | 03 or 01 | 02,06 | Authentication logs, source IP, session timeline |
| Collection | 03 or 06 | 06 | File access, archive/staging behavior |
| Exfiltration simulation | 06 | 04 | Outbound transfer logs, flow records |
| Defense events | 07 | All | Firewall-style allow/deny records, IDS alerts |
| Switch telemetry | 08 | All | Network session and packet metadata |

## Data Fusion Requirements

Normalize all events into this minimum schema:

| Field | Meaning |
| --- | --- |
| timestamp_utc | Normalized event time |
| source_node | Source host or sensor |
| source_ip | Source IP address |
| source_user | User account when available |
| source_process | Process name or PID when available |
| destination_node | Destination host or service |
| destination_ip | Destination IP address |
| destination_port | Network port when available |
| event_type | auth, process, file, registry, network, alert, flow |
| entity | User, process, file, registry key, domain, IP, hash |
| raw_source | Original log file or sensor |
| attack_stage | ATT&CK-aligned stage |
| confidence | Detection confidence |

## Multi-Agent Analysis Roles

| Agent | Responsibility |
| --- | --- |
| Log Parser Agent | Parse Windows/Linux logs into the normalized schema |
| Time Alignment Agent | Correct clock skew and align event sequences |
| Entity Extraction Agent | Extract users, processes, files, IPs, domains, hashes |
| Session Reconstruction Agent | Rebuild login sessions and source paths |
| Host Behavior Agent | Build process/file behavior chains |
| Traffic Analysis Agent | Rebuild sessions and detect covert channels |
| ATT&CK Mapping Agent | Map evidence to tactics and techniques |
| Graph Correlation Agent | Build the attack relationship graph |
| Attribution Agent | Compare TTPs and infrastructure fingerprints |
