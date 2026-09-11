# AttackTraceLab Requirement Fit

## 1. Safety Boundary

- Hypervisor: VMware Workstation
- Isolated network: VMnet2 Host-only
- Lab subnet: 192.168.56.0/24
- Host VMnet2 adapter: 192.168.56.1/24
- DHCP: disabled
- Bridged networking: prohibited for intentionally vulnerable VMs
- Real host LAN adapters: not modified

VMware host network check:

| Network | Type | DHCP | Subnet | Mask |
| --- | --- | --- | --- | --- |
| vmnet1 | hostOnly | true | 192.168.171.0 | 255.255.255.0 |
| vmnet2 | hostOnly | false | 192.168.56.0 | 255.255.255.0 |
| vmnet8 | nat | true | 192.168.74.0 | 255.255.255.0 |

## 2. Required 8-Node Role Mapping

| Required role | Lab node | IP | Implementation status |
| --- | --- | --- | --- |
| Attack node | 01-Kali-Attacker | 192.168.56.10 | Implemented |
| Internal office computer | Windows XP Professional | 192.168.56.20 | Implemented |
| Web server | 03-DMZ-Web-Server | 192.168.56.30 | Implemented with Metasploitable2 web services |
| C2 server | 04-C2-Server | 192.168.56.40 | Implemented as isolated C2 simulation node |
| Email server | 05-Email-Server | 192.168.56.50 | Implemented with Metasploitable2 mail-service role |
| Core server in server area | 06-Core-Server | 192.168.56.60 | Implemented with Metasploitable2 database/file-service role |
| Firewall | 07-Firewall-IDS | 192.168.56.70 | Implemented as firewall/IDS/log-source simulation node |
| Internal switch | 08-Internal-Switch-Sensor | 192.168.56.80 | Implemented as switch telemetry/traffic-sensor simulation node; VMnet2 is the actual L2 switch fabric |

## 3. Data Sources for the Traceability System

Windows host logs:
- Node 02 provides Windows XP logon/logoff, process, service, and network artifacts.
- Use this node for login-session reconstruction, office-host compromise traces, and lateral movement evidence.

Linux host logs:
- Nodes 03-08 provide Linux authentication, service, web, mail, database, file-service, and system logs.
- Use these nodes for time-series alignment, normalization, entity extraction, and attack-stage mapping.

Host behavior:
- Kali provides attack tool execution behavior.
- Windows XP provides office-host behavior and login-session evidence.
- Metasploitable2-based service nodes provide process, file, service, and network artifacts around exploitation and post-exploitation.

Network traffic:
- VMnet2 isolates all attack and victim traffic inside 192.168.56.0/24.
- Host-side ARP and ping validation confirms all nodes are reachable through the isolated network.
- Node 08 is reserved as the network/switch telemetry and packet-capture analysis role.
- Node 07 is reserved as the firewall/IDS event source role.

## 4. Attack Chain Validation Design

The lab supports an end-to-end traceability test chain:

1. Reconnaissance
   - Source: 01-Kali-Attacker
   - Targets: 03-DMZ-Web-Server, 05-Email-Server, 06-Core-Server
   - Evidence: network scans, ARP entries, service logs
   - ATT&CK mapping: Discovery

2. Initial access
   - Target: 03-DMZ-Web-Server
   - Evidence: web access logs, authentication traces, spawned process relationships
   - ATT&CK mapping: Initial Access, Execution

3. Command and control simulation
   - C2 node: 04-C2-Server
   - Evidence: HTTP/DNS/ICMP-style beacon simulation traffic and server-side logs
   - ATT&CK mapping: Command and Control

4. Credential access and lateral movement
   - Source: 03-DMZ-Web-Server or 01-Kali-Attacker
   - Targets: 02-Windows-XP, 06-Core-Server
   - Evidence: login events, source IP correlation, SMB/SSH/RPC-style traces
   - ATT&CK mapping: Credential Access, Lateral Movement

5. Collection and staging
   - Target: 06-Core-Server
   - Evidence: file access, process tree, service logs
   - ATT&CK mapping: Collection

6. Exfiltration simulation
   - Destination: 04-C2-Server
   - Evidence: outbound transfer simulation, flow records, server logs
   - ATT&CK mapping: Exfiltration

7. Attribution and graph reconstruction
   - Inputs: host logs, process/file/network events, ARP, flow records, service logs
   - Outputs: entity graph, attack path, ATT&CK stage timeline, attacker infrastructure links

## 5. Current Validation Results

Ping validation from host VMnet2:

| IP | Node | Result |
| --- | --- | --- |
| 192.168.56.10 | 01-Kali-Attacker | OK |
| 192.168.56.20 | Windows XP Professional | OK |
| 192.168.56.30 | 03-DMZ-Web-Server | OK |
| 192.168.56.40 | 04-C2-Server | OK |
| 192.168.56.50 | 05-Email-Server | OK |
| 192.168.56.60 | 06-Core-Server | OK |
| 192.168.56.70 | 07-Firewall-IDS | OK |
| 192.168.56.80 | 08-Internal-Switch-Sensor | OK |

ARP validation from host VMnet2:

| IP | MAC |
| --- | --- |
| 192.168.56.10 | 00-0c-29-18-77-51 |
| 192.168.56.20 | 00-0c-29-5b-87-6d |
| 192.168.56.30 | 00-0c-29-2b-7f-b9 |
| 192.168.56.40 | 00-0c-29-0c-9f-24 |
| 192.168.56.50 | 00-0c-29-a7-89-6d |
| 192.168.56.60 | 00-0c-29-9b-70-07 |
| 192.168.56.70 | 00-0c-29-62-b4-3e |
| 192.168.56.80 | 00-0c-29-63-7e-ef |

VMX network validation:
- All 8 nodes are attached to custom VMnet2.
- Bad NAT or bridged binding count: 0.

## 6. High-Fidelity Upgrade Path

The current lab satisfies the minimum isolated 8-node role requirement and is suitable for traceability-system data collection and attack-chain validation.

For a more realistic enterprise boundary topology, add these upgrades only after explicit confirmation:
- Add extra host-only VMware networks for zones, such as DMZ and internal server area.
- Convert 07-Firewall-IDS into a dual-NIC inline firewall/router.
- Replace clone nodes with distinct vulnerable images, such as a dedicated mail server, firewall appliance, AD-style Windows server, and traffic sensor.
- Downloading any new vulnerable image, C2 framework, or packet dataset must be confirmed before the download starts.
