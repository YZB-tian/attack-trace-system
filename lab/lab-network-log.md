# AttackTraceLab Network Log

## 2026-09-09 19:13:50 +08:00 - Pre-change inspection

Target lab network:
- VMware network: VMnet2 Host-only
- Target subnet: 192.168.56.0/24
- Existing nodes: Kali 192.168.56.10, Windows XP 192.168.56.20

Current VMware virtual adapters:
- VMware Network Adapter VMnet1: 192.168.171.1/24, up
- VMware Network Adapter VMnet8: 192.168.74.1/24, up
- VMware Network Adapter VMnet2: 169.254.184.237/16, up

Current route observations:
- 192.168.56.0/24 is currently routed through interface "以太网 4".
- Interface "以太网 4" is VirtualBox Host-Only Ethernet Adapter with 192.168.56.1/24.
- VMnet2 currently has only an APIPA route, not the target 192.168.56.0/24 route.

Existing VM network bindings:
- D:\AttackTraceLab\VMs\01-Kali-Attacker\01-Kali-Attacker.vmx
  - displayName: 01-Kali-Attacker
  - ethernet0.connectionType: custom
  - ethernet0.vnet: VMnet2
  - ethernet0.displayName: VMnet2
  - result: not bridged
- D:\winxp\winxp\Windows XP Professional.vmx
  - displayName: Windows XP Professional
  - ethernet0.connectionType: custom
  - ethernet0.vnet: VMnet2
  - ethernet0.displayName: VMnet2
  - result: not bridged

Runtime observations:
- vmrun list: Total running VMs: 0
- ARP:
  - 192.168.56.255 broadcast entry on "以太网 4"
  - no observed Kali or Windows XP ARP entries during this inspection
- Ping:
  - not tested because no listed VMware VMs were running and VMnet2 is not yet on the target subnet.

Metasploitable2 source status:
- No Metasploitable2 VM/OVA/OVF was found under D:\AttackTraceLab during targeted inspection.
- Wider filesystem search was stopped after it exceeded the practical wait time.

Blocker before changing VMware network:
- The requested subnet 192.168.56.0/24 is already assigned to a VirtualBox Host-Only adapter.
- Changing VMnet2 to the same subnet would create overlapping host routes unless the VirtualBox adapter is changed or disabled, which is a host network change and requires explicit user confirmation.

## 2026-09-09 - Attempted conflict resolution

User confirmation:
- User allowed handling the VirtualBox Host-Only adapter conflict.

Planned limited change:
- Move VirtualBox Host-Only Ethernet Adapter "以太网 4" from 192.168.56.1/24 to 192.168.57.1/24.
- Assign VMware Network Adapter VMnet2 to 192.168.56.1/24.
- Do not modify physical adapters or real LAN configuration.

Result:
- Windows rejected the adapter IP change with "Access denied".
- Follow-up inspection confirmed no partial change occurred.

Post-attempt state:
- "以太网 4" remains 192.168.56.1/24.
- "VMware Network Adapter VMnet2" remains 169.254.184.237/16.
- 192.168.56.0/24 remains routed through "以太网 4".

Next required action:
- Run the network change from an elevated/admin context, or manually change the two virtual adapters:
  - VirtualBox Host-Only Ethernet Adapter "以太网 4": move to 192.168.57.1/24 or disable if unused.
  - VMware Network Adapter VMnet2: set to 192.168.56.1/24.

## 2026-09-09 - Node 03 import: Metasploitable2

Source:
- Found existing source at D:\build\Metasploitable2-Linux.

Import action:
- Copied source VM to D:\AttackTraceLab\VMs\03-Metasploitable2.
- Updated copied VM displayName to "03-Metasploitable2".

Isolation changes:
- Original source VM had ethernet0.connectionType = "nat" and ethernet1.connectionType = "hostonly".
- Copied VM was changed so ethernet0 is custom VMnet2.
- Copied VM was changed so ethernet1 is disabled.
- Verification found no remaining NAT, bridged, or VMnet0/VMnet1/VMnet8 network bindings in the copied VMX.

Runtime:
- Started D:\AttackTraceLab\VMs\03-Metasploitable2\Metasploitable.vmx.
- Started existing Kali and Windows XP nodes for validation.
- vmrun list showed 3 running VMs:
  - D:\AttackTraceLab\VMs\01-Kali-Attacker\01-Kali-Attacker.vmx
  - D:\winxp\winxp\Windows XP Professional.vmx
  - D:\AttackTraceLab\VMs\03-Metasploitable2\Metasploitable.vmx

Validation status:
- IP: pending inside Metasploitable2. Intended address: 192.168.56.30/24.
- Route: pending inside Metasploitable2.
- ARP: pending inside Metasploitable2.
- Ping: pending from Metasploitable2 to Kali 192.168.56.10 and Windows XP 192.168.56.20.

Current blockers:
- Host VMnet2 still cannot be assigned 192.168.56.1/24 from the current non-admin process.
- VMware Tools/guest API is unavailable or not accepting guest operations for Metasploitable2.
- Automated keyboard input into the VMware console did not enter the guest login prompt from this process.

## 2026-09-09 - Node 03 offline static IP patch

Additional action:
- Stopped 03-Metasploitable2.
- Converted the copied Metasploitable2 VMDK to a monolithic sparse working copy:
  - D:\AttackTraceLab\VMs\03-Metasploitable2\converted\Metasploitable-growable.vmdk
- Patched the copied disk image's /etc/network/interfaces content in place.
- Updated the copied VMX to boot from the patched disk:
  - scsi0:0.fileName = "converted/Metasploitable-growable.vmdk"

Patched guest network configuration:
- auto lo
- iface lo inet loopback
- auto eth0
- iface eth0 inet static
- address 192.168.56.30
- netmask 255.255.255.0

Patch verification:
- The patched disk no longer contains "iface eth0 inet dhcp" in the target interfaces block.
- The patched disk contains "iface eth0 inet static" and "address 192.168.56.30".
- The VMX still has no NAT, bridged, VMnet0, VMnet1, or VMnet8 binding.

Post-patch runtime:
- Started 03-Metasploitable2 again.
- vmrun list showed Kali, Windows XP, and 03-Metasploitable2 running.
- VMware guest IP query succeeded for:
  - Kali: 192.168.56.10
  - Windows XP: 192.168.56.20
- VMware guest IP query for 03-Metasploitable2 did not return, consistent with missing/unknown VMware Tools.

Validation attempts from host:
- Host route table still routes 192.168.56.0/24 through VirtualBox Host-Only adapter "以太网 4".
- VMnet2 still has 169.254.184.237/16 on the host side.
- ping -S 169.254.184.237 to 192.168.56.30, 192.168.56.10, and 192.168.56.20 failed with "General failure".
- VMware vnetsniffer did not start in the current non-admin context.

Remaining validation gap:
- Guest-to-guest ARP and ping should be validated after the host VMnet2 route conflict is resolved or after obtaining guest command access to Kali/Windows XP.

## 2026-09-09 20:06 +08:00 - VMnet2 conflict resolved and node 03 validated

Admin network change:
- Updated the network script to identify adapters by InterfaceDescription and ifIndex, avoiding localized interface-name encoding issues.
- Ran the script from an elevated PowerShell process.

Post-change host adapter state:
- VirtualBox Host-Only Ethernet Adapter: moved to 192.168.57.1/24.
- VMware Network Adapter VMnet2: set to 192.168.56.1/24.

Post-change route state:
- 192.168.56.0/24 now routes through VMware Network Adapter VMnet2.
- 192.168.57.0/24 now routes through the VirtualBox Host-Only adapter.

VMware host network state:
- vmnet2 type: hostOnly
- vmnet2 DHCP: false
- vmnet2 subnet: 192.168.56.0
- vmnet2 mask: 255.255.255.0

Running VM state:
- Total running VMs: 3
- D:\AttackTraceLab\VMs\01-Kali-Attacker\01-Kali-Attacker.vmx
- D:\winxp\winxp\Windows XP Professional.vmx
- D:\AttackTraceLab\VMs\03-Metasploitable2\Metasploitable.vmx

IP validation:
- Kali: 192.168.56.10, confirmed by VMware guest IP query.
- Windows XP: 192.168.56.20, confirmed by VMware guest IP query.
- Metasploitable2: 192.168.56.30, confirmed by successful ping and ARP entry after offline static IP patch.

Ping validation from host VMnet2:
- 192.168.56.10: 2 sent, 2 received, 0% loss, time <1 ms.
- 192.168.56.20: 2 sent, 2 received, 0% loss, time <1 ms.
- 192.168.56.30: 2 sent, 2 received, 0% loss, time <1 ms.

ARP validation on host VMnet2:
- 192.168.56.10 -> 00-0c-29-18-77-51
- 192.168.56.20 -> 00-0c-29-5b-87-6d
- 192.168.56.30 -> 00-0c-29-2b-7f-b9
- 192.168.56.255 -> ff-ff-ff-ff-ff-ff

Isolation status:
- The three current lab nodes are attached to VMware VMnet2.
- Metasploitable2 has no NAT or bridged adapter in its copied VMX.

## 2026-09-09 - Nodes 04-08 expansion and validation

Source decision:
- No additional local OVA/OVF/VMX vulnerable lab images were found under the checked local paths.
- To avoid starting an unconfirmed download, nodes 04-08 were created as isolated Metasploitable2 clone targets.
- The original Metasploitable2 source directory was used as the source for each new node, not the running node 03 disk.

Created nodes:
- 04-Metasploitable2-Clone: 192.168.56.40
- 05-Metasploitable2-Clone: 192.168.56.50
- 06-Metasploitable2-Clone: 192.168.56.60
- 07-Metasploitable2-Clone: 192.168.56.70
- 08-Metasploitable2-Clone: 192.168.56.80

Per-node static IP method:
- Converted each copied Metasploitable2 VMDK into a local monolithic sparse working disk.
- Patched each copied disk's /etc/network/interfaces block from DHCP to a static IP.
- Updated each copied VMX to boot from its patched working disk.

Per-node isolation verification:
- 04-Metasploitable2-Clone: Bad NAT/bridge binding count 0.
- 05-Metasploitable2-Clone: Bad NAT/bridge binding count 0.
- 06-Metasploitable2-Clone: Bad NAT/bridge binding count 0.
- 07-Metasploitable2-Clone: Bad NAT/bridge binding count 0.
- 08-Metasploitable2-Clone: Bad NAT/bridge binding count 0.
- All five new nodes have ethernet0 custom VMnet2.
- All five new nodes have ethernet1 disabled.

Per-node launch and ping validation from host VMnet2:
- 192.168.56.40: 2 sent, 2 received, 0% loss, average 2 ms.
- 192.168.56.50: 2 sent, 2 received, 0% loss, average <1 ms.
- 192.168.56.60: 2 sent, 2 received, 0% loss, average <1 ms.
- 192.168.56.70: 2 sent, 2 received, 0% loss, average <1 ms.
- 192.168.56.80: 2 sent, 2 received, 0% loss, average <1 ms.

Final 8-node ping validation from host VMnet2:
- 192.168.56.10: 2 sent, 2 received, 0% loss.
- 192.168.56.20: 2 sent, 2 received, 0% loss.
- 192.168.56.30: 2 sent, 2 received, 0% loss.
- 192.168.56.40: 2 sent, 2 received, 0% loss.
- 192.168.56.50: 2 sent, 2 received, 0% loss.
- 192.168.56.60: 2 sent, 2 received, 0% loss.
- 192.168.56.70: 2 sent, 2 received, 0% loss.
- 192.168.56.80: 2 sent, 2 received, 0% loss.

Final ARP validation on host VMnet2:
- 192.168.56.10 -> 00-0c-29-18-77-51
- 192.168.56.20 -> 00-0c-29-5b-87-6d
- 192.168.56.30 -> 00-0c-29-2b-7f-b9
- 192.168.56.40 -> 00-0c-29-0c-9f-24
- 192.168.56.50 -> 00-0c-29-a7-89-6d
- 192.168.56.60 -> 00-0c-29-9b-70-07
- 192.168.56.70 -> 00-0c-29-62-b4-3e
- 192.168.56.80 -> 00-0c-29-63-7e-ef
- 192.168.56.255 -> ff-ff-ff-ff-ff-ff

Final route validation:
- 192.168.56.0/24 routes through VMware Network Adapter VMnet2.
- VMnet2 host adapter is 192.168.56.1/24.

Final runtime state:
- Total running VMs: 8.
- Current lab target count: 8 nodes.

VMware Workstation library registration:
- Opened node 04-08 VMX files once in VMware Workstation.
- Inventory now includes:
  - 04-Metasploitable2-Clone
  - 05-Metasploitable2-Clone
  - 06-Metasploitable2-Clone
  - 07-Metasploitable2-Clone
  - 08-Metasploitable2-Clone

## 2026-09-09 - Requirement-oriented role adaptation

User requirement:
- The lab must satisfy the experiment requirement for a malicious attack traceability system.
- Required roles include attacker, C2 server, firewall, web server, email server, internal switch, office endpoint, and core internal server.

Role mapping applied:
- 01-Kali-Attacker: attack node, 192.168.56.10.
- Windows XP Professional: internal office endpoint, 192.168.56.20.
- 03-DMZ-Web-Server: web server, 192.168.56.30.
- 04-C2-Server: C2 simulation endpoint, 192.168.56.40.
- 05-Email-Server: email-service evidence node, 192.168.56.50.
- 06-Core-Server: internal server-area core server, 192.168.56.60.
- 07-Firewall-IDS: firewall/IDS event-source node, 192.168.56.70.
- 08-Internal-Switch-Sensor: internal switch telemetry and traffic-sensor node, 192.168.56.80.

Files added:
- D:\AttackTraceLab\lab-requirement-fit.md
- D:\AttackTraceLab\attack-scenario-matrix.md
- D:\AttackTraceLab\verify-lab.ps1

Final requirement-fit validation:
- VMnet2 remains host-only on 192.168.56.0/24.
- Host VMnet2 adapter remains 192.168.56.1/24.
- All 8 nodes are running.
- All 8 node IPs respond to ping.
- ARP entries exist for all 8 node IPs on host VMnet2.
- VMX isolation check shows BadNatOrBridge = 0 for all 8 nodes.

Known modeling note:
- VMnet2 is the actual isolated layer-2 switch fabric.
- Node 08 represents switch telemetry and traffic-sensor data.
- Node 07 represents firewall and IDS data in the current single-subnet model.
- A higher-fidelity inline firewall with segmented DMZ/office/server zones would require additional host-only VMnets and another explicit confirmation before changing VMware network settings.

## 2026-09-10 - High-fidelity lab rebuild started

Safety and network state before installation:
- VMnet2 remains host-only on 192.168.56.0/24 with DHCP disabled.
- Host VMnet2 adapter remains 192.168.56.1/24.
- No bridged adapter was added and no physical host adapter was changed.
- New VMs are being created under D:\AttackTraceLab\VMs-v2 without overwriting the existing eight-node prototype.

Installation media finalized and hashed:
- Ubuntu Server 24.04.4 LTS: 3,405,469,696 bytes; SHA256 E907D92EEEC9DF64163A7E454CBC8D7755E8DDC7ED42F99DBC80C40F1A138433 (matches the official published value).
- Windows Server 2025 Evaluation zh-CN: 8,423,151,616 bytes; SHA256 855176CFB446A3561DC36E81110774E57FD2BB0FA6CCD8A14978662F9F47FD03.
- Windows 11 Enterprise 25H2 Evaluation zh-CN: 7,371,034,624 bytes; SHA256 7B4AC87391B659F7724229682B642256289A1C00504056249F0F12029157D3D2.
- OPNsense 26.7 DVD archive: 494,298,945 bytes; SHA256 95CAFEDDA6D5B22CE832E249DC2309110FBEE19F813AD78CF28BB3D387186BFB (matches the official published value).

OPNsense VM status (initial installation stage; superseded by the validation below):
- New VM path: D:\AttackTraceLab\VMs-v2\07-OPNsense-Firewall\07-OPNsense-Firewall.vmx.
- Fixed the VMware PCIe-slot startup failure by adding standard PCIe root-port declarations and unique slot assignments.
- VM boots OPNsense 26.7 successfully from the verified ISO.
- Ethernet0 is attached only to custom VMnet2; Ethernet1 remains absent pending explicit approval for an additional isolated segment.
- Live environment detected vmx0 and temporarily assigned the media default 192.168.1.1/24; final 192.168.56.70/24 assignment and validation are still pending installation.

OPNsense post-install validation (2026-09-10):
- Installed to dedicated 20 GB da0 with explicit user authorization; verified hard-disk boot.
- Installation CD startConnected FALSE; ethernet0 custom VMnet2 only, ethernet1 absent.
- LAN configured through console as 192.168.56.70/24, upstream gateway blank, DHCP disabled, HTTPS retained.
- Host ping bound to 192.168.56.1: 3/3 replies, TTL 64, less than 1 ms.
- Host ARP: 192.168.56.70 -> 00-0C-29-FD-96-3A; matches VMX MAC.
- TCP 443 connection bound to 192.168.56.1 succeeded.
- Guest route table, guest-originated ping and reboot persistence remain unverified.
- Single-NIC placement does not provide inline segmentation between lab nodes.
- Evidence: D:\AttackTraceLab\evidence\07-OPNsense-network-verification.txt.

## 2026-09-10 - Ubuntu base and high-fidelity web node

Ubuntu base template:
- Installed Ubuntu Server 24.04.4 LTS to a new 32 GB virtual disk.
- Permanent netplan address: 192.168.56.90/24 on ens160.
- Default gateway: none.
- SSH: enabled and active.
- Hostname: ubuntu-base.
- Clone hygiene: machine-id and SSH host keys are regenerated by a one-shot service on each clone's first boot.
- Validation from the guest: ping to 192.168.56.1 and 192.168.56.10 both returned 2/2 replies.
- Validation from the host VMnet2 address: ping to 192.168.56.90 returned 2/2 replies.
- Host ARP entry: 192.168.56.90 -> 00-0C-29-E2-5D-18.

Prototype transition:
- The previous Metasploitable2 nodes 03-08 were suspended with their state preserved; no VM or disk was deleted.
- Kali 192.168.56.10 and Windows XP 192.168.56.20 remained running.

03-Ubuntu-Web:
- VM path: D:\AttackTraceLab\VMs-v2\03-Ubuntu-Web\03-Ubuntu-Web.vmx.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.30/24 on ens160; no default gateway.
- Hostname: web01.attacktrace.lab.
- Unique MAC: 00-0C-29-57-5B-C7.
- Real service: systemd-managed Python HTTP evidence service on TCP/80.
- Service checks: systemd active; /healthz returned ok; root page returned the lab portal response.
- Evidence output: /var/log/attacktrace/web-events.jsonl records timestamp, source IP, method, path, query, user agent, username, and login outcome.
- Guest ping to 192.168.56.1 and 192.168.56.10: 2/2 replies for each target.
- Host ping from 192.168.56.1 to 192.168.56.30: 2/2 replies.
- Guest ARP: host 00:50:56:c0:00:02; Kali 00:0c:29:18:77:51; XP 00:0c:29:5b:87:6d.
- Host ARP: 192.168.56.30 -> 00-0C-29-57-5B-C7.

05-Ubuntu-Mail:
- VM path: D:\AttackTraceLab\VMs-v2\05-Ubuntu-Mail\05-Ubuntu-Mail.vmx.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.50/24 on ens160; no default gateway.
- Hostname: mail01.attacktrace.lab.
- Unique MAC: 00-0C-29-31-C8-C5.
- Real service: systemd-managed SMTP receiver on TCP/25 with a local message spool.
- Service checks: systemd active and 0.0.0.0:25 listening.
- SMTP protocol test: 220 greeting, EHLO, MAIL FROM, RCPT TO, DATA queueing, and QUIT all succeeded.
- Evidence output: /var/log/attacktrace/smtp-events.jsonl plus one timestamped .eml file in /var/spool/attacktrace-mail.
- Guest ping to 192.168.56.1 and 192.168.56.10: 2/2 replies for each target.
- Host ping from 192.168.56.1 to 192.168.56.50: 2/2 replies.
- Host ARP: 192.168.56.50 -> 00-0C-29-31-C8-C5.

04-Ubuntu-C2-Sim:
- VM path: D:\AttackTraceLab\VMs-v2\04-Ubuntu-C2-Sim\04-Ubuntu-C2-Sim.vmx.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.40/24 on ens160; no default gateway.
- Hostname: c2sim01.attacktrace.lab.
- Unique MAC: 00-0C-29-76-6C-9D.
- Real service: systemd-managed benign HTTP beacon and task simulator on TCP/8080.
- Safety boundary: the simulator records beacons and returns a fixed metadata-report task; it does not execute or distribute commands.
- Protocol test: /beacon accepted a JSON event and /tasks returned the fixed inventory task.
- Evidence output: /var/log/attacktrace/c2-events.jsonl records source IP, agent ID, hostname, user, process, state, user agent, and timestamp.
- Guest ping to 192.168.56.1 and 192.168.56.10: 2/2 replies for each target.
- Host ping from 192.168.56.1 to 192.168.56.40: 2/2 replies.
- Host ARP: 192.168.56.40 -> 00-0C-29-76-6C-9D.

08-Ubuntu-Sensor:
- VM path: D:\AttackTraceLab\VMs-v2\08-Ubuntu-Sensor\08-Ubuntu-Sensor.vmx.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.80/24 on ens160; no default gateway.
- Hostname: sensor01.attacktrace.lab.
- Unique MAC: 00-0C-29-A6-C5-79.
- Real service: systemd-managed tcpdump capture on ens160 with full packet snapshots and 10 MB x 24 rotating PCAP files.
- Service checks: systemd active and capture.pcap00 is growing.
- Packet validation: PCAP contains ICMP and ARP involving the sensor itself.
- Promiscuous validation: the sensor captured separate host-to-web TCP/80 and host-to-C2 TCP/8080 conversations, including HTTP request and response metadata.
- Guest ping to 192.168.56.1 and 192.168.56.10: 2/2 replies for each target.
- Host ping from 192.168.56.1 to 192.168.56.80: 2/2 replies.
- Host ARP: 192.168.56.80 -> 00-0C-29-A6-C5-79.

## 2026-09-10 - Windows Server core node

06-WindowsServer-Core:
- VM path: D:\AttackTraceLab\VMs-v2\06-WindowsServer-Core\06-WindowsServer-Core.vmx.
- Installed Windows Server 2025 Evaluation (Desktop Experience) from the verified zh-CN ISO.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.60/24 on Ethernet0; no default gateway.
- Hostname: CORE01.
- Unique MAC: 00-0C-29-89-B2-35.
- VMware Tools 12.5.3 is installed and its time-synchronization channel is enabled.
- Real services: SMB file service/share CORE-DATA on TCP/445, RDP on TCP/3389, and WinRM on TCP/5985.
- Evidence data: C:\AttackTraceLab\core-data\finance-planning.txt is a synthetic LAB-SENSITIVE file for access and staging traces.
- Audit coverage: logon/logoff, special logon, process creation with command lines, file-system, registry, filtering-platform connections, PowerShell script-block/module logging, and PowerShell transcription.
- Guest ping to 192.168.56.1: succeeded.
- Guest ARP: 192.168.56.1 -> 00-50-56-C0-00-02.
- Host ping from 192.168.56.1 to 192.168.56.60: succeeded with TTL 128.
- Host direct TCP checks from 192.168.56.1: 445, 3389, and 5985 all accepted connections.
- Host ARP: 192.168.56.60 -> 00-0C-29-89-B2-35.
- Verification artifact: D:\AttackTraceLab\evidence\06-WindowsServer-Core-verification.txt.

## 2026-09-10 - Windows 11 office node

02-Windows11-Office:
- VM path: D:\AttackTraceLab\VMs-v2\02-Windows11-Office\02-Windows11-Office.vmx.
- Installed Windows 11 Enterprise 25H2 Evaluation from the verified zh-CN ISO.
- Network adapter: custom VMnet2 only; no NAT or bridged adapter.
- Permanent IP: 192.168.56.20/24 on Ethernet0; no default gateway.
- Hostname: WIN11-OFFICE.
- Unique MAC: 00-0C-29-49-78-EE.
- VMware Tools 12.5.3 is installed and running; its time-synchronization channel is enabled.
- Real endpoint services: WinRM on TCP/5985 and a scheduled office-activity telemetry task every 15 minutes.
- Evidence data: synthetic quarterly plan and employee contact documents under C:\Users\Public\Documents\AttackTraceLab.
- Cross-node behavior validation: the office node authenticated to \\192.168.56.60\CORE-DATA and read finance-planning.txt successfully over SMB/TCP 445.
- Audit coverage: logon/logoff, special logon, process creation with command lines, file-system, registry, filtering-platform connections, PowerShell script-block/module logging, and PowerShell transcription.
- Guest ping to 192.168.56.1 and 192.168.56.60: succeeded.
- Guest ARP: host 00-50-56-C0-00-02; core server 00-0C-29-89-B2-35.
- Host ping from 192.168.56.1 to 192.168.56.20: 2/2 replies with TTL 128.
- Host direct TCP check from 192.168.56.1: WinRM/5985 accepted a connection; RDP/3389 did not listen and is recorded as not validated.
- Host ARP: 192.168.56.20 -> 00-0C-29-49-78-EE.
- Verification artifact: D:\AttackTraceLab\evidence\02-Windows11-Office-verification.txt.
