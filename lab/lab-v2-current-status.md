# Lab v2 status - 2026-09-10

## Authoritative update at 12:30 UTC

Use COURSE-LAB-RUNBOOK.md for current topology and readiness. The remaining older sections below are historical and must not be used as the active configuration.

Office is now 192.168.70.20, core 192.168.80.60, web/mail 192.168.60.30/.50. Node 08 is an actual two-port office bridge with capture, verified across reboot. Linux syscall evidence and Windows process/file evidence were collected. The latest controlled exercise course-20260910T122827Z passed 18 cross-source checks, including real Kali-to-Web SSH and receiver-side simulated C2 data.

Windows office evaluation is expired and can shut down; one supported rearm did not resolve it. Long-term readiness is not complete until this is resolved. These are controlled emulation scenarios, not proof of all intrusion stages in the Word requirements.

## DMZ migration update

Web node has moved from VMnet2 / 192.168.56.30 to LAB-DMZ / 192.168.60.30/24. It has explicit routes to 192.168.56.0/24, 192.168.70.0/24 and 192.168.80.0/24 through 192.168.60.1, with no default route. Static configuration survived shutdown and startup.

Local HTTP health check returned ok; TCP 80 and SSH 22 listen. ARP resolved 192.168.60.1 to 00:0c:29:fd:96:44, matching the firewall DMZ NIC. Ping to that interface failed 2/2; filtering is suspected but not yet verified from firewall rules/logs. Cross-zone validation remains pending. See evidence/web-dmz-check.txt. The flat-network verification script below is now historical for this node and must be updated before reuse.

Rollback evidence: evidence/web-before-dmz.vmx and guest /root/web-before-dmz.yaml.

## Clock and logging follow-up

At approximately 09:18 UTC, all four Ubuntu service nodes reported UTC timestamps consistent with sequential host checks. The earlier eight-hour system-clock offset was no longer present. Persistent journald was configured. Reboot persistence and long-term drift remain to be tested.

C2 baseline retrieval initially failed because its log directory is restricted. The report was exported with guest sudo without relaxing directory permissions. Per-node evidence is in evidence/*-current-check.txt. Existing pre-correction logs retain their original timestamps and require offset-aware normalization; they were not rewritten.

## Segmentation update: 2026-09-10 10:36 UTC

The table below is a historical flat-network baseline, not the current address map.
User-authorized segmentation is partially applied. OPNsense now has LAN
192.168.56.70/24, OPT1 192.168.60.1/24, OPT2 192.168.70.1/24 and
OPT3 192.168.80.1/24. Its additional adapters use LAB-DMZ, LAB-OFFICE,
and LAB-SERVER isolated LAN segments respectively.

Web now uses 192.168.60.30/24 and mail 192.168.60.50/24 on LAB-DMZ.
Both have permanent netplan configuration and explicit lab-subnet routes,
with no default route. Mail-to-web ping succeeded 2/2 and HTTP /healthz
returned ok. Web-to-mail SMTP accepted a synthetic test message with no
rejected recipients. Evidence: evidence/mail-dmz-check.txt and
evidence/dmz-smtp-check.txt; web evidence: evidence/web-dmz-check.txt.

Firewall OPT1 ARP resolves, but ICMP responses fail. Firewall policy and
cross-zone communication remain unverified. Browser management access is
blocked by an untrusted certificate; no browser safety bypass was performed.
Office and core have not yet migrated. Office was powered off at the latest
inventory. No host physical adapter settings were modified.

The remaining sections describe the earlier baseline. In particular, their
single-NIC and all-VMnet2 descriptions are superseded by this update.

All eight VMs were running simultaneously during verification. Host-source-bound ping returned 2/2 replies for every address below. Evidence: evidence/v2-validation-20260910-164759.json.

| Node | Address | Verified service |
| --- | --- | --- |
| Kali | 192.168.56.10 | Reachable; SSH port 22 closed |
| Windows 11 office | 192.168.56.20 | WinRM 5985 reachable; earlier SMB client read succeeded |
| Ubuntu web | 192.168.56.30 | SSH 22, HTTP 80; /healthz returned ok |
| Ubuntu C2 simulator | 192.168.56.40 | SSH 22, HTTP 8080; /tasks returned fixed metadata-report task |
| Ubuntu mail | 192.168.56.50 | SSH 22, SMTP 25 reachable; earlier message delivery recorded |
| Windows Server core | 192.168.56.60 | SMB 445, RDP 3389, WinRM 5985 reachable |
| OPNsense | 192.168.56.70 | TCP 443 reachable; installed on virtual disk |
| Ubuntu sensor | 192.168.56.80 | SSH 22 reachable; capture service configured and previously validated |

## Resource adjustment

Four powered-off Ubuntu service VMs were reduced from 4096 MB to 1024 MB each before starting. Kali retains 2048 MB, Windows 11 4096 MB, Windows Server 6144 MB, OPNsense 4096 MB. Host free memory after startup was approximately 2.4 GB. Capture under load and memory pressure require further testing.

## Isolation and verification limits

All eight VM network configurations use VMnet2. No host physical adapter was modified. Old XP and Metasploitable2 nodes remain offline and must not run concurrently with replacements using the same addresses.

VMnet2 host-only includes the host at 192.168.56.1; it is not isolation from the host itself. Host forwarding and proxy exposure have not been fully audited.

OPNsense is single-NIC on the same subnet. Traffic between lab nodes does not necessarily traverse it. Routed DMZ, office and server zones have not been implemented. Additional isolated segments require the user's network-change approval.

The sensor is not a separately implemented managed switch. VMnet2 supplies the virtual L2 fabric; strict eight-role grading requires a topology revision or instructor acceptance.

The web and SMTP services are custom minimal implementations. The C2 service is a benign simulator. They do not by themselves constitute a complete intrusion chain or production-like enterprise applications.

Current checks verify host-to-node reachability and selected services. They do not establish complete all-pairs connectivity, guest route tables, OPNsense firewall enforcement, continuous capture after this restart, comprehensive syscall or memory-injection monitoring, centralized collection, multi-agent analysis, attack-chain reconstruction, or attacker attribution.

The older lab-requirement-fit.md and verify-lab.ps1 refer to the retired prototype. Use this document and verify-v2.ps1 for the replacement nodes.
