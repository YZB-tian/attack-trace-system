# Course lab: current operating guide

Updated 2026-09-10. This document supersedes the old flat-network plans.

## Current readiness

### Latest checkpoint: 2026-09-10 15:57 UTC

The Office replacement is now `02-Windows11-Office-Rebuild`, address
192.168.70.20. All eight current VMs are running. Fresh guest checks show
Office LicenseStatus 1, 129456 grace minutes, VMware Tools running, current
Security events, and no IPv4 default route. The expired Office warning below
is historical and refers to the retired installation, not the replacement.
Core remains evaluation software: LicenseStatus 2, 13637 grace minutes.

Web, C2 and SMTP services are active. Web capture and both sensor capture
services are active; both unnumbered office bridge ports are forwarding.
Office-to-Core TCP445 connected; TCP3389 did not connect within 2.5 seconds.
This is consistent with earlier policy evidence, not a fresh firewall-log check.

Application ingestion is now verified for the earlier 900-event dataset and a
separate 22-event Zeek experiment with one periodic-communication candidate.
See D:\build\attack-trace-system\docs\course-requirement-status.md for remaining
Word requirements. Neither dataset proves a complete exploited intrusion chain.

### Historical checkpoint

18 functional evidence checks passed for `course-20260910T122827Z`.
This is an eight-node, segmented lab capable of collecting authentic logs and packets from controlled exercises.
Long-term readiness is BLOCKED by the Windows 11 evaluation license (zero remaining grace minutes). A supported rearm was attempted once and did not restore the grace period. Do not disable licensing services or falsify the clock. A usable licensed/evaluation installation is needed. Core Windows Server also remains evaluation software, with approximately 9.6 days of initial grace observed at inspection.

## Nodes

| Role | VM name | IP |
| --- | --- | --- |
| Attacker/test origin | 01-Kali-Attacker | 192.168.56.10 |
| Office | 02-Windows11-Office | 192.168.70.20 |
| Web | 03-Ubuntu-Web | 192.168.60.30 |
| C2 simulator | 04-Ubuntu-C2-Sim | 192.168.56.40 |
| Mail | 05-Ubuntu-Mail | 192.168.60.50 |
| Core server | 06-WindowsServer-Core | 192.168.80.60 |
| Firewall | 07-OPNsense-Firewall | 192.168.56.70; 192.168.60.1; 192.168.70.1; 192.168.80.1 |
| Internal switch/capture | 08-Ubuntu-Sensor | management 192.168.56.80; unnumbered br-office |

Office -> isolated downstream segment -> br-office -> OFFICE segment -> OPNsense.
The management NIC is not bridged. Other zones remain separated by OPNsense. No physical host adapter was changed, and no NAT/bridged VM adapter was added.

## Allowed exercise paths

- Kali -> Web TCP80 and TCP22 (known-credential SSH scenario).
- Web -> C2 TCP8080.
- Office -> Core TCP445.
- Office -> C2 TCP8080.
- Web -> Mail TCP25 inside DMZ.
- Existing narrowly scoped gateway ICMP and host management rules remain.
- Office -> Core TCP3389 is the negative control and remains blocked.

Earlier evidence showing Kali SSH blocked is historical: SSH was explicitly allowed for the new controlled exercise. Do not use that old test as the current policy assertion.

Kali, C2 and switch have a dedicated guest nftables table preventing new connections to host 192.168.56.1, and new IPv6 TCP/UDP connections. Existing host-initiated management replies remain allowed. This closes the observed host-proxy path, not a guarantee against a guest administrator deliberately altering networking. Guests have only explicit lab routes, no public default route.

## Repeating the exercise

Use `guest-services/v2/run-course-validation.ps1`. It creates a unique evidence directory and performs:

1. Two intentionally failed HTTP logins and one successful training login.
2. A real Kali-to-Web SSH session using known lab credentials and a pinned host key.
3. Linux process/file/archive operations, traced with strace, followed by three benign HTTP beacons and a synthetic transfer to C2.
4. Benign SMTP message delivery.
5. A separately orchestrated Windows office workflow: SMB synthetic file access, local staging/archive, simulated transfer to C2, and blocked RDP control.

Then use `export-course-artifacts.ps1 -RunId <run>` with the firewall password supplied in the local `LAB_FW_PASSWORD` environment variable. Do not publish credentials. The exporter refuses to overwrite prior evidence. It briefly pauses packet capture while copying files; it does not stop switching or application services.

Copy the matching SSH authentication log window and validate both PCAPs using `verify-course-pcaps.py` on Kali. The final dataset demonstrates this step. `verify-course-evidence.py` checks cross-source observations. Run IDs identify orchestrated test batches, not proof of a causal compromise between all machines.

## Evidence coverage

- Windows: original Security/PowerShell EVTX; process 4688, file 4663, authentication and SMB 4624/5140/5145.
- Linux: SSH authentication logs, application JSONL, traced process/file/network syscalls for the exercise process and descendants.
- Network: Web local packet capture and office inline-switch capture, bounded rotating files.
- Firewall: raw structured Live View API response, including rule labels and actions.
- C2/mail: receiver-side service logs; only synthetic data is sent.

Rotating PCAPs eventually overwrite old capture segments. Export immediately after an experiment. Final evidence is `evidence/course-20260910T122827Z`, including `acceptance.json` and `sha256-manifest.json`. Earlier exploratory runs are not the final acceptance dataset.

## Honest scope

These are real observations of controlled emulation, not fabricated logs. The lab does NOT claim an exploited vulnerability, stolen credentials, privilege escalation, or a proven Web-to-Office compromise. Office execution is separately orchestrated. There is no memory-injection exercise, no APT attribution proof, and no completed application-import verification here. If the instructor requires actual exploitation/lateral compromise rather than emulation, additional scenario work is required; this report is not certification that every Word requirement is met.

The minimal HTTP, SMTP and C2 services are intentionally simple course services, not complete enterprise products. Keep the original XP/Metasploitable prototype offline. Do not upload evidence or scripts to public GitHub without reviewing embedded lab credentials and account information.
