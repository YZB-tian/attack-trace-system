# AttackTraceLab Node Plan

Network:
- VMware VMnet2 Host-only
- Subnet: 192.168.56.0/24
- Host VMnet2 adapter: 192.168.56.1/24
- DHCP: disabled
- Vulnerable VMs must not use bridged networking.

Current nodes:

| Node | Role | IP | VM path | Status |
| --- | --- | --- | --- | --- |
| 01 | Kali attacker | 192.168.56.10 | D:\AttackTraceLab\VMs\01-Kali-Attacker\01-Kali-Attacker.vmx | Running, ping OK |
| 02 | Windows XP target | 192.168.56.20 | D:\winxp\winxp\Windows XP Professional.vmx | Running, ping OK |
| 03 | DMZ web server | 192.168.56.30 | D:\AttackTraceLab\VMs\03-Metasploitable2\Metasploitable.vmx | Running, ping OK |
| 04 | C2 simulation server | 192.168.56.40 | D:\AttackTraceLab\VMs\04-Metasploitable2-Clone\Metasploitable.vmx | Running, ping OK |
| 05 | Email server | 192.168.56.50 | D:\AttackTraceLab\VMs\05-Metasploitable2-Clone\Metasploitable.vmx | Running, ping OK |
| 06 | Internal core server | 192.168.56.60 | D:\AttackTraceLab\VMs\06-Metasploitable2-Clone\Metasploitable.vmx | Running, ping OK |
| 07 | Firewall and IDS event source | 192.168.56.70 | D:\AttackTraceLab\VMs\07-Metasploitable2-Clone\Metasploitable.vmx | Running, ping OK |
| 08 | Internal switch telemetry and traffic sensor | 192.168.56.80 | D:\AttackTraceLab\VMs\08-Metasploitable2-Clone\Metasploitable.vmx | Running, ping OK |

Future replacement candidates:
- Replace cloned Metasploitable2 nodes with distinct vulnerable images when approved sources are available.
- Downloading any additional vulnerable VM image requires explicit confirmation before the download begins.

Per-node validation checklist:
- Confirm VMX network adapter is custom VMnet2.
- Confirm no bridged, NAT, VMnet0, VMnet1, or VMnet8 adapter remains enabled for vulnerable VMs.
- Confirm IP address.
- Confirm route table.
- Confirm ARP table.
- Confirm ping to at least Kali and the host VMnet2 adapter.
- Record results in D:\AttackTraceLab\lab-network-log.md.
