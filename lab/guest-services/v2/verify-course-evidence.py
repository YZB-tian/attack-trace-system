import hashlib
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

root = Path(sys.argv[1])
run = root.name
start = datetime.strptime(run, 'course-%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)


def read(name):
    return json.loads((root/name).read_text(encoding='utf-8-sig'))


def jsonlines(name):
    return [json.loads(line) for line in (root/name).read_text(encoding='utf-8-sig').splitlines() if line.strip()]


ssh = read('kali-ssh.json')
web = read('web-timeline.json')
office = read('office-timeline.json')
core_events = read('core-security.json')
office_events = read('office-security.json')
firewall = read('firewall-live-raw.json')
c2 = [e for e in jsonlines('c2-events.jsonl') if e.get('payload',{}).get('run_id')==run]
pcap = read('pcap-verification.json')
checks = {
    'http_failed_then_successful_login': [e['status'] for e in read('kali-login.json')]==[401,401,200],
    'real_ssh_session': ssh['exit_code']==0 and web[0]['origin']=='ssh_session' and web[0]['ssh_connection'].startswith('192.168.56.10 '),
    'server_auth_log': 'Accepted password for labadmin from 192.168.56.10' in (root/'web-auth.log').read_text(),
    'linux_exec_syscall': 'execve("/usr/bin/id"' in (root/'web-syscalls.strace').read_text(),
    'linux_file_syscall': f'/tmp/{run}/synthetic.txt' in (root/'web-syscalls.strace').read_text(),
    'office_scenario_complete': office[-1]['Stage']=='complete' and office[-1]['Detail']['Success'],
    'windows_file_audit': any(e['event_id']==4663 and run in e['fields'].get('ObjectName','') for e in office_events),
    'windows_process_audit': any(e['event_id']==4688 and e['fields'].get('NewProcessName','').lower().endswith('whoami.exe') and datetime.fromisoformat(e['timestamp'])>=start for e in office_events),
    'core_remote_share_audit': any(e['event_id']==5145 and e['fields'].get('IpAddress')=='192.168.70.20' and e['fields'].get('RelativeTargetName')=='finance-planning.txt' and datetime.fromisoformat(e['timestamp'])>=start for e in core_events),
    'web_c2_received': sum(e['source_ip']=='192.168.60.30' for e in c2)==4,
    'office_c2_received': sum(e['source_ip']=='192.168.70.20' for e in c2)==2,
    'mail_sent': any(e['stage']=='smtp_delivery' for e in web),
    'packet_windows_correlated': all(v['packets']>0 and v['run_id_payload_packets']>0 for v in pcap.values()),
}
for label, action in [('Course-Kali-to-Web-SSH','pass'),('Course-Web-to-C2-8080','pass'),('Course-Office-to-C2-8080','pass'),('Office-to-Core-SMB','pass')]:
    checks['firewall_'+label] = any(e.get('label')==label and e.get('action')==action for e in firewall)
checks['firewall_rdp_block'] = any(e.get('src')=='192.168.70.20' and e.get('dstport')=='3389' and e.get('action')=='block' for e in firewall)
license_file = root / 'office-license.json'
license_verified = False
if license_file.exists():
    products = read('office-license.json').get('Products', [])
    if isinstance(products, dict):
        products = [products]
    license_verified = any(p.get('LicenseStatus') == 1 for p in products)
limitations = ['Windows scenario is separately orchestrated; no proven Web-to-Office compromise.',
              'No vulnerability exploitation or privilege escalation claimed.']
if not license_verified:
    limitations.insert(0, 'Current Windows office activation is not verified by this dataset.')
result = dict(run_id=run,checks=checks,functional_tests_passed=all(checks.values()),
              classification='controlled_emulation_not_uncontrolled_intrusion',
              office_license_verified=license_verified, limitations=limitations)
(root/'acceptance.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
hashes=[dict(file=p.name,bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.iterdir()) if p.is_file() and p.name!='sha256-manifest.json']
(root/'sha256-manifest.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
if not result['functional_tests_passed']:
    raise SystemExit(1)
