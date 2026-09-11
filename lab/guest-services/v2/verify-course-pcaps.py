import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import IP, TCP, Raw, PcapReader

run = sys.argv[1]
start = datetime.strptime(run, 'course-%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc).timestamp()
result = {}
for label in ('web','office'):
    flows = {}
    correlated_payloads = 0
    count = 0
    with PcapReader('/tmp/' + run + '-' + label + '-verify.pcap') as packets:
        for packet in packets:
            if not start <= float(packet.time) <= start + 180 or IP not in packet or TCP not in packet:
                continue
            count += 1
            key = f'{packet[IP].src}->{packet[IP].dst}:{packet[TCP].dport}'
            flows[key] = flows.get(key,0) + 1
            if Raw in packet and run.encode() in bytes(packet[Raw].load):
                correlated_payloads += 1
    result[label] = dict(packets=count, flows=flows, run_id_payload_packets=correlated_payloads)
assert '192.168.56.10->192.168.60.30:22' in result['web']['flows']
assert '192.168.60.30->192.168.56.40:8080' in result['web']['flows']
assert '192.168.60.30->192.168.60.50:25' in result['web']['flows']
assert '192.168.70.20->192.168.80.60:445' in result['office']['flows']
assert '192.168.70.20->192.168.80.60:3389' in result['office']['flows']
assert all(v['run_id_payload_packets'] > 0 for v in result.values())
Path('/tmp/' + run + '-pcap-verification.json').write_text(json.dumps(result,indent=2))
print('Both captures contain this experiment window and run ID')
