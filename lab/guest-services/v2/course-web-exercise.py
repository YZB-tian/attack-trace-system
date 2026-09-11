import hashlib
import json
import os
from pathlib import Path
import re
import smtplib
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

run = sys.argv[1]
if not re.fullmatch(r'course-[0-9TZ]+', run):
    raise SystemExit('Invalid run ID')
root = Path('/tmp') / run
root.mkdir(mode=0o700, exist_ok=False)
events = []
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def record(stage, **fields):
    events.append(dict(timestamp=datetime.now(timezone.utc).isoformat(), run_id=run,
                       stage=stage, classification='controlled_emulation', **fields))
    (root / 'timeline.json').write_text(json.dumps(events, indent=2))


def post(path, body):
    req = urllib.request.Request('http://192.168.56.40:8080' + path,
                                 data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    with http.open(req, timeout=8) as response:
        return response.status


identity = subprocess.check_output(['/usr/bin/id'], text=True).strip()
record('execution_validation', pid=os.getpid(), identity=identity,
       origin='ssh_session' if os.environ.get('SSH_CONNECTION') else 'vmware_guest_orchestration_not_remote_exploit',
       ssh_connection=os.environ.get('SSH_CONNECTION'))
sample = root / 'synthetic.txt'
sample.write_text('SYNTHETIC COURSE DATA ONLY\n' + run + '\n')
record('file_collection', path=str(sample), sha256=hashlib.sha256(sample.read_bytes()).hexdigest())
with tarfile.open(root / 'synthetic.tar.gz', 'w:gz') as archive:
    archive.add(sample, arcname='synthetic.txt')
record('archive_staging', path=str(root / 'synthetic.tar.gz'))
for i in range(3):
    status = post('/beacon', dict(run_id=run, host='web01', sequence=i, mode='controlled_emulation'))
    record('http_beacon', destination='192.168.56.40:8080', status=status)
    time.sleep(1)
record('synthetic_transfer', status=post('/result', dict(run_id=run, mode='controlled_emulation',
       content=sample.read_text(), sha256=hashlib.sha256(sample.read_bytes()).hexdigest())))
message = EmailMessage()
message['From'] = 'course@attacktrace.lab'
message['To'] = 'student@attacktrace.lab'
message['Subject'] = 'Controlled course exercise ' + run
message.set_content('Benign mail evidence, not a phishing payload. Run: ' + run)
with smtplib.SMTP('192.168.60.50', 25, timeout=8) as smtp:
    smtp.send_message(message)
record('smtp_delivery', destination='192.168.60.50:25')
print(json.dumps(dict(run_id=run, root=str(root), stages=len(events), success=True)))
