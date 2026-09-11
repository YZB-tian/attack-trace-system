import base64
import json
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
import paramiko

run = sys.argv[1]
if not re.fullmatch(r'course-[0-9TZ]+', run):
    raise SystemExit('Invalid run ID')
parts = Path('/tmp/course-web-host-key.pub').read_text().split()
key = paramiko.Ed25519Key(data=base64.b64decode(parts[1]))
client = paramiko.SSHClient()
client.get_host_keys().add('192.168.60.30', 'ssh-ed25519', key)
client.set_missing_host_key_policy(paramiko.RejectPolicy())
start = datetime.now(timezone.utc).isoformat()
try:
    client.connect('192.168.60.30', username='labadmin', password='__LAB_PASSWORD__',
                   look_for_keys=False, allow_agent=False, timeout=8)
    command = ('strace -f -ttt -yy -s 256 -e trace=process,file,network -o /tmp/' + run +
               '-web.strace python3 /tmp/course-web-exercise.py ' + run)
    _, stdout, stderr = client.exec_command(command, timeout=40)
    output = stdout.read().decode()
    errors = stderr.read().decode()
    code = stdout.channel.recv_exit_status()
    result = dict(run_id=run,started_utc=start,exit_code=code,stdout=output,stderr=errors,
                  scenario='authorized_valid_credentials_emulation',source='192.168.56.10',destination='192.168.60.30')
    Path('/tmp/' + run + '-ssh.json').write_text(json.dumps(result,indent=2))
    if code != 0:
        raise RuntimeError(errors)
finally:
    client.close()
