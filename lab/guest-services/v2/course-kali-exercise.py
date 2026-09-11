import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

run = sys.argv[1]
if not re.fullmatch(r'course-[0-9TZ]+', run):
    raise SystemExit('Invalid run ID')
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []
for password in ('course-wrong-1', 'course-wrong-2', '__TRAINING_PASSWORD__'):
    req = urllib.request.Request('http://192.168.60.30/login',
        data=urllib.parse.urlencode(dict(user='labuser', password=password)).encode(),
        headers={'User-Agent': run})
    try:
        with http.open(req, timeout=8) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    results.append(dict(timestamp=datetime.now(timezone.utc).isoformat(), status=status,
                        stage='controlled_login_test', run_id=run))
Path('/tmp/' + run + '-kali.json').write_text(json.dumps(results, indent=2))
assert [r['status'] for r in results] == [401, 401, 200], results
print('Login failure and success evidence verified')
