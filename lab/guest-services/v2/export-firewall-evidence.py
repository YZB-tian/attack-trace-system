import json
import re
import runpy
import sys
import urllib.request
from pathlib import Path

out = Path(sys.argv[1]).resolve()
if not out.is_relative_to(Path('D:/AttackTraceLab/evidence').resolve()) or not out.is_dir():
    raise SystemExit('Invalid evidence directory')
opener, base = runpy.run_path(str(Path(__file__).with_name('inspect-firewall.py')))['session']()
page = opener.open(base + '/ui/diagnostics/firewall/log', timeout=15).read().decode()
token = re.search(r'setRequestHeader\("X-CSRFToken",\s*"([^\"]+)"', page).group(1)
request = urllib.request.Request(base + '/api/diagnostics/firewall/log/?limit=50', headers={'X-CSRFToken':token})
result = json.loads(opener.open(request, timeout=20).read())
(out / 'firewall-live-raw.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({'type':type(result).__name__, 'keys':list(result)[:10] if isinstance(result,dict) else None,
                  'sample':result[:2] if isinstance(result,list) else str(result)[:1200]}, indent=2))
