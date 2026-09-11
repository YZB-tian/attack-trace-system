import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import runpy
session = runpy.run_path(str(Path(__file__).with_name('inspect-firewall.py')))['session']

opener, base = session()
page = opener.open(base + '/ui/firewall/filter', timeout=15).read().decode()
token = re.search(r'setRequestHeader\("X-CSRFToken",\s*"([^\"]+)"', page).group(1)


def api(path, payload=None):
    headers = {'X-CSRFToken': token}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + '/api/firewall/filter/' + path, data=data, headers=headers)
    return json.loads(opener.open(req, timeout=30).read())


stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
root = Path('D:/AttackTraceLab/evidence')
before = api('search_rule/')
(root / ('firewall-before-course-' + stamp + '.json')).write_text(json.dumps(before, indent=2), encoding='utf-8')
rows = before['rows']
desired = [
    ('Course-Web-to-C2-8080', 'opt1', '192.168.60.30/32', '192.168.56.40/32', '8080'),
    ('Course-Office-to-C2-8080', 'opt2', '192.168.70.20/32', '192.168.56.40/32', '8080'),
    ('Course-Kali-to-Web-SSH', 'lan', '192.168.56.10/32', '192.168.60.30/32', '22'),
]
results = []
for name, interface, source, destination, port in desired:
    fields = dict(enabled='1', action='pass', quick='1', interface=interface,
                  direction='in', ipprotocol='inet', protocol='TCP',
                  source_net=source, destination_net=destination,
                  destination_port=port, log='1', description=name)
    found = [r for r in rows if r.get('description') == name]
    if found:
        if len(found) != 1 or any(str(found[0].get(k, '')) != v for k, v in fields.items()):
            raise RuntimeError('Existing rule conflicts; preserved without modification: ' + name)
        results.append({'name': name, 'status': 'already_present'})
    else:
        result = api('add_rule/', {'rule': fields})
        if result.get('result') != 'saved':
            raise RuntimeError(str(result))
        results.append({'name': name, 'status': 'created', 'uuid': result.get('uuid')})
apply_result = api('apply', {})
after = api('search_rule/')
(root / ('firewall-after-course-' + stamp + '.json')).write_text(json.dumps(after, indent=2), encoding='utf-8')
print(json.dumps({'rules':results,'apply':apply_result}, indent=2))
