import http.cookiejar
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'input' and a.get('type') == 'hidden' and a.get('name'):
            self.hidden[a['name']] = a.get('value', '')


def session():
    # The lab appliance uses its own self-signed certificate; no external host is accessed.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
    )
    base = 'https://192.168.56.70'
    page = opener.open(base + '/', timeout=15).read().decode()
    form = Inputs()
    form.feed(page)
    data = dict(form.hidden, usernamefld='root', passwordfld=os.environ['LAB_FW_PASSWORD'], login='1')
    page = opener.open(base + '/', urllib.parse.urlencode(data).encode(), timeout=15).read().decode()
    if 'id="passwordfld"' in page:
        raise RuntimeError('Firewall login failed; no repeated attempts')
    return opener, base


if __name__ == '__main__':
    opener, base = session()
    page = opener.open(base + '/ui/diagnostics/firewall/log', timeout=15).read().decode()
    pos = page.find('/api/diagnostics/firewall/log/')
    print(page[max(0,pos-1600):pos+2400])
