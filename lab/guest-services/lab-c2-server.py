#!/usr/bin/python
import hashlib
import os
import time
from cgi import parse_qs
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse

HOST = '192.168.56.40'
PORT = 8080
LOG_PATH = '/var/log/lab-c2/events.jsonl'


def json_value(value):
    if isinstance(value, (int, long)):
        return str(value)
    text = str(value)
    text = text.replace('\\', '\\\\').replace('"', '\\"')
    text = text.replace('\r', '\\r').replace('\n', '\\n')
    return '"%s"' % text


def json_object(fields):
    parts = []
    for key in sorted(fields.keys()):
        parts.append('%s:%s' % (json_value(key), json_value(fields[key])))
    return '{%s}' % ','.join(parts)


def append_event(event):
    event['timestamp_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    handle = open(LOG_PATH, 'a')
    try:
        handle.write(json_object(event) + '\n')
    finally:
        handle.close()


class LabC2Handler(BaseHTTPRequestHandler):
    server_version = 'AttackTraceLab-C2/1.0'

    def send_json(self, status, payload):
        body = json_object(payload) + '\n'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        agent_id = parse_qs(parsed.query).get('id', ['unknown'])[0][:128]
        append_event({
            'source_ip': self.client_address[0],
            'method': 'GET',
            'path': parsed.path,
            'agent_id': agent_id,
        })
        if parsed.path == '/health':
            self.send_json(200, {'service': 'lab-c2-simulator', 'status': 'ok'})
        elif parsed.path == '/task':
            self.send_json(200, {'task': 'sleep', 'seconds': 60})
        else:
            self.send_json(404, {'error': 'not_found'})

    def do_POST(self):
        parsed = urlparse(self.path)
        length = min(int(self.headers.getheader('Content-Length') or 0), 4096)
        body = self.rfile.read(length)
        append_event({
            'source_ip': self.client_address[0],
            'method': 'POST',
            'path': parsed.path,
            'body_bytes': len(body),
            'body_sha256': hashlib.sha256(body).hexdigest(),
        })
        if parsed.path == '/checkin':
            self.send_json(200, {'status': 'accepted'})
        else:
            self.send_json(404, {'error': 'not_found'})

    def log_message(self, format_string, *args):
        return


if __name__ == '__main__':
    if not os.path.isdir('/var/log/lab-c2'):
        os.makedirs('/var/log/lab-c2')
    HTTPServer((HOST, PORT), LabC2Handler).serve_forever()
