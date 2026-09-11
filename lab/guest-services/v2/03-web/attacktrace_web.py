#!/usr/bin/python3
import json
import os
import pwd
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOG_PATH = "/var/log/attacktrace/web-events.jsonl"


def write_event(event):
    event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(LOG_PATH, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "AttackTraceLabWeb/1.0"

    def send_text(self, status, body, content_type="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        request = urlparse(self.path)
        write_event({
            "event": "http_request",
            "method": "GET",
            "path": request.path,
            "query": request.query,
            "source_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
        })
        if request.path == "/healthz":
            self.send_text(200, "ok\n")
            return
        if request.path == "/":
            self.send_text(200, "AttackTraceLab intranet portal\nPOST user/password to /login\n")
            return
        self.send_text(404, "not found\n")

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length", "0")), 4096)
        values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = values.get("user", [""])[0]
        success = user == "labuser" and values.get("password", [""])[0] == "__TRAINING_PASSWORD__"
        write_event({
            "event": "login_attempt",
            "source_ip": self.client_address[0],
            "user": user,
            "success": success,
        })
        self.send_text(200 if success else 401, "login accepted\n" if success else "login denied\n")

    def log_message(self, fmt, *args):
        return


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    account = pwd.getpwnam("www-data")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    server.serve_forever()


if __name__ == "__main__":
    main()
