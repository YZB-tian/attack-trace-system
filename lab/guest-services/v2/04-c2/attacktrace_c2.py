#!/usr/bin/python3
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/var/log/attacktrace/c2-events.jsonl"


def record(event):
    event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(LOG_PATH, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "AttackTraceLabC2Simulator/1.0"

    def send_json(self, status, value):
        data = json.dumps(value, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"parse_error": True}

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "ok", "mode": "benign-simulation"})
            return
        record({"event": "c2_get", "source_ip": self.client_address[0], "path": self.path})
        self.send_json(200, {"tasks": [{"id": "inventory", "action": "report-host-metadata"}]})

    def do_POST(self):
        payload = self.body()
        event = "beacon" if self.path == "/beacon" else "result" if self.path == "/result" else "c2_post"
        record({
            "event": event,
            "source_ip": self.client_address[0],
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "payload": payload,
        })
        self.send_json(200, {"accepted": True, "next_check_seconds": 30})

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
