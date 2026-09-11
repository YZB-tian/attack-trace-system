#!/usr/bin/env python3
"""Minimal DNS server used as the far end of a lab DNS tunnel.

It answers every TXT query with a hex digest of the queried label, which is
enough for a client to exfiltrate encoded data through DNS. Runs only inside
the isolated VMnet2 lab.
"""
import binascii
import hashlib
import json
import socket
import struct
import time

LOG = "/tmp/dns-tunnel-server.jsonl"


def parse_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return labels, offset


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    handle = open(LOG, "a", encoding="utf-8")
    while True:
        data, address = sock.recvfrom(4096)
        if len(data) < 12:
            continue
        try:
            labels, offset = parse_name(data, 12)
            qtype, _ = struct.unpack("!HH", data[offset:offset + 4])
            question = data[12:offset + 4]
        except (IndexError, struct.error):
            continue
        label = labels[0] if labels else ""
        handle.write(json.dumps({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source_ip": address[0],
            "qname": ".".join(labels),
            "label": label,
            "qtype": qtype,
        }) + "\n")
        handle.flush()
        answer_data = binascii.hexlify(hashlib.sha256(label.encode()).digest()[:16])
        txt = bytes([len(answer_data)]) + answer_data
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 0, len(txt)) + txt
        response = (data[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
                    + question + answer)
        sock.sendto(response, address)


if __name__ == "__main__":
    main()
