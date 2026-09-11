#!/usr/bin/env python3
"""ICMP echo traffic generator for the lab tunnel experiments.

Positive phase: 160 echo requests with 400 bytes of random payload, which the
target kernel answers with the same payload, so both directions carry
high-entropy data. Negative phase: ordinary small pings.
"""
import os
import socket
import struct
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def main():
    target = "192.168.56.30"
    phase = sys.argv[1] if len(sys.argv) > 1 else "positive"
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    identifier = os.getpid() & 0xFFFF
    if phase == "positive":
        count, size, delay = 160, 400, 0.1
    else:
        count, size, delay = 30, 24, 1.0
    print("%s start %s" % (phase, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), flush=True)
    for sequence in range(1, count + 1):
        payload = os.urandom(size)
        header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
        header = struct.pack("!BBHHH", 8, 0, checksum(header + payload), identifier, sequence)
        try:
            sock.sendto(header + payload, (target, 0))
        except OSError as exc:
            print("send failed:", exc, flush=True)
        time.sleep(delay)
    print("%s end %s" % (phase, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), flush=True)


if __name__ == "__main__":
    main()
