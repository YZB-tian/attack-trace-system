#!/bin/bash
if [ -f /tmp/dns-server.pid ]; then
    kill "$(cat /tmp/dns-server.pid)" 2>/dev/null
    sleep 1
fi
rm -f /tmp/dns-tunnel-server.jsonl
nohup python3 /tmp/30-dns-tunnel-server.py >/tmp/dns-server.out 2>&1 &
echo $! > /tmp/dns-server.pid
sleep 2
cat /tmp/dns-server.pid
ss -lunp | head -n 6
cat /tmp/dns-server.out
