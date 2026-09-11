#!/bin/bash
if [ -f /tmp/covert.pid ]; then
    kill "$(cat /tmp/covert.pid)" 2>/dev/null
    rm -f /tmp/covert.pid
fi
sleep 2
ls -l /tmp/covert.pcap
cat /tmp/covert-tcpdump.log | tail -n 3
