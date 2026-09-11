#!/bin/bash
if [ -f /tmp/covert.pid ]; then
    kill "$(cat /tmp/covert.pid)" 2>/dev/null
    sleep 1
fi
rm -f /tmp/covert.pcap
nohup tcpdump -i ens160 -s 0 -U -w /tmp/covert.pcap >/tmp/covert-tcpdump.log 2>&1 &
echo $! > /tmp/covert.pid
sleep 2
cat /tmp/covert.pid
ls -l /tmp/covert.pcap
