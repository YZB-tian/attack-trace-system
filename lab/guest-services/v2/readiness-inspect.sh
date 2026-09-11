#!/bin/sh
{
date -u --iso-8601=seconds
hostname
ip -br address
ip route
ip neigh
for tool in auditctl auditd strace perf tcpdump python3 gcc; do command -v "$tool" || true; done
ls /var/cache/apt/archives/*.deb 2>/dev/null
systemctl is-active attacktrace-web attacktrace-smtp attacktrace-c2 attacktrace-capture attacktrace-office-capture attacktrace-node-capture rsyslog
ss -lnt
df -h /
ls -lh /var/log/attacktrace
vmware-toolbox-cmd timesync status
} > /tmp/readiness-inspect.txt 2>&1
