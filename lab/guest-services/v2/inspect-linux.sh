#!/bin/sh
{
  date -u --iso-8601=seconds
  hostname
  id
  ip -br address
  ip route
  ip neigh
  free -m
  command -v bridge
  command -v ovs-vsctl
  command -v auditctl
  sudo -n true && echo SUDO_READY
  systemctl is-active attacktrace-capture
  systemctl list-units --type=service --state=running --no-pager
  ls -lh /var/log/attacktrace/pcap/ 2>/dev/null
} > /tmp/lab-inspection.txt 2>&1
