#!/bin/sh
set -eu
test "$(id -u)" = 0
test ! -e /etc/netplan/70-office-switch.yaml
ip -br address > /tmp/switch-before.txt
ip route >> /tmp/switch-before.txt
install -m 600 /tmp/70-office-switch.yaml /etc/netplan/70-office-switch.yaml
netplan generate
netplan apply
mkdir -p /var/log/attacktrace/office-pcap
install -m 644 /tmp/attacktrace-office-capture.service /etc/systemd/system/attacktrace-office-capture.service
systemctl daemon-reload
systemctl enable --now attacktrace-office-capture
{
  date -u --iso-8601=seconds
  ip -br address
  ip route
  bridge link
  bridge fdb show br br-office
  sysctl net.ipv4.ip_forward
  systemctl is-active attacktrace-office-capture
} > /tmp/switch-after.txt
