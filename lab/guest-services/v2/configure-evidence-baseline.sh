#!/bin/sh
set -eu
epoch="$1"
case "$epoch" in *[!0-9]*|'') exit 2;; esac
mkdir -p /var/log/attacktrace /etc/systemd/journald.conf.d
date -u --iso-8601=seconds > /var/log/attacktrace/clock-before.txt
timedatectl set-timezone Asia/Shanghai
date -u -s "@$epoch"
hwclock --systohc --utc || true
if command -v vmware-toolbox-cmd >/dev/null 2>&1; then
  vmware-toolbox-cmd timesync enable
fi
cat > /etc/systemd/journald.conf.d/60-attacktrace.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=256M
Compress=yes
EOF
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
{
  date -u --iso-8601=seconds
  hostname
  timedatectl
  ip -br address
  ip route
  ip neigh
  ping -c 2 -W 2 192.168.56.1
  journalctl --disk-usage
  systemctl is-active rsyslog
} > /var/log/attacktrace/baseline-verification.txt 2>&1
chmod 644 /var/log/attacktrace/baseline-verification.txt
