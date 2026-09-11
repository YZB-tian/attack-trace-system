#!/bin/sh
set -eu
test "$(id -u)" = 0
test ! -e /etc/course-host-guard.nft
if nft list table inet course_host_guard >/dev/null 2>&1; then exit 2; fi
nft list ruleset > /tmp/host-guard-before.nft
nft -c -f /tmp/course-host-guard.nft
install -m 600 /tmp/course-host-guard.nft /etc/course-host-guard.nft
install -m 644 /tmp/course-host-guard.service /etc/systemd/system/course-host-guard.service
systemctl daemon-reload
systemctl enable --now course-host-guard
nft list table inet course_host_guard > /tmp/host-guard-after.nft
