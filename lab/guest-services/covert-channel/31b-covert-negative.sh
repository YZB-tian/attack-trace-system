#!/bin/sh
# Negative controls: ordinary DNS lookups, ordinary HTTP polling and ordinary
# ICMP echo traffic that must not raise covert-channel alerts.
RUN="$1"
OUT="/tmp/$RUN"
mkdir -p "$OUT"
echo "== negative start $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
for n in web01 mail01 core01 firewall01 sensor01 c2sim01; do
  dig +short +time=2 +tries=1 A "$n.attacktrace.lab" @192.168.56.40 >/dev/null 2>&1
  sleep 2
done
k=0
while [ "$k" -lt 24 ]; do
  k=$((k+1))
  case $((k % 3)) in
    0) curl -s -m 5 -o /dev/null "http://192.168.56.40:8080/healthz" ;;
    1) curl -s -m 5 -o /dev/null "http://192.168.56.40:8080/tasks" ;;
    2) curl -s -m 5 -o /dev/null "http://192.168.56.40:8080/tasks?id=inventory" ;;
  esac
  S=$(( (k * 7) % 9 + 2 ))
  sleep "$S"
done
for p in 1 2 3 4 5 6; do
  ping -c 5 -i 1 192.168.56.40 >/dev/null 2>&1
  sleep 3
done
echo "== negative end $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
