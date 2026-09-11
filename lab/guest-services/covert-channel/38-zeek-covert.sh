#!/bin/bash
RUN="$1"
OUT="/tmp/$RUN-covert"
ZR=/tmp/ats-zeek/opt/zeek
ZE="$ZR/bin/zeek"
export ZEEKPATH=".:$ZR/share/zeek:$ZR/share/zeek/policy:$ZR/share/zeek/site:$ZR/share/zeek/builtin-plugins"
export ZEEK_PLUGIN_PATH="$ZR/lib/zeek/plugins"
export PATH="$ZR/bin:$PATH"
rm -rf "$OUT"
mkdir -p "$OUT"
cp "/tmp/$RUN-capture.pcap" "$OUT/capture.pcap"
cp /tmp/protocol-evidence.zeek "$OUT/protocol-evidence.zeek"
cd "$OUT" || exit 1
"$ZE" -C -r capture.pcap LogAscii::use_json=T protocol-evidence.zeek > "$OUT/zeek-stdout.txt" 2>&1
echo "zeek_exit=$?"
ls -l "$OUT"/*.log 2>/dev/null
rm -f "$OUT/capture.pcap"
cd /tmp || exit 1
tar czf "/tmp/$RUN-zeeklogs.tar.gz" -C /tmp "$RUN-covert"
ls -l "/tmp/$RUN-zeeklogs.tar.gz"
