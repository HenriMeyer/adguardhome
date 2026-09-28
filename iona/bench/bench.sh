#!/bin/bash
# Local AdGuard Home benchmark mirroring the router setup.
#
#   bench.sh <AdGuardHome binary> <lists dir> <env dir>
#
# <lists dir> is the hagezi/ folder fetch-lists.sh builds; <env dir> is wiped
# and recreated. Needs dig, curl, python3, and network access for upstream DNS.
#
# Starts AGH from the router's adguardhome.yaml template (paths/ports rewritten,
# DNS on 127.0.0.1:5354, API on 127.0.0.1:3001, GOGC=20, GOMAXPROCS=4 like the
# MT7986), then measures:
#   1. startup: time until the block lists are active, RSS afterwards
#   2. whitelist: time from "@@||domain^ added + filtering/refresh {whitelist}"
#      until the domain resolves unblocked, and the RSS peak during it
#   3. DNS availability during the whitelist refresh (queries answered/failed)
#   4. client tags: whether a tag outside AGH's fixed 21-value enum is accepted
set -u

BIN="${1:?binary}"; LISTS="${2:?lists dir}"; E="${3:?env dir}"
# This file lives in firmware/forks/adguardhome/iona/bench/.
TEMPLATE="$(cd "$(dirname "$0")/../../../.." && pwd)/openwrt/files/etc/adguardhome/adguardhome.yaml"
API="http://127.0.0.1:3001"
DNS=(-p 5354 @127.0.0.1 +tries=1 +time=1 +short)
BLOCK_IP="10.9.9.9"

rm -rf "$E"; mkdir -p "$E/filters/hagezi" "$E/filters/whitelist" "$E/querylog" "$E/work" "$E/tmp/statistic"
cp "$LISTS"/*.txt "$E/filters/hagezi/"
: > "$E/user_whitelist.txt"

# Router template → local paths and ports. Cache off so every query hits the
# filtering engine; custom_ip so "blocked" is unambiguous in dig output.
sed -e "s#/etc/adguardhome#$E#g" -e "s#/tmp/adguardhome#$E/tmp#g" \
    -e 's#^  address: 127.0.0.1:0#  address: 127.0.0.1:3001#' \
    -e 's#^    - 0.0.0.0#    - 127.0.0.1#' -e 's#^  port: 53$#  port: 5354#' \
    -e 's#^  cache_enabled: true#  cache_enabled: false#' \
    -e "s#^  blocking_mode: nxdomain#  blocking_mode: custom_ip#" \
    -e "s#^  blocking_ipv4: \"\"#  blocking_ipv4: $BLOCK_IP#" \
    -e 's#^  blocking_ipv6: ""#  blocking_ipv6: "::"#' \
    -e 's#^  file_enabled: true#  file_enabled: false#' \
    "$TEMPLATE" > "$E/adguardhome.yaml"

# Same filters block router-adguard-apply-lists writes: one entry per list.
python3 - "$E" <<'PY'
import os, sys
e = sys.argv[1]
names = sorted(os.listdir(f"{e}/filters/hagezi"))
block = "filters:\n" + "".join(
    f"  - enabled: true\n    url: {e}/filters/hagezi/{n}\n    name: hagezi {n}\n    id: {i}\n"
    for i, n in enumerate(names, 1))
p = f"{e}/adguardhome.yaml"
s = open(p).read().replace("filters: []\n", block, 1)
open(p, "w").write(s)
PY

rss() { awk '/^VmRSS/{r=$2} /^VmHWM/{h=$2} END{printf "rss=%dMB peak=%dMB", r/1024, h/1024}' "/proc/$PID/status"; }
blocked() { [ "$(dig "${DNS[@]}" "$1" A 2>/dev/null | head -1)" = "$BLOCK_IP" ]; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2fs", b-a}'; }

# A domain that ultimate.txt blocks (tagged list, applies to untagged clients).
DOMAIN="$(grep -m1 -o -E '^\|\|[a-z0-9.-]+\.[a-z]{2,}\^' "$E/filters/hagezi/ultimate.txt" | sed -n '1p' | tr -d '|^')"
PROBE="$(grep -o -E '^\|\|[a-z0-9.-]+\.[a-z]{2,}\^' "$E/filters/hagezi/tif.medium.txt" | sed -n '5000p' | tr -d '|^')"

T0="$(now)"
GOGC=20 GOMAXPROCS=4 "$BIN" --config "$E/adguardhome.yaml" --work-dir "$E/work" \
  --no-check-update --logfile "$E/agh.log" &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT

for _ in $(seq 1 600); do blocked "$PROBE" && break; kill -0 $PID 2>/dev/null || break; sleep 0.1; done
blocked "$PROBE" || { echo "block lists never became active"; tail -20 "$E/agh.log"; exit 1; }
echo "startup:   lists active after $(since "$T0"), $(rss)"
sleep 3
echo "idle:      $(rss)"

blocked "$DOMAIN" || { echo "test domain $DOMAIN is not blocked"; exit 1; }

# DNS availability probe during the refresh: one query every 50 ms.
( ok=0; fail=0; end=$(( $(date +%s) + 25 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if [ -n "$(dig "${DNS[@]}" "$PROBE" A 2>/dev/null)" ]; then ok=$((ok+1)); else fail=$((fail+1)); fi
    sleep 0.05
  done; echo "$ok $fail" > "$E/probe.out" ) &
PROBE_PID=$!

printf '@@||%s^\n' "$DOMAIN" >> "$E/user_whitelist.txt"
T1="$(now)"
RESP="$(curl -s -m 60 -X POST -H 'Content-Type: application/json' \
  -d '{"whitelist":true}' "$API/control/filtering/refresh")"
API_T="$(since "$T1")"
for _ in $(seq 1 600); do blocked "$DOMAIN" || break; sleep 0.05; done
if blocked "$DOMAIN"; then
  echo "whitelist: $DOMAIN still blocked after 30s (api said: $RESP)"
else
  echo "whitelist: $DOMAIN unblocked after $(since "$T1") (api call $API_T, $RESP), $(rss)"
fi

wait "$PROBE_PID"
read -r ok fail < "$E/probe.out"
echo "dns during refresh: $ok answered, $fail failed"

TAG_RESP="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"name":"tagtest","ids":["127.0.0.1"],"tags":["iona_cat_22"],"use_global_settings":true,"use_global_blocked_services":true}' \
  "$API/control/clients/add")"
echo "client tag iona_cat_22: HTTP $TAG_RESP ($( [ "$TAG_RESP" = 200 ] && echo accepted || echo rejected ))"

if [ "$TAG_RESP" = 200 ]; then
  # End to end: this client (127.0.0.1) carries iona_cat_22, so a rule excluding
  # that tag must not apply to it, while one excluding another tag still must.
  curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
    -d '{"rules":["||freetag-exempt.example^$ctag=~iona_cat_22","||freetag-control.example^$ctag=~iona_cat_23"]}' \
    "$API/control/filtering/set_rules"
  for _ in $(seq 1 600); do blocked freetag-control.example && break; sleep 0.05; done
  printf 'ctag=~iona_cat_22 (client has it):  %s\n' "$(blocked freetag-exempt.example && echo blocked || echo not blocked)"
  printf 'ctag=~iona_cat_23 (client lacks it): %s\n' "$(blocked freetag-control.example && echo blocked || echo not blocked)"
fi
