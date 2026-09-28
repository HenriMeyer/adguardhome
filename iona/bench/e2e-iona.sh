#!/bin/bash
# End-to-end test of the AdGuard Home binary in Iona mode on a development
# machine: control files + SIGHUP instead of the HTTP API.
#
#   e2e-iona.sh <AdGuardHome> <iona-listtable> <lists dir> <work dir>
#
# <lists dir> holds the lists as the router pulls them (with lists-meta.json).
# Runs DNS on 127.0.0.1:5399 with the router's adguardhome.yaml template and
# checks every control path while a probe keeps querying, so that any DNS gap
# shows up.  Exit status 1 if any check failed.
set -u

BIN="${1:?AdGuardHome}"; LT="${2:?iona-listtable}"; LISTS="${3:?lists dir}"; E="${4:?work dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/../../../../openwrt/files/etc/adguardhome/adguardhome.yaml"
DNS=(-p 5399 @127.0.0.1 +tries=1 +time=1)
BLOCK_IP=10.9.9.9
I="$E/iona"
STATUS="$E/tmp/iona-status.json"
FAIL=0

pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=1; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.3fs", b-a}'; }
answer() { dig "${DNS[@]}" +short "$1" A 2>/dev/null | head -1; }
blocked() { [ "$(answer "$1")" = "$BLOCK_IP" ]; }
applied() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["applied"])' "$STATUS" 2>/dev/null || echo 0; }
status() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$STATUS" "$1"; }

# hup sends SIGHUP and waits until the reload is applied; prints the time.
hup() {
	local before t0
	before="$(applied)"; t0="$(now)"
	kill -HUP "$PID"
	for _ in $(seq 1 200); do
		[ "$(applied)" -gt "$before" ] && { since "$t0"; return 0; }
		sleep 0.02
	done
	echo "timeout"; return 1
}

rm -rf "$E"; mkdir -p "$I/keys" "$E/work" "$E/tmp/statistic" "$E/querylog" "$E/filters/whitelist"
"$LT" keygen "$E/test.key" "$I/keys/test.pub"
"$LT" build -key "$E/test.key" -seq 1 -o "$E/seq1.tbl" "$LISTS"/*.txt >/dev/null
cp "$E/seq1.tbl" "$I/lists.tbl"
printf '@@||resources.aldec.com^$important\n' > "$E/filters/whitelist/iona_global_allowlist.txt"
: > "$E/user_whitelist.txt"

sed -e "s#/etc/adguardhome#$E#g" -e "s#/tmp/adguardhome#$E/tmp#g" \
    -e 's#^    - 0.0.0.0#    - 127.0.0.1#' -e 's#^  port: 53$#  port: 5399#' \
    -e "s#^  blocking_mode: nxdomain#  blocking_mode: custom_ip#" \
    -e "s#^  blocking_ipv4: \"\"#  blocking_ipv4: $BLOCK_IP#" \
    -e 's#^  blocking_ipv6: ""#  blocking_ipv6: "::"#' \
    "$TEMPLATE" > "$E/adguardhome.yaml"
python3 - "$E" <<'PY'
import sys
e = sys.argv[1]
p = f"{e}/adguardhome.yaml"
s = open(p).read().replace("filters: []\n",
    f"filters:\n  - enabled: true\n    url: {e}/filters/whitelist/iona_global_allowlist.txt\n"
    "    name: whitelist iona_global_allowlist.txt\n    id: 1\n", 1)
s = s.replace(f"    - {e}/filters/whitelist/*\n", f"    - {e}/filters/whitelist/*\n", 1)
open(p, "w").write(s)
PY

echo "== start (Iona mode, router selection)"
printf '%s\n' anti.piracy.txt dns-rebind-protection.txt doh-vpn-proxy-bypass.txt dyndns.txt fake.txt \
	gambling.txt native.amazon.txt native.apple.txt native.huawei.txt native.lgwebos.txt \
	native.oppo-realme.txt native.roku.txt native.samsung.txt native.tiktok.txt native.vivo.txt \
	native.winoffice.txt native.xiaomi.txt nosafesearch.txt nsfw.txt popupads.txt pro.plus.txt \
	spam-tlds.txt tif.medium.txt > "$I/selected"
T0="$(now)"
AGH_IONA_DIR="$I" AGH_IONA_STATUS="$STATUS" GOGC=20 GOMAXPROCS=4 \
	"$BIN" --config "$E/adguardhome.yaml" --work-dir "$E/work" --no-check-update --logfile "$E/agh.log" &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT
for _ in $(seq 1 300); do [ "$(applied)" -ge 1 ] && break; sleep 0.05; done
START_T="$(since "$T0")"
[ "$(applied)" -ge 1 ] && pass "applied after $START_T" || { fail "never applied"; tail -20 "$E/agh.log"; exit 1; }
grep -E 'VmRSS|VmHWM' "/proc/$PID/status" | tr -s ' \t' ' ' | sed 's/^/        /'

# Probe: one query every 20 ms for the rest of the test; counts failures.
touch "$E/probe.run"
( n=0; f=0; while [ -e "$E/probe.run" ]; do
	if [ -n "$(dig "${DNS[@]}" +short example.com A 2>/dev/null)" ]; then n=$((n+1)); else f=$((f+1)); fi
	sleep 0.02; done; echo "$n $f" > "$E/probe.out" ) &
PROBE=$!

# only_in <list>: a domain that no other list contains.
only_in() {
	comm -23 <(grep -oE '^\|\|[a-z0-9.-]+\^' "$LISTS/$1" | tr -d '|^' | sort -u) \
		<(ls "$LISTS"/*.txt | grep -v "/$1\$" | xargs cat | grep -oE '^\|\|[a-z0-9.-]+\^' | tr -d '|^' | sort -u) | sed -n 100p
}
GAMB="$(only_in gambling.txt)"
PROP="$(grep -oE '^\|\|[a-z0-9.-]+\^' "$LISTS/pro.plus.txt" | sed -n 777p | tr -d '|^')"
ULTI="$(only_in ultimate.txt)"
[ -n "$GAMB" ] && [ -n "$ULTI" ] || { fail "could not pick test domains"; exit 1; }

echo "== filtering"
blocked "$GAMB" && pass "gambling domain $GAMB blocked" || fail "gambling domain not blocked"
blocked "sub.$PROP" && pass "subdomain of pro.plus entry blocked" || fail "pro.plus subdomain not blocked"
blocked "$ULTI" && fail "ultimate-only domain blocked although ultimate not selected" || pass "unselected list inactive ($ULTI)"
blocked "x.fritz.box" && fail "rebind exception ignored" || pass "residual @@ exception (fritz.box) wins"
blocked "foo.actor" && pass "residual TLD rule (*.actor) blocks" || fail "TLD rule not applied"
blocked "resources.aldec.com" && fail "global allowlist ignored" || pass "global allowlist wins"
[ "$(status 'd["table"]["entries"]')" -gt 1000000 ] && pass "status: $(status 'd["table"]["entries"]') entries, source $(status 'd["table"]["source"]')" || fail "status table"

echo "== user whitelist via SIGHUP"
printf '@@||%s^$important\n' "$GAMB" >> "$E/user_whitelist.txt"
T="$(hup)"; blocked "$GAMB" && fail "whitelist not effective ($T)" || pass "whitelist effective after $T"
: > "$E/user_whitelist.txt"
T="$(hup)"; blocked "$GAMB" && pass "whitelist removal effective after $T" || fail "removal not effective"

echo "== list selection via SIGHUP (no restart)"
PID_BEFORE="$PID"
echo ultimate.txt >> "$I/selected"
T="$(hup)"; blocked "$ULTI" && pass "ultimate enabled after $T" || fail "ultimate not enabled"
sed -i '/^gambling.txt$/d' "$I/selected"
T="$(hup)"; blocked "$GAMB" && fail "gambling still active" || pass "gambling disabled after $T"
[ "$(status 'd["pid"]')" = "$PID_BEFORE" ] && pass "same process (pid $PID_BEFORE)" || fail "process changed"

echo "== table swap via staged file (transport form)"
"$LT" build -key "$E/test.key" -seq 2 -o "$E/seq2.tbl" "$LISTS"/*.txt >/dev/null
"$LT" pack -pub "$I/keys/test.pub" "$E/seq2.tbl" "$E/seq2.tbz" >/dev/null
cp "$E/seq2.tbz" "$I/lists.tbl.new"
T="$(hup)"; [ "$(status 'd["table"]["sequence"]')" = 2 ] && pass "sequence 2 active after $T" || fail "swap failed: $(status 'd["errors"]')"
grep -E 'VmRSS|VmHWM' "/proc/$PID/status" | tr -s ' \t' ' ' | sed 's/^/        /'
[ -f "$I/lists.tbl.prev" ] && pass "previous table kept as lists.tbl.prev" || fail "no prev"

echo "== rejected tables keep the active one"
python3 - "$E/seq2.tbl" "$E/bad.tbl" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[len(b) // 2] ^= 0xFF
open(sys.argv[2], "wb").write(b)
PY
cp "$E/bad.tbl" "$I/lists.tbl.new"; hup >/dev/null
[ "$(status 'd["table"]["sequence"]')" = 2 ] && blocked "$ULTI" && pass "tampered table rejected: $(status 'd["errors"][0]')" || fail "tampered table not rejected"
cp "$E/seq1.tbl" "$I/lists.tbl.new"; hup >/dev/null
[ "$(status 'd["table"]["sequence"]')" = 2 ] && pass "downgrade rejected: $(status 'd["errors"][0]')" || fail "downgrade accepted"
"$LT" keygen "$E/other.key" "$E/other.pub"
"$LT" build -key "$E/other.key" -seq 9 -o "$I/lists.tbl.new" "$LISTS"/native.apple.txt >/dev/null
hup >/dev/null
[ "$(status 'd["table"]["sequence"]')" = 2 ] && pass "foreign key rejected" || fail "foreign key accepted"

echo "== DNS control files via SIGHUP"
printf 'nxdomain\n' > "$I/blocking"
T="$(hup)"
[ "$(dig "${DNS[@]}" "$ULTI" A | grep -c 'status: NXDOMAIN')" = 1 ] && pass "blocking mode nxdomain after $T" || fail "blocking mode not applied"
printf 'custom_ip %s ::\n' "$BLOCK_IP" > "$I/blocking"
hup >/dev/null
printf 'iona.router 192.168.1.1\nnas.lan 192.168.1.50\n' > "$I/rewrites"
T="$(hup)"
[ "$(answer nas.lan)" = 192.168.1.50 ] && pass "rewrite nas.lan after $T" || fail "rewrite not applied"
printf '9.9.9.10\n' > "$I/upstreams"
T="$(hup)"
[ "$(status 'd["extra"]["upstreams"]')" = "['9.9.9.10']" ] && pass "upstreams applied after $T" || fail "upstreams: $(status 'd["extra"]')"
[ -n "$(answer example.org)" ] && pass "resolving via new upstream" || fail "no resolution via new upstream"
printf 'not-an-upstream!!\n' > "$I/upstreams"
hup >/dev/null
[ -n "$(status 'd["extra"].get("dns_error","")')" ] && [ "$(status 'd["extra"]["upstreams"]')" = "['9.9.9.10']" ] \
	&& pass "invalid upstream rejected, old kept: $(status 'd["extra"]["dns_error"]' | cut -c1-60)" || fail "invalid upstream handling"
rm -f "$I/upstreams"

echo "== devices file with bad lines"
printf 'zz:zz 1\naa:bb:cc:dd:ee:ff gambling.txt\n' > "$I/devices"
hup >/dev/null
[ "$(status 'len(d["devices"])')" = 1 ] && pass "valid device line applied, error reported" || fail "devices"

echo "== many reloads in a row"
T0="$(now)"; for _ in $(seq 1 50); do kill -HUP "$PID"; done; sleep 2
kill -0 "$PID" && pass "survived 50 SIGHUPs in $(since "$T0")" || fail "died on SIGHUP storm"

rm -f "$E/probe.run"; wait "$PROBE"
read -r ok bad < "$E/probe.out"
[ "$bad" = 0 ] && pass "probe: $ok queries answered during the whole test, 0 failed" || fail "probe: $bad of $((ok+bad)) queries failed"
grep -E 'VmRSS|VmHWM' "/proc/$PID/status" | tr -s ' \t' ' ' | sed 's/^/        /'
exit $FAIL
