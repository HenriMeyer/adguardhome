#!/bin/bash
# Build a local list set that mirrors the router's: public HaGeZi lists, with
# $ctag=~<tag> appended to tagged lists the way hagezi-sync does server-side.
set -eu
OUT="${1:?out dir}"
RAW="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock"
mkdir -p "$OUT/raw" "$OUT/hagezi"

# name tag ("-" = untagged)
LISTS="
ultimate.txt device_phone
native.amazon.txt device_tv
native.apple.txt device_audio
native.huawei.txt os_macos
native.lgwebos.txt os_linux
native.oppo-realme.txt os_android
native.roku.txt os_other
native.samsung.txt device_tablet
native.tiktok.txt os_windows
native.vivo.txt user_regular
native.winoffice.txt device_pc
native.xiaomi.txt device_laptop
gambling.txt device_other
nsfw.txt device_securityalarm
nosafesearch.txt os_ios
tif.medium.txt -
fake.txt -
popupads.txt -
doh-vpn-proxy-bypass.txt -
dyndns.txt -
spam-tlds.txt -
anti.piracy.txt -
"

printf '%s\n' "$LISTS" | while read -r name tag; do
  [ -n "$name" ] || continue
  [ -s "$OUT/raw/$name" ] || curl -fsSL --compressed -o "$OUT/raw/$name" "$RAW/$name"
  if [ "$tag" = "-" ]; then
    cp "$OUT/raw/$name" "$OUT/hagezi/$name"
  else
    # Only rule lines get the modifier; comments and blanks stay as they are.
    awk -v t="$tag" '/^[|@]/ { print $0 (index($0, "$") ? "," : "$") "ctag=~" t; next } { print }' \
      "$OUT/raw/$name" > "$OUT/hagezi/$name"
  fi
done
[ -s "$OUT/raw/dns-rebind-protection.txt" ] || curl -fsSL --compressed \
  -o "$OUT/raw/dns-rebind-protection.txt" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adguard/dns-rebind-protection.txt"
cp "$OUT/raw/dns-rebind-protection.txt" "$OUT/hagezi/"

ls "$OUT/hagezi" | wc -l
cat "$OUT"/hagezi/*.txt | grep -c -E '^[|@]'
du -sh "$OUT/hagezi"
