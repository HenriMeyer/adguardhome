#!/bin/sh
# publish-lists.sh — builds, signs, and uploads the router list table (KAN-119).
#
# Runs outside Supabase: an Edge Function is limited to 256 MB and 2 s of CPU per
# request (supabase.com/docs/guides/functions/limits), while building the table
# takes ~3–8 s of CPU and ~300 MB. Meant for a scheduled CI job after hagezi-sync
# (see github-workflow.yml next to this file).
#
# It takes the lists exactly as routers pulled them so far (hagezi/*.txt in the
# bucket, as hagezi-sync uploads them; iona-listtable drops their legacy $ctag), so
# the table blocks what the per-list files blocked, and uploads the transport form
# to tables/v1/lists.tbz. v1 is the table format version: a new format goes to a new
# path while older firmware keeps pulling v1.
#
# Environment:
#   SUPABASE_URL                 https://<ref>.supabase.co (or a test mirror)
#   SUPABASE_SERVICE_ROLE_KEY    for the upload (never on a router)
#   IONA_LISTS_KEY               base64 Ed25519 private key (CI secret)
#   IONA_LISTTABLE               path to the iona-listtable binary
#   BUCKET                       default Lists
#   DRY_RUN=1                    build and verify, don't upload
set -eu

: "${SUPABASE_URL:?}" "${IONA_LISTS_KEY:?}" "${IONA_LISTTABLE:?}"
BUCKET="${BUCKET:-Lists}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/lists"
printf '%s\n' "$IONA_LISTS_KEY" > "$WORK/key"
chmod 600 "$WORK/key"

index="$(curl -fsS "$SUPABASE_URL/functions/v1/hagezi-index?bucket=$BUCKET&prefix=hagezi" \
	-H "Authorization: Bearer ${SUPABASE_SERVICE_ROLE_KEY:-}")"
paths="$(printf '%s' "$index" | python3 -c 'import json,sys; [print(f["path"]) for f in json.load(sys.stdin)["files"] if f["path"].startswith("hagezi/") and f["path"].endswith(".txt")]')"
[ -n "$paths" ] || { echo "no lists in the index" >&2; exit 1; }

n=0
for p in $paths; do
	curl -fsS -o "$WORK/lists/${p##*/}" "$SUPABASE_URL/storage/v1/object/public/$BUCKET/$p"
	n=$((n + 1))
done
echo "downloaded $n lists"

# The public key belonging to the private one, for verifying our own output.
python3 - "$WORK/key" "$WORK/pub" <<'PY'
import base64, sys
priv = base64.b64decode(open(sys.argv[1]).read().strip())
open(sys.argv[2], "w").write(base64.b64encode(priv[32:]).decode() + "\n")
PY

seq="$(date +%s)"
"$IONA_LISTTABLE" build -key "$WORK/key" -seq "$seq" -o "$WORK/lists.tbl" "$WORK"/lists/*.txt
"$IONA_LISTTABLE" pack -pub "$WORK/pub" "$WORK/lists.tbl" "$WORK/lists.tbz"
"$IONA_LISTTABLE" unpack "$WORK/lists.tbz" "$WORK/check.tbl"
cmp "$WORK/lists.tbl" "$WORK/check.tbl"
"$IONA_LISTTABLE" verify -pub "$WORK/pub" "$WORK/check.tbl"

if [ "${DRY_RUN:-0}" = 1 ]; then
	echo "dry run: not uploading sequence $seq"
	exit 0
fi

: "${SUPABASE_SERVICE_ROLE_KEY:?}"
curl -fsS -X POST "$SUPABASE_URL/storage/v1/object/$BUCKET/tables/v1/lists.tbz" \
	-H "Authorization: Bearer $SUPABASE_SERVICE_ROLE_KEY" \
	-H "x-upsert: true" -H "Content-Type: application/octet-stream" \
	--data-binary "@$WORK/lists.tbz" >/dev/null
echo "published tables/v1/lists.tbz, sequence $seq, $(wc -c < "$WORK/lists.tbz") bytes"
