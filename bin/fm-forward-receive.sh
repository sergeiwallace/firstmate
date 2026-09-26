#!/usr/bin/env bash
# fm-forward-receive.sh - the owning chief's entry point for a forwarded dispatch.
#
# Usage: fm-forward-receive.sh [--db <path>] --dispatch-id <id> --expected-owner-epoch <n>
#                              [--expected-hash <sha256-hex>] [--now <rfc3339>]
#        fm-forward-receive.sh --help
#
# A non-owning chief that wants a VP on this machine to act first stages the body
# in THIS chief's broker (the fm-body-stage path), then sends a non-operational
# doorbell naming only the dispatch id and the owner epoch it believes current.
# This tool is what the owning chief runs from that doorbell. It revalidates the
# epoch against the staged object and returns METADATA ONLY (id, vp_id, hash,
# state, deadlines) so local transport selection can begin
# (bin/fm-message-transport.sh). It never claims and never prints body_utf8: the
# body is obtained solely by the target VP's own fm-receive claim.
#
# Not yet revalidated here: the machine singleton lock and the signed VP-owner
# authority record, whose provisioning is human-gated on this fleet (they live
# under /var/lock and /var/lib and need root-signed keys). Until they land this
# tool is the epoch and hash check only, and says so in its output.
#
# The broker database is named, never guessed: --db, then FM_DISPATCH_BODY_DB,
# then $FM_HOME/dispatch-bodies.sqlite3. Exit codes are the broker's: 0
# deliverable; 2 refused; 3 stale-owner (the output names the current epoch) or
# hash conflict; 4 receipt only (already claimed/finished, expired, unknown).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BROKER="$SCRIPT_DIR/fm-dispatch-body.py"

usage() {
  awk '
    NR == 1 { next }
    /^#/ { sub(/^# ?/, ""); print; next }
    { exit }
  ' "$0"
}

refuse() {  # <status> <message>
  printf '{"refused": true, "code": %s, "reason": "fm-forward-receive: %s"}\n' "$1" "$2" >&2
  exit "$1"
}

DB=${FM_DISPATCH_BODY_DB:-}
DISPATCH_ID=
EPOCH=
EXPECTED=
NOW=
while [ $# -gt 0 ]; do
  case "$1" in
    --db) [ $# -ge 2 ] || refuse 2 "--db requires a path"; DB=$2; shift 2 ;;
    --db=*) DB=${1#--db=}; shift ;;
    --dispatch-id) [ $# -ge 2 ] || refuse 2 "--dispatch-id requires a value"; DISPATCH_ID=$2; shift 2 ;;
    --expected-owner-epoch) [ $# -ge 2 ] || refuse 2 "--expected-owner-epoch requires a value"; EPOCH=$2; shift 2 ;;
    --expected-hash) [ $# -ge 2 ] || refuse 2 "--expected-hash requires a value"; EXPECTED=$2; shift 2 ;;
    --now) [ $# -ge 2 ] || refuse 2 "--now requires a value"; NOW=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) refuse 2 "unknown argument '$1' (see --help)" ;;
  esac
done

[ -n "$DISPATCH_ID" ] || refuse 2 "--dispatch-id is required"
case "$EPOCH" in
  ''|*[!0-9]*) refuse 2 "--expected-owner-epoch must be a non-negative integer (got '${EPOCH}'); a forward without the epoch it believes current cannot be validated" ;;
esac

if [ -z "$DB" ]; then
  if [ -n "${FM_HOME:-}" ]; then
    DB="$FM_HOME/dispatch-bodies.sqlite3"
  else
    refuse 2 "no broker database named: set --db, FM_DISPATCH_BODY_DB, or FM_HOME (this chief's home); never guessed"
  fi
fi

command -v python3 >/dev/null 2>&1 || refuse 2 "python3 is required by the dispatch-body broker and is not on PATH"
[ -f "$BROKER" ] || refuse 2 "broker missing at $BROKER"

set -- --db "$DB"
[ -n "$NOW" ] && set -- "$@" --now "$NOW"
set -- "$@" forward-receive --dispatch-id "$DISPATCH_ID" --expected-owner-epoch "$EPOCH"
[ -n "$EXPECTED" ] && set -- "$@" --expected-hash "$EXPECTED"

exec python3 "$BROKER" "$@"
