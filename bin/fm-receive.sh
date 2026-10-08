#!/usr/bin/env bash
# fm-receive.sh - the recipient's claim gate for a chief-of-staff dispatch.
#
# Usage: fm-receive.sh [--db <path>] --dispatch-id <id> --vp-id <vp-id> --route native|buzz|agent-mail|fm-send
#                      [--expected-hash <sha256-hex>] [--now <rfc3339>]
#        fm-receive.sh --help
#
# Every transport (the native SendMessage doorbell, an Agent Mail envelope, an
# fm-send inbox item) ends here before any operational text reaches the recipient
# model. The gate performs one atomic claim in the owning chief's dispatch-body
# broker (bin/fm-dispatch-body.py): the first caller for a staged dispatch id wins
# and receives body_utf8 exactly once; every later caller, on any route, receives
# only the stored receipt. A late doorbell after a fallback won, or a fallback
# after the doorbell won, is therefore a no-op by construction.
#
# The broker database is named, never guessed: --db, then FM_DISPATCH_BODY_DB,
# then $FM_HOME/dispatch-bodies.sqlite3 (a chief claiming against its own home).
# With none of them set the gate refuses (exit 2). The winner's receipt projection
# is written to $FM_HOME/state/dispatch-inbox/<id>.json when FM_HOME is set.
#
# Exit codes are the broker's: 0 winner (stdout JSON carries body_utf8); 2 refused
# (invalid input, wrong target VP, authentication, no database named) - nothing
# changed; 3 hash conflict (an envelope copy that does not match the staged
# object) - nothing changed; 4 receipt only (loser, expired, unknown) - no body.
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
  printf '{"refused": true, "code": %s, "reason": "fm-receive: %s"}\n' "$1" "$2" >&2
  exit "$1"
}

DB=${FM_DISPATCH_BODY_DB:-}
DISPATCH_ID=
VP_ID=
ROUTE=
EXPECTED=
NOW=
while [ $# -gt 0 ]; do
  case "$1" in
    --db) [ $# -ge 2 ] || refuse 2 "--db requires a path"; DB=$2; shift 2 ;;
    --db=*) DB=${1#--db=}; shift ;;
    --dispatch-id) [ $# -ge 2 ] || refuse 2 "--dispatch-id requires a value"; DISPATCH_ID=$2; shift 2 ;;
    --vp-id) [ $# -ge 2 ] || refuse 2 "--vp-id requires a value"; VP_ID=$2; shift 2 ;;
    --route) [ $# -ge 2 ] || refuse 2 "--route requires a value"; ROUTE=$2; shift 2 ;;
    --expected-hash) [ $# -ge 2 ] || refuse 2 "--expected-hash requires a value"; EXPECTED=$2; shift 2 ;;
    --now) [ $# -ge 2 ] || refuse 2 "--now requires a value"; NOW=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) refuse 2 "unknown argument '$1' (see --help)" ;;
  esac
done

[ -n "$DISPATCH_ID" ] || refuse 2 "--dispatch-id is required; a receive without an id has nothing to claim"
[ -n "$VP_ID" ] || refuse 2 "--vp-id is required; the gate returns a body only to its addressed VP"
[ -n "$ROUTE" ] || refuse 2 "--route is required (native, buzz, agent-mail, or fm-send) so the winning route is recorded"

if [ -z "$DB" ]; then
  if [ -n "${FM_HOME:-}" ]; then
    DB="$FM_HOME/dispatch-bodies.sqlite3"
  else
    refuse 2 "no broker database named: set --db, FM_DISPATCH_BODY_DB, or FM_HOME (the owning chief home); the gate never guesses"
  fi
fi

command -v python3 >/dev/null 2>&1 || refuse 2 "python3 is required by the dispatch-body broker and is not on PATH"
[ -f "$BROKER" ] || refuse 2 "broker missing at $BROKER"

set -- --db "$DB"
[ -n "$NOW" ] && set -- "$@" --now "$NOW"
set -- "$@" claim --dispatch-id "$DISPATCH_ID" --vp-id "$VP_ID" --route "$ROUTE"
[ -n "$EXPECTED" ] && set -- "$@" --expected-hash "$EXPECTED"
[ -n "${FM_HOME:-}" ] && set -- "$@" --inbox-dir "$FM_HOME/state/dispatch-inbox"

exec python3 "$BROKER" "$@"
