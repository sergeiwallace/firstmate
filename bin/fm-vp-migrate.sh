#!/usr/bin/env bash
# fm-vp-migrate.sh - plan and record the migration of one existing VP session
# into a scoped Firstmate secondmate home (design AIH-62xkr, T-3.1).
#
# Usage:
#   fm-vp-migrate.sh <vp-name> --repo <path> --dry-run [options]
#   fm-vp-migrate.sh <vp-name> --repo <path> --execute      (refused; see below)
#
#   --repo <path>          the repository this VP is scoped to (required)
#   --dry-run              plan every gate and write a receipt; touch nothing
#   --execute              REFUSED with status 2: the live cutover is an
#                          operator step, not an automated one
#   --home <path>          the secondmate home to seed (default:
#                          <chief-home>/secondmates/<vp-name>)
#   --receipt-dir <dir>    where to write <vp>.receipt (default: a fresh
#                          mktemp -d under a dry run, NEVER the live chief home:
#                          a value - or a TMPDIR - that resolves at or under
#                          $FM_HOME is refused with status 2, naming the path)
#   --sessions-dir <dir>   where VP session records live
#                          (default: ${XDG_CONFIG_HOME:-$HOME}/.claude/sessions)
#   --role <role>          the VP's AI_SESSION_ROLE, which a Claude Code session
#                          record does not carry; without it that gate records
#                          `unmeasured` rather than inventing a value
#   --help
#
# WHAT THIS DOES NOT DO, BY CONSTRUCTION
#
# It never stops, signals, kills, attaches to, relaunches, or messages a live
# session - not even the VP it is migrating. The sessions directory is read, and
# only read. On this host aih-1, aih-2, aih-3, aih-4, kg-1, kg-2 and kg-3 are
# live CC sessions whose records sit in that directory, so a migration tool that
# treated a record as a handle would be one bug away from dropping a colleague's
# session. The cutover - stop the old VP, launch the replacement, retire the
# authority record - is deliberately NOT implemented: `--execute` refuses and
# names what it would do, so there is no code path here that could perform it.
#
# T-3.1's gates, in order. A dry run plans each one and records
# pass | fail | skipped(dry-run) | skipped(unmeasured: <why>); the first failure
# stops the run, is named in the receipt, and exits non-zero with the old VP
# still authoritative and nothing seeded.
#
#   vp-record              the named VP has exactly one readable session record
#   repo-scope             --repo is preserved: it contains the VP's own cwd
#   charter                a charter brief is resolvable for the new home
#   harness-selection      the harness family (and role, when supplied) carried over
#   beads-ownership        the VP's in-progress/blocked backlog work, read-only,
#                          through bin/fm-tasks-axi.sh (never a bare backend CLI)
#   home-seed              a scoped home + route can be seeded (fm-home-seed.sh)
#   route-register         the resulting registry bindings validate
#   reconcile              the replacement would reconcile its books
#   native-dispatch-proof  one native SendMessage/ack/notify_when_idle cycle
#   cutover                retire the old VP and make the replacement authoritative
#
# The last three cannot be proved without starting a session, so under --dry-run
# they are always recorded as skipped(dry-run) and never as pass. A receipt that
# claimed a native-dispatch proof nobody observed is the one output that would
# make this tool dangerous.
#
# Exit codes: 0 the plan is complete and every reached gate passed; 1 a gate
# failed (named in the receipt); 2 bad arguments, or --execute.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/fm-secondmate-registry-lib.sh disable=SC1091
. "$SCRIPT_DIR/fm-secondmate-registry-lib.sh"

usage() {
  awk '
    NR == 1 { next }
    /^#/ { sub(/^# ?/, ""); print; next }
    { exit }
  ' "$0"
}

refuse() {  # <status> <message>
  printf 'fm-vp-migrate: %s\n' "$2" >&2
  exit "$1"
}

# physical_path <path>: the physical absolute spelling of <path>, resolved
# without creating it. The deepest existing ancestor is resolved with `pwd -P`
# and the missing tail is re-appended, because the receipt directory usually
# does not exist yet and a comparison against an unresolved spelling is not a
# comparison: /tmp is a symlink on macOS, `..` and a symlinked --receipt-dir
# both re-enter directories a literal prefix test says they are outside of.
# bin/fm-ff-lib.sh ships resolve_path/path_is_ancestor_of for the existing-path
# case; that library is the git self-sync machinery and requires FM_ROOT and
# FM_HOME to be set, which this planner deliberately does not, so the two
# non-existent-tail-safe lines live here instead.
physical_path() {  # <path>
  local p=$1 rest= base
  [ -n "$p" ] || return 1
  case "$p" in
    /*) ;;
    *) p="$(pwd -P)/$p" ;;
  esac
  while [ "$p" != / ] && [ ! -d "$p" ]; do
    rest="$(basename "$p")${rest:+/$rest}"
    p="$(dirname "$p")"
  done
  base=$(CDPATH='' cd -P -- "$p" 2>/dev/null && pwd -P) || base=$p
  printf '%s' "${base%/}${rest:+/$rest}"
}

# path_at_or_under <candidate> <ancestor>: true when candidate IS ancestor or
# sits beneath it. Both arguments must already be physical.
path_at_or_under() {  # <candidate> <ancestor>
  [ -n "$1" ] && [ -n "$2" ] || return 1
  [ "$1" != "$2" ] || return 0
  case "$1" in
    "$2"/*) return 0 ;;
  esac
  return 1
}

# refuse_inside_chief_home <label> <path>: the "a dry run never lands in the
# live chief home" guarantee, enforced rather than merely defaulted. Without
# this it was bypassable - `--receipt-dir "$FM_HOME/state/migrations"`, or
# TMPDIR pointing into the home, wrote a planner receipt into the live chief
# home while that same receipt declared nothing live had been touched.
# <chief-home>/state/migrations/<vp>.receipt belongs to the operator's real
# cutover, which this script does not perform.
refuse_inside_chief_home() {  # <label> <path>
  [ -n "${FM_HOME:-}" ] || return 0
  local home abs
  home=$(physical_path "$FM_HOME") || return 0
  abs=$(physical_path "$2") || return 0
  if path_at_or_under "$abs" "$home"; then
    refuse 2 "$1 resolves inside the live chief home: $abs is at or under $home; a dry-run receipt must never land there"
  fi
}

VP=
REPO=
HOME_DIR=
RECEIPT_DIR=
SESSIONS_DIR=
ROLE=
MODE=

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) [ $# -ge 2 ] || refuse 2 "--repo requires a path"; REPO=$2; shift 2 ;;
    --home) [ $# -ge 2 ] || refuse 2 "--home requires a path"; HOME_DIR=$2; shift 2 ;;
    --receipt-dir) [ $# -ge 2 ] || refuse 2 "--receipt-dir requires a path"; RECEIPT_DIR=$2; shift 2 ;;
    --sessions-dir) [ $# -ge 2 ] || refuse 2 "--sessions-dir requires a path"; SESSIONS_DIR=$2; shift 2 ;;
    --role) [ $# -ge 2 ] || refuse 2 "--role requires a value"; ROLE=$2; shift 2 ;;
    --dry-run)
      [ -z "$MODE" ] || refuse 2 "name one of --dry-run or --execute, not both"
      MODE=dry-run
      shift
      ;;
    --execute)
      [ -z "$MODE" ] || refuse 2 "name one of --dry-run or --execute, not both"
      MODE=execute
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    -*) refuse 2 "unknown option '$1' (see --help)" ;;
    *)
      [ -z "$VP" ] || refuse 2 "name exactly one VP (got '$VP' and '$1')"
      VP=$1
      shift
      ;;
  esac
done

[ -n "$VP" ] || refuse 2 "a VP name is required (see --help)"
case "$VP" in
  *[!A-Za-z0-9._-]*) refuse 2 "VP name '$VP' is not a safe session name" ;;
esac
[ -n "$REPO" ] || refuse 2 "--repo is required: a migration must preserve the VP's repo scope explicitly"
[ -n "$MODE" ] || refuse 2 "name a mode: --dry-run plans and records; --execute is refused"

# The live cutover is an operator step. This is a refusal, not a stub awaiting a
# flag: nothing below this point can stop a session, because no such code
# exists in this file.
if [ "$MODE" = execute ]; then
  printf 'fm-vp-migrate: live cutover is an operator step; see docs/configuration.md (VP-to-secondmate migration)\n' >&2
  printf '%s\n' \
    'Refused. --execute would, for this VP:' \
    '  1. seed the scoped secondmate home and route planned by --dry-run' \
    '  2. launch the replacement secondmate under that home' \
    '  3. reconcile route, authority record/epoch, registry entry, owning-chief' \
    '     routes, ListAgents identity, dispatch-body broker access and Beads work' \
    '  4. prove one native SendMessage / acknowledgement / notify_when_idle cycle' \
    '  5. retire the old VP session and make the replacement authoritative' \
    'Steps 2 and 5 stop and start live CC sessions, so they stay with the' \
    'operator. Run --dry-run, read the receipt, then perform the cutover by hand.' >&2
  exit 2
fi

: "${SESSIONS_DIR:=${XDG_CONFIG_HOME:-$HOME}/.claude/sessions}"

# --- receipt ------------------------------------------------------------------
#
# A dry run's receipt never lands in the live chief home: with no --receipt-dir
# it goes to a fresh temp directory. The live location
# (<chief-home>/state/migrations/<vp>.receipt) belongs to the operator's real
# cutover, which this script does not perform.
#
# Both spellings of the destination are checked BEFORE anything is created, and
# the resolved result is checked again afterwards: mktemp follows a symlinked
# TMPDIR, so the only spelling the guarantee can be stated about is the one the
# receipt is actually written to.
if [ -z "$RECEIPT_DIR" ]; then
  TMP_BASE=${TMPDIR:-/tmp}
  refuse_inside_chief_home "the TMPDIR a default receipt directory would use" "$TMP_BASE"
  RECEIPT_DIR=$(mktemp -d "${TMP_BASE%/}/fm-vp-migrate.XXXXXX") \
    || refuse 2 "could not create a receipt directory"
else
  refuse_inside_chief_home "--receipt-dir" "$RECEIPT_DIR"
  mkdir -p "$RECEIPT_DIR" || refuse 2 "receipt directory is not writable: $RECEIPT_DIR"
fi
RECEIPT_DIR=$(physical_path "$RECEIPT_DIR") \
  || refuse 2 "could not resolve the receipt directory to a physical path"
refuse_inside_chief_home "the resolved receipt directory" "$RECEIPT_DIR"
RECEIPT="$RECEIPT_DIR/$VP.receipt"

GATE_LINES=
FAILED_GATE=
record() {  # <gate> <status> [detail]
  local gate=$1 status=$2 detail=${3-}
  if [ -n "$detail" ]; then
    GATE_LINES="${GATE_LINES}gate: $gate: $status ($detail)"$'\n'
  else
    GATE_LINES="${GATE_LINES}gate: $gate: $status"$'\n'
  fi
}

fail_gate() {  # <gate> <detail>
  FAILED_GATE=$1
  record "$1" fail "$2"
}

write_receipt() {
  {
    printf 'receipt: vp-to-secondmate migration\n'
    printf 'vp: %s\n' "$VP"
    printf 'mode: %s\n' "$MODE"
    printf 'repo: %s\n' "$REPO"
    printf 'home: %s\n' "${HOME_DIR:-<unresolved>}"
    printf '%s' "$GATE_LINES"
    if [ -n "$FAILED_GATE" ]; then
      printf 'result: FAILED at gate %s\n' "$FAILED_GATE"
    else
      printf 'result: plan complete; no gate failed\n'
    fi
    printf 'rollback: the old VP session %s stays authoritative; it was never stopped, signalled or messaged\n' "$VP"
    if [ -n "$FAILED_GATE" ]; then
      printf 'rollback: the failed home is preserved for diagnosis, not removed\n'
    fi
    printf 'rollback: no live session was touched by this run\n'
    printf 'cutover: operator step; --execute is refused by this tool\n'
  } > "$RECEIPT" || refuse 2 "could not write the receipt: $RECEIPT"
}

finish() {
  write_receipt
  printf 'receipt: %s\n' "$RECEIPT"
  if [ -n "$FAILED_GATE" ]; then
    printf 'fm-vp-migrate: failed at gate %s\n' "$FAILED_GATE" >&2
    exit 1
  fi
  exit 0
}

# --- gate: vp-record ----------------------------------------------------------
#
# Read-only, and matched on the record's own `name` field rather than on a file
# name, because the file is keyed by pid. A pid-keyed guess would migrate
# whichever session happened to inherit that pid.
VP_CWD=
if [ ! -d "$SESSIONS_DIR" ]; then
  fail_gate vp-record "sessions directory is absent: $SESSIONS_DIR"
  finish
fi
VP_RECORD=$(
  for f in "$SESSIONS_DIR"/*.json; do
    [ -f "$f" ] || continue
    python3 - "$f" "$VP" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
try:
    with open(path) as fh:
        rec = json.load(fh)
except Exception:
    sys.exit(0)
if isinstance(rec, dict) and rec.get("name") == want:
    print(path)
PY
  done
)
case "$VP_RECORD" in
  '') fail_gate vp-record "no session record names a VP called '$VP' under $SESSIONS_DIR"; finish ;;
  *$'\n'*) fail_gate vp-record "more than one session record names '$VP'; refusing to guess which is authoritative"; finish ;;
esac
VP_CWD=$(python3 - "$VP_RECORD" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    rec = json.load(fh)
print(rec.get("cwd", ""))
PY
)
if [ -z "$VP_CWD" ]; then
  fail_gate vp-record "the record for '$VP' carries no cwd, so its repo scope cannot be preserved"
  finish
fi
record vp-record pass "$VP_RECORD"

# --- gate: repo-scope ---------------------------------------------------------
#
# Preserving repo scope means the new home is scoped to the SAME repository the
# VP already works in, so --repo must contain the VP's own cwd. A --repo that
# does not is a mis-targeted migration, caught before anything is seeded.
repo_abs=$(cd "$REPO" 2>/dev/null && pwd -P) || repo_abs=
if [ -z "$repo_abs" ]; then
  fail_gate repo-scope "--repo is not an existing directory: $REPO"
  finish
fi
cwd_abs=$(cd "$VP_CWD" 2>/dev/null && pwd -P) || cwd_abs=$VP_CWD
case "$cwd_abs/" in
  "$repo_abs/"*) record repo-scope pass "$repo_abs contains the VP cwd $cwd_abs" ;;
  *)
    fail_gate repo-scope "the VP's cwd ($cwd_abs) is not inside --repo ($repo_abs)"
    finish
    ;;
esac

# --- gate: charter ------------------------------------------------------------
CHARTER_SOURCE=
if [ -n "${FM_SECONDMATE_CHARTER:-}" ]; then
  CHARTER_SOURCE='FM_SECONDMATE_CHARTER (inline)'
  record charter pass "$CHARTER_SOURCE"
elif [ -f "$repo_abs/data/charter.md" ]; then
  CHARTER_SOURCE="$repo_abs/data/charter.md"
  record charter pass "$CHARTER_SOURCE"
else
  record charter skipped "unmeasured: no filled charter brief and FM_SECONDMATE_CHARTER is unset; the seed would derive one"
fi

# --- gate: harness-selection --------------------------------------------------
#
# A Claude Code session record carries its harness implicitly (version,
# entrypoint, kind) but has no AI_SESSION_ROLE field, so the role is recorded as
# unmeasured unless --role names it. Inventing one would silently re-charter the
# migrated VP.
HARNESS=$(python3 - "$VP_RECORD" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    rec = json.load(fh)
print("claude" if rec.get("version") and rec.get("entrypoint") else "")
PY
)
if [ -z "$HARNESS" ]; then
  record harness-selection skipped "unmeasured: the record carries no harness marker"
elif [ -n "$ROLE" ]; then
  record harness-selection pass "harness=$HARNESS role=$ROLE"
else
  record harness-selection skipped "unmeasured: harness=$HARNESS, but the record carries no AI_SESSION_ROLE; pass --role to carry it over"
fi

# --- gate: beads-ownership ----------------------------------------------------
#
# Read-only in every branch, and read through the home's own tasks-axi wrapper
# rather than a bare backend CLI. The wrapper owns backlog addressing and
# backend resolution, so going around it would read a different queue than the
# lifecycle transitions do - which is exactly what fm-lint.sh's backend-purity
# check refuses. The cost is that an absent tasks-axi makes this gate
# unmeasurable, and an unmeasurable gate is recorded as such: an empty - and
# therefore falsely reassuring - ownership set is never reported as a pass.
BACKLOG_OUT=$(FM_HOME="${FM_HOME:-$repo_abs}" "$SCRIPT_DIR/fm-tasks-axi.sh" list 2>&1) || BACKLOG_OUT=
if [ -z "$BACKLOG_OUT" ]; then
  record beads-ownership skipped "unmeasured: the tasks-axi wrapper returned nothing for $repo_abs (tasks-axi absent, or no backlog resolved)"
else
  OWNED=$(printf '%s\n' "$BACKLOG_OUT" | grep -c -- "$VP") || OWNED=0
  record beads-ownership pass "$OWNED backlog row(s) mentioning $VP in $repo_abs (read-only, via fm-tasks-axi.sh)"
fi

# --- gate: home-seed ----------------------------------------------------------
#
# Validated, never performed: a dry run proves the home PATH is seedable and
# stops. The real seed is bin/fm-home-seed.sh, invoked by the operator's
# cutover.
: "${HOME_DIR:=${FM_HOME:-$repo_abs}/secondmates/$VP}"
case "$HOME_DIR" in
  /*) ;;
  *) fail_gate home-seed "the secondmate home must be an absolute path: $HOME_DIR"; finish ;;
esac
if [ -e "$HOME_DIR" ] && [ ! -d "$HOME_DIR" ]; then
  fail_gate home-seed "the secondmate home path exists and is not a directory: $HOME_DIR"
  finish
fi
if [ -d "$HOME_DIR" ] && [ ! -f "$HOME_DIR/.fm-secondmate-home" ]; then
  fail_gate home-seed "$HOME_DIR already exists and is not a firstmate secondmate home; seeding would convert it in place"
  finish
fi
seed_parent=$(dirname "$HOME_DIR")
if [ ! -d "$seed_parent" ]; then
  fail_gate home-seed "the secondmate home's parent directory does not exist: $seed_parent"
  finish
fi
if [ ! -w "$seed_parent" ]; then
  fail_gate home-seed "the secondmate home's parent directory is not writable: $seed_parent"
  finish
fi
# Nothing was created: assert that, rather than assuming it.
if [ ! -e "$HOME_DIR" ]; then
  record home-seed "skipped(dry-run)" "would seed $HOME_DIR via fm-home-seed.sh '$VP' '$HOME_DIR' '$repo_abs'; path validated, nothing created"
else
  record home-seed "skipped(dry-run)" "would re-use the existing secondmate home $HOME_DIR; nothing written"
fi

# --- gate: route-register -----------------------------------------------------
#
# The registry is only READ. When a registry exists its bindings are validated
# with the shipped parser (secondmate_registry_validate_bindings), so a
# migration that would collide with, nest inside, or duplicate an existing
# route fails here instead of after a half-written registry.
REGISTRY=${FM_DATA_OVERRIDE:-${FM_HOME:-$repo_abs}/data}/secondmates.md
if [ -f "$REGISTRY" ]; then
  if secondmate_registry_validate_bindings "$REGISTRY" secondmate_registry_path_key; then
    if secondmate_registry_line_for_id "$REGISTRY" "$VP" >/dev/null 2>&1; then
      record route-register "skipped(dry-run)" "$VP already has a registry binding at $SECONDMATE_REGISTRY_HOME; the seed would reconcile it"
    else
      record route-register "skipped(dry-run)" "existing bindings in $REGISTRY validate; would add a route for $VP"
    fi
  else
    fail_gate route-register "$SECONDMATE_REGISTRY_ERROR"
    finish
  fi
else
  record route-register "skipped(dry-run)" "no registry at $REGISTRY yet; the seed would create the first binding"
fi

# --- the three gates a dry run cannot reach -----------------------------------
record reconcile "skipped(dry-run)" "would run fm-secondmate-reconcile.sh against the replacement's home"
record native-dispatch-proof "skipped(dry-run)" "requires a live replacement session; never recorded as pass by a dry run"
record cutover "skipped(dry-run)" "operator step: stop $VP, make the replacement authoritative, retire the old authority record"

finish
