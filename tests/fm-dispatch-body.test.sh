#!/usr/bin/env bash
# Behavior tests for the durable dispatch-body broker (bin/fm-dispatch-body.py) and
# its two faces, the recipient claim gate (bin/fm-receive.sh) and the owning chief's
# forward entry point (bin/fm-forward-receive.sh).
#
# What these guard: the database is the sole body authority. A stage commits one
# canonical, RFC 8785-hashed body and is idempotent for the same id and content but
# a terminal conflict for the same id with anything different. A claim is atomic:
# under a real three-route race exactly one caller receives the body, and every
# loser, late doorbell, expired, or unknown id receives only the stored receipt.
# The body is returned only to its addressed VP and only while the object is
# staged or resumable by its own claim token; injection, terminal outcomes,
# expiry and reconcile-required all NULL the body in the same transaction. Nothing
# is ever guessed: a missing home, an unowned or readable database, a bad
# timestamp, or a non-UTF-8 body refuses before any change. Every command is
# exercised as a subprocess against a real SQLite file in a fresh temp home.
set -u

# shellcheck source=tests/lib.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BROKER="$ROOT/bin/fm-dispatch-body.py"
RECEIVE="$ROOT/bin/fm-receive.sh"
FORWARD="$ROOT/bin/fm-forward-receive.sh"
TMP_ROOT=$(fm_test_tmproot fm-dispatch-body)

unset FM_HOME FM_DISPATCH_BODY_DB

command -v python3 >/dev/null 2>&1 || { printf 'skip: python3 not found\n'; exit 0; }
python3 -c 'import sqlite3' 2>/dev/null || { printf 'skip: python3 has no sqlite3 module\n'; exit 0; }

# Every fixture timestamp is anchored to the run's own clock, never to a literal
# date. Literal dates made the suite a time bomb: the fixture window closed at a
# fixed instant, after which every claim that does not pass its own --now found
# the object expired and returned a receipt (exit 4) instead of the body.
# ts <offset-seconds> prints an RFC 3339 UTC instant relative to now (python
# rather than `date -d`, which is GNU-only and this fork also runs on macOS).
ts() {
  python3 -c 'import sys, datetime as d; print((d.datetime.now(d.timezone.utc) + d.timedelta(seconds=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"
}
STAGED_AT=$(ts -3600)          # the fixture was staged an hour ago
BEFORE_STAGED_AT=$(ts -7200)   # earlier than that, for the inverted-expiry case
WITHIN_WINDOW_AT=$(ts 0)       # inside the fixture's 24h window
DEADLINE_AT=$(ts 82800)        # the fixture's expiry: staged + 24h
PAST_DEADLINE_AT=$(ts 108000)  # after the deadline, for the expiry sweep
BEFORE_RETENTION_AT=$(ts 345600)  # staged + 4 days: inside the 7-day retention
AFTER_RETENTION_AT=$(ts 1123200)  # staged + 13 days: past it

# run <expected-exit> <label> <cmd...>: capture combined output into OUT, exit into RC.
OUT=
RC=0
run() {
  local expected=$1 label=$2
  shift 2
  set +e
  OUT=$("$@" 2>&1)
  RC=$?
  expect_code "$expected" "$RC" "$label"
}
set +e

# json <path-expr> reads one field from $OUT (python, so nested keys work): json receipt.state
json() {
  printf '%s' "$OUT" | python3 -c '
import json, sys
obj = json.loads(sys.stdin.read())
for key in sys.argv[1].split("."):
    obj = obj[key] if not isinstance(obj, list) else obj[int(key)]
print(obj if not isinstance(obj, (dict, list)) else json.dumps(obj, sort_keys=True))
' "$1"
}

# db_field <db> <dispatch-id> <column>: read straight from SQLite (the real boundary, not the CLI).
db_field() {
  python3 - "$1" "$2" "$3" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
row = conn.execute(f"SELECT {sys.argv[3]} FROM dispatch_bodies WHERE dispatch_id=?", (sys.argv[2],)).fetchone()
print("<no-row>" if row is None else ("<NULL>" if row[0] is None else row[0]))
PY
}

new_home() {  # <name> -> prints a fresh private home
  local home="$TMP_ROOT/$1"
  mkdir -p "$home/state" "$home/config"
  chmod 700 "$home"
  printf '%s\n' "$home"
}

BODY_FILE="$TMP_ROOT/body.txt"
printf 'Chief-of-staff dispatch cos-1 for aih-3.\n\nPlease invoke your /next skill now.\nReply: invoked /next, run id cos-1, outcome <ok|blocked|declined>\n  trailing spaces and unicode: caf\xc3\xa9 \xe2\x80\x94 \xf0\x9f\x9a\xa2\n' > "$BODY_FILE"
BODY_SHA=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$BODY_FILE")

# body_sha_of_json: SHA-256 of the body_utf8 field in $OUT, so byte-exactness (including a
# trailing newline that $(...) would strip) is compared without lossy capture.
body_sha_of_json() {
  printf '%s' "$OUT" | python3 -c 'import hashlib,json,sys; print(hashlib.sha256(json.loads(sys.stdin.read())["body_utf8"].encode("utf-8")).hexdigest())'
}

# db_body_sha <db> <dispatch-id>: SHA-256 of the stored body, read straight from SQLite.
db_body_sha() {
  python3 - "$1" "$2" <<'PYX'
import hashlib, sqlite3, sys
row = sqlite3.connect(sys.argv[1]).execute("SELECT body_utf8 FROM dispatch_bodies WHERE dispatch_id=?", (sys.argv[2],)).fetchone()
print("<no-row>" if row is None else ("<NULL>" if row[0] is None else hashlib.sha256(row[0].encode("utf-8")).hexdigest()))
PYX
}

stage() {  # <db> <id> [extra args...]  (fixed identity fields)
  local db=$1 id=$2
  shift 2
  python3 "$BROKER" --db "$db" stage --dispatch-id "$id" --vp-id vp/ai-harness/primary \
    --owner-machine-key mk-1 --owner-epoch 4 --chief-generation 7 --staged-by-machine-key mk-1 \
    --created-at "$STAGED_AT" --expires-at "$DEADLINE_AT" "$@"
}

# --- stage: one canonical body, committed before any transport --------------------------------

test_stage_commits_a_private_database_and_a_verifiable_hash() {
  local home db expected_hash
  home=$(new_home stage)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-1 --body-file "$BODY_FILE"
  assert_equals staged "$(json receipt.state)" "a fresh stage is staged"
  assert_equals False "$(json idempotent)" "first stage is not idempotent"
  assert_not_contains "$OUT" "invoke your /next" "stage never echoes the body"
  assert_equals 600 "$(stat -c %a "$db" 2>/dev/null || stat -f %Lp "$db")" "database is created 0600"
  # Positive control on the hash contract: recompute RFC 8785 + domain prefix independently.
  expected_hash=$(python3 - "$BODY_FILE" "$STAGED_AT" "$DEADLINE_AT" <<'PY'
import hashlib, json, sys
body = open(sys.argv[1], "rb").read().decode("utf-8")
payload = {"schema_version": 1, "dispatch_id": "cos-1", "vp_id": "vp/ai-harness/primary",
           "owner_machine_key": "mk-1", "owner_epoch": 4, "chief_generation": 7,
           "staged_by_machine_key": "mk-1", "body_utf8": body,
           "created_at": sys.argv[2], "expires_at": sys.argv[3]}
canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print(hashlib.sha256(b"firstmate-dispatch-body/v1\0" + canon).hexdigest())
PY
)
  assert_equals "$expected_hash" "$(json receipt.message_hash)" "message_hash is SHA-256 over the domain prefix plus RFC 8785 JSON"
  assert_equals "$BODY_SHA" "$(db_body_sha "$db" cos-1)" "the stored body is byte-exact (no normalization)"
  pass "stage commits a 0600 database with the specified canonical hash"
}

test_stage_is_idempotent_for_same_content_and_a_conflict_otherwise() {
  local home db first
  home=$(new_home idem)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "first stage" stage "$db" cos-2 --body-file "$BODY_FILE"
  first=$(json receipt.message_hash)
  run 0 "same stage again" stage "$db" cos-2 --body-file "$BODY_FILE"
  assert_equals True "$(json idempotent)" "same id and content is idempotent"
  assert_equals "$first" "$(json receipt.message_hash)" "idempotent stage returns the original hash"
  printf 'a different prompt\n' > "$TMP_ROOT/other.txt"
  run 3 "different body, same id" stage "$db" cos-2 --body-file "$TMP_ROOT/other.txt"
  assert_contains "$OUT" "conflict" "the conflict is named"
  assert_contains "$OUT" "body_utf8" "the differing field is named"
  assert_equals "$first" "$(db_field "$db" cos-2 message_hash)" "a conflict changes nothing"
  run 3 "different epoch, same id" python3 "$BROKER" --db "$db" stage --dispatch-id cos-2 --vp-id vp/ai-harness/primary \
    --owner-machine-key mk-1 --owner-epoch 5 --chief-generation 7 --staged-by-machine-key mk-1 \
    --created-at "$STAGED_AT" --expires-at "$DEADLINE_AT" --body-file "$BODY_FILE"
  assert_contains "$OUT" "owner_epoch" "a differing owner epoch is named"
  assert_equals 4 "$(db_field "$db" cos-2 owner_epoch)" "the staged epoch is unchanged"
  pass "same id and hash is idempotent; same id with different content, target or epoch is a terminal conflict"
}

test_stage_refuses_invalid_input_before_any_change() {
  local home db
  home=$(new_home invalid)
  db="$home/dispatch-bodies.sqlite3"
  run 2 "no body" stage "$db" cos-3
  assert_contains "$OUT" "body" "missing body is named"
  run 2 "bad timestamp" python3 "$BROKER" --db "$db" stage --dispatch-id cos-3 --vp-id vp --owner-machine-key mk \
    --owner-epoch 1 --chief-generation 1 --staged-by-machine-key mk --created-at "2026-09-26 10:00" --body-file "$BODY_FILE"
  assert_contains "$OUT" "RFC 3339" "bad timestamp is named"
  run 2 "expiry before creation" stage "$db" cos-3 --body-file "$BODY_FILE" --expires-at "$BEFORE_STAGED_AT"
  assert_contains "$OUT" "not after created_at" "inverted expiry is named"
  run 2 "ttl too long" python3 "$BROKER" --db "$db" stage --dispatch-id cos-3 --vp-id vp --owner-machine-key mk \
    --owner-epoch 1 --chief-generation 1 --staged-by-machine-key mk --ttl-seconds 90000 --body-file "$BODY_FILE"
  assert_contains "$OUT" "may only be shortened" "the 24h default may only be shortened"
  run 2 "negative epoch" python3 "$BROKER" --db "$db" stage --dispatch-id cos-3 --vp-id vp --owner-machine-key mk \
    --owner-epoch -1 --chief-generation 1 --staged-by-machine-key mk --body-file "$BODY_FILE"
  assert_contains "$OUT" "owner_epoch" "negative epoch is named"
  printf 'bad \xff byte\n' > "$TMP_ROOT/bad-utf8.txt"
  run 2 "non-UTF-8 body" stage "$db" cos-3 --body-file "$TMP_ROOT/bad-utf8.txt"
  assert_contains "$OUT" "not valid UTF-8" "non-UTF-8 body is named"
  run 2 "id with a newline" stage "$db" "cos
3" --body-file "$BODY_FILE"
  assert_contains "$OUT" "dispatch_id" "a malformed id is named"
  assert_absent "$db" "no refused stage even created the database"
  pass "every invalid stage refuses with exit 2 and writes nothing"
}

test_no_home_is_refused_not_guessed() {
  run 2 "no db, no FM_HOME" env -u FM_HOME -u FM_DISPATCH_BODY_DB python3 "$BROKER" receipt --dispatch-id cos-1
  assert_contains "$OUT" "never guessed" "the refusal says the database is never guessed"
  run 2 "parent dir missing" python3 "$BROKER" --db "$TMP_ROOT/nowhere/dispatch-bodies.sqlite3" init
  assert_contains "$OUT" "does not exist" "a missing home is named, not created"
  pass "with no database named or no home present the broker refuses"
}

test_unowned_or_shared_database_is_refused() {
  local home db
  home=$(new_home shared)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "init" python3 "$BROKER" --db "$db" init
  chmod 644 "$db"
  run 2 "group/other readable db" python3 "$BROKER" --db "$db" receipt --dispatch-id cos-1
  assert_contains "$OUT" "authentication" "a readable database is an authentication refusal"
  chmod 600 "$db"
  run 4 "private db works again (unknown id)" python3 "$BROKER" --db "$db" receipt --dispatch-id cos-1
  chmod 777 "$home"
  run 2 "world-writable home" python3 "$BROKER" --db "$db" receipt --dispatch-id cos-1
  assert_contains "$OUT" "world-writable" "a world-writable home is refused"
  chmod 700 "$home"
  pass "a database or home that another user could read or replace fails closed"
}

# --- claim: exactly one winner, everyone else a receipt -------------------------------------------

test_first_claim_wins_the_body_and_later_routes_get_the_receipt() {
  local home db token
  home=$(new_home claim)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-4 --body-file "$BODY_FILE"
  run 0 "native claim" env FM_HOME="$home" "$RECEIVE" --db "$db" --dispatch-id cos-4 --vp-id vp/ai-harness/primary --route native
  assert_equals True "$(json winner)" "first claim wins"
  assert_equals "$BODY_SHA" "$(body_sha_of_json)" "the winner receives the exact body"
  assert_equals claimed "$(json receipt.state)" "state is claimed"
  assert_equals native "$(json receipt.winner_route)" "winning route recorded"
  token=$(json claim_token)
  [ "${#token}" -ge 32 ] || fail "claim token is unguessably long (got ${#token} chars)"
  assert_present "$home/state/dispatch-inbox/cos-4.json" "winner writes the inbox receipt projection"
  assert_no_grep "invoke your /next" "$home/state/dispatch-inbox/cos-4.json" "the projection carries no body"
  run 4 "agent-mail claim after native won" "$RECEIVE" --db "$db" --dispatch-id cos-4 --vp-id vp/ai-harness/primary --route agent-mail
  assert_not_contains "$OUT" "invoke your /next" "a loser never sees the body"
  assert_equals claimed "$(json receipt.state)" "loser gets the stored receipt"
  assert_equals native "$(json receipt.winner_route)" "receipt names the winner"
  run 4 "fm-send claim after native won" "$RECEIVE" --db "$db" --dispatch-id cos-4 --vp-id vp/ai-harness/primary --route fm-send
  assert_not_contains "$OUT" "invoke your /next" "second loser never sees the body"
  pass "the first claim receives the body once; every later route receives only the receipt"
}

test_three_route_race_has_exactly_one_winner() {
  local home db i winners=0 losers=0 leaks=0
  home=$(new_home race)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-5 --body-file "$BODY_FILE"
  for i in native agent-mail fm-send; do
    ( "$RECEIVE" --db "$db" --dispatch-id cos-5 --vp-id vp/ai-harness/primary --route "$i" > "$TMP_ROOT/race-$i.out" 2>&1; printf '%s' $? > "$TMP_ROOT/race-$i.rc" ) &
  done
  wait
  for i in native agent-mail fm-send; do
    case "$(cat "$TMP_ROOT/race-$i.rc")" in
      0) winners=$((winners + 1)); grep -q "invoke your /next" "$TMP_ROOT/race-$i.out" || fail "winner $i lacks the body" ;;
      4) losers=$((losers + 1)); grep -q "invoke your /next" "$TMP_ROOT/race-$i.out" && leaks=$((leaks + 1)) ;;
      *) fail "route $i exited $(cat "$TMP_ROOT/race-$i.rc"): $(cat "$TMP_ROOT/race-$i.out")" ;;
    esac
  done
  assert_equals 1 "$winners" "exactly one route wins a concurrent claim"
  assert_equals 2 "$losers" "the other two routes get receipts"
  assert_equals 0 "$leaks" "no loser output contains the body"
  pass "three concurrent routes on one staged dispatch produce exactly one winner and no body leak"
}

test_wrong_target_or_hash_gets_nothing_and_changes_nothing() {
  local home db hash
  home=$(new_home target)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-6 --body-file "$BODY_FILE"
  hash=$(json receipt.message_hash)
  run 2 "claim by another VP" "$RECEIVE" --db "$db" --dispatch-id cos-6 --vp-id vp/other/primary --route native
  assert_contains "$OUT" "target-mismatch" "the wrong target is named"
  assert_not_contains "$OUT" "invoke your /next" "no body for the wrong target"
  assert_equals staged "$(db_field "$db" cos-6 state)" "a mismatched target leaves the object staged"
  run 3 "claim with a wrong envelope hash" "$RECEIVE" --db "$db" --dispatch-id cos-6 --vp-id vp/ai-harness/primary --route agent-mail \
    --expected-hash 0000000000000000000000000000000000000000000000000000000000000000
  assert_contains "$OUT" "hash-conflict" "the hash conflict is named"
  assert_not_contains "$OUT" "invoke your /next" "no body on a hash conflict"
  assert_equals staged "$(db_field "$db" cos-6 state)" "a hash conflict leaves the object staged"
  run 0 "claim with the right hash and target" "$RECEIVE" --db "$db" --dispatch-id cos-6 --vp-id vp/ai-harness/primary --route agent-mail --expected-hash "$hash"
  assert_equals "$BODY_SHA" "$(body_sha_of_json)" "positive control: the addressed VP with the right hash wins"
  pass "a dispatch id alone obtains nothing: wrong target refuses, wrong hash conflicts, both leave the object staged"
}

test_unknown_id_is_expired_unknown() {
  local home db
  home=$(new_home unknown)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "init" python3 "$BROKER" --db "$db" init
  run 4 "receive unknown" "$RECEIVE" --db "$db" --dispatch-id cos-none --vp-id vp --route native
  assert_contains "$OUT" "expired/unknown" "unknown id is reported as expired/unknown"
  run 4 "receipt unknown" python3 "$BROKER" --db "$db" receipt --dispatch-id cos-none
  assert_contains "$OUT" "expired/unknown" "receipt of unknown id is expired/unknown"
  pass "an unknown dispatch id can never recreate or recover a body"
}

# --- lifecycle: expiry, injection, terminal, resume, reconcile -----------------------------------

test_expired_object_yields_receipt_and_the_body_is_nulled() {
  local home db
  home=$(new_home expiry)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-7 --body-file "$BODY_FILE"
  run 4 "claim after the deadline" "$RECEIVE" --db "$db" --dispatch-id cos-7 --vp-id vp/ai-harness/primary --route native --now "$DEADLINE_AT"
  assert_equals expired "$(json receipt.state)" "a claim at the deadline finds it expired"
  assert_not_contains "$OUT" "invoke your /next" "no body after expiry"
  assert_equals "<NULL>" "$(db_field "$db" cos-7 body_utf8)" "expiry NULLs the body in the database"
  run 0 "stage another" stage "$db" cos-8 --body-file "$BODY_FILE"
  run 0 "expire-due sweep" python3 "$BROKER" --db "$db" --now "$PAST_DEADLINE_AT" expire-due
  assert_contains "$OUT" "cos-8" "the sweep names what it expired"
  assert_equals "<NULL>" "$(db_field "$db" cos-8 body_utf8)" "the sweep NULLs the body"
  run 0 "stage a live one" stage "$db" cos-9 --body-file "$BODY_FILE"
  run 0 "sweep before deadline" python3 "$BROKER" --db "$db" --now "$WITHIN_WINDOW_AT" expire-due
  assert_equals 0 "$(json count)" "a sweep before the deadline expires nothing"
  assert_equals staged "$(db_field "$db" cos-9 state)" "positive control: a live object stays staged"
  pass "unclaimed expiry records expired, NULLs the body, and returns only a receipt"
}

test_inject_and_terminal_null_the_body_and_need_the_winner_token() {
  local home db token
  home=$(new_home inject)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-10 --body-file "$BODY_FILE"
  run 0 "claim" "$RECEIVE" --db "$db" --dispatch-id cos-10 --vp-id vp/ai-harness/primary --route native
  token=$(json claim_token)
  run 2 "inject with a wrong token" python3 "$BROKER" --db "$db" inject --dispatch-id cos-10 --claim-token not-the-token
  assert_contains "$OUT" "claim-token-mismatch" "wrong token is named"
  assert_equals claimed "$(db_field "$db" cos-10 state)" "wrong token changes nothing"
  assert_equals "$BODY_SHA" "$(db_body_sha "$db" cos-10)" "wrong token keeps the body"
  run 0 "resume with the right token" python3 "$BROKER" --db "$db" resume --dispatch-id cos-10 --claim-token "$token"
  assert_equals "$BODY_SHA" "$(body_sha_of_json)" "the durable winner token resumes the body"
  run 2 "resume with a wrong token" python3 "$BROKER" --db "$db" resume --dispatch-id cos-10 --claim-token nope
  assert_not_contains "$OUT" "invoke your /next" "a wrong token resumes nothing"
  run 0 "inject" python3 "$BROKER" --db "$db" inject --dispatch-id cos-10 --claim-token "$token"
  assert_equals injected "$(json receipt.state)" "injected"
  assert_equals "<NULL>" "$(db_field "$db" cos-10 body_utf8)" "injection NULLs the body in the same transaction"
  run 4 "resume after injection" python3 "$BROKER" --db "$db" resume --dispatch-id cos-10 --claim-token "$token"
  assert_not_contains "$OUT" "invoke your /next" "no body after injection even for the winner"
  run 4 "late native doorbell after injection" "$RECEIVE" --db "$db" --dispatch-id cos-10 --vp-id vp/ai-harness/primary --route native
  assert_equals injected "$(json receipt.state)" "a late claim gets the injected receipt"

  run 0 "stage for terminal" stage "$db" cos-11 --body-file "$BODY_FILE"
  run 0 "claim" "$RECEIVE" --db "$db" --dispatch-id cos-11 --vp-id vp/ai-harness/primary --route fm-send
  token=$(json claim_token)
  run 2 "terminal without a reason" python3 "$BROKER" --db "$db" terminal --dispatch-id cos-11 --claim-token "$token" --reason ""
  run 0 "terminal" python3 "$BROKER" --db "$db" terminal --dispatch-id cos-11 --claim-token "$token" --reason "pane rejected input"
  assert_equals terminal "$(json receipt.state)" "terminal"
  assert_equals "pane rejected input" "$(json receipt.failure_reason)" "failure reason retained"
  assert_equals "<NULL>" "$(db_field "$db" cos-11 body_utf8)" "terminal NULLs the body"
  pass "inject/terminal require the winner token, NULL the body, and leave only a receipt behind"
}

test_reconcile_required_is_surfaced_and_never_restaged() {
  local home db
  home=$(new_home reconcile)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-12 --body-file "$BODY_FILE"
  run 0 "claim" "$RECEIVE" --db "$db" --dispatch-id cos-12 --vp-id vp/ai-harness/primary --route native
  run 0 "token lost on restart" python3 "$BROKER" --db "$db" reconcile-required --dispatch-id cos-12 --reason "claim token not persisted before crash"
  assert_equals reconcile-required "$(json receipt.state)" "state is reconcile-required"
  assert_equals "<NULL>" "$(db_field "$db" cos-12 body_utf8)" "reconcile-required NULLs the body"
  run 4 "claim after reconcile-required" "$RECEIVE" --db "$db" --dispatch-id cos-12 --vp-id vp/ai-harness/primary --route agent-mail
  assert_equals reconcile-required "$(json receipt.state)" "no route can reinject a reconcile-required dispatch"
  run 0 "re-stage same id and content" stage "$db" cos-12 --body-file "$BODY_FILE"
  assert_equals True "$(json idempotent)" "a re-stage is idempotent on the receipt"
  assert_equals reconcile-required "$(db_field "$db" cos-12 state)" "a re-stage never resets the state to staged"
  pass "an unprovable claim becomes reconcile-required, is surfaced, and is never reset or reinjected"
}

# --- forward-receive: metadata for the owner, never the body --------------------------------------

test_forward_receive_returns_metadata_only_and_refuses_a_stale_epoch() {
  local home db hash
  home=$(new_home forward)
  db="$home/dispatch-bodies.sqlite3"
  run 0 "stage" stage "$db" cos-13 --body-file "$BODY_FILE"
  hash=$(json receipt.message_hash)
  run 0 "forward-receive with the current epoch" env FM_HOME="$home" "$FORWARD" --dispatch-id cos-13 --expected-owner-epoch 4 --expected-hash "$hash"
  assert_equals True "$(json deliverable)" "deliverable"
  assert_equals vp/ai-harness/primary "$(json receipt.vp_id)" "metadata names the target VP"
  assert_not_contains "$OUT" "invoke your /next" "forward-receive never exposes the body"
  assert_not_contains "$OUT" "body_utf8" "forward-receive carries no body field at all"
  assert_equals staged "$(db_field "$db" cos-13 state)" "forward-receive does not claim"
  run 3 "stale epoch" "$FORWARD" --db "$db" --dispatch-id cos-13 --expected-owner-epoch 3
  assert_contains "$OUT" "stale-owner" "a stale epoch is stale-owner"
  assert_equals 4 "$(json current_owner_epoch)" "the current epoch is returned for one refreshed forward"
  run 3 "wrong hash" "$FORWARD" --db "$db" --dispatch-id cos-13 --expected-owner-epoch 4 --expected-hash 1111111111111111111111111111111111111111111111111111111111111111
  assert_contains "$OUT" "hash-conflict" "a mismatched forward hash conflicts"
  run 4 "unknown id" "$FORWARD" --db "$db" --dispatch-id cos-none --expected-owner-epoch 4
  assert_contains "$OUT" "cannot create one" "a forward cannot create a body"
  run 2 "no epoch" "$FORWARD" --db "$db" --dispatch-id cos-13
  assert_contains "$OUT" "expected-owner-epoch" "a forward without its believed epoch is refused"
  run 0 "claimed by the VP" "$RECEIVE" --db "$db" --dispatch-id cos-13 --vp-id vp/ai-harness/primary --route native
  run 4 "forward after the claim" "$FORWARD" --db "$db" --dispatch-id cos-13 --expected-owner-epoch 4
  assert_equals claimed "$(json receipt.state)" "after a claim only the receipt remains for a forward"
  pass "forward-receive validates epoch and hash, returns metadata only, and never claims or exposes the body"
}

# --- cleanup: receipts leave only after the journal holds them -----------------------------------

test_cleanup_removes_only_journaled_old_receipts() {
  local home db token hash journal
  home=$(new_home cleanup)
  db="$home/dispatch-bodies.sqlite3"
  journal="$home/dispatch.jsonl"
  run 0 "stage journaled" stage "$db" cos-14 --body-file "$BODY_FILE"
  hash=$(json receipt.message_hash)
  run 0 "claim" "$RECEIVE" --db "$db" --dispatch-id cos-14 --vp-id vp/ai-harness/primary --route native
  token=$(json claim_token)
  run 0 "inject" python3 "$BROKER" --db "$db" --now "$WITHIN_WINDOW_AT" inject --dispatch-id cos-14 --claim-token "$token"
  run 0 "stage unjournaled" stage "$db" cos-15 --body-file "$BODY_FILE"
  run 0 "claim" "$RECEIVE" --db "$db" --dispatch-id cos-15 --vp-id vp/ai-harness/primary --route native
  token=$(json claim_token)
  run 0 "inject" python3 "$BROKER" --db "$db" --now "$WITHIN_WINDOW_AT" inject --dispatch-id cos-15 --claim-token "$token"
  run 2 "cleanup without a journal" python3 "$BROKER" --db "$db" --now "$AFTER_RETENTION_AT" cleanup --journal "$journal"
  assert_contains "$OUT" "journal" "a missing journal refuses cleanup"
  printf '{"dispatch_id":"cos-14","message_hash":"%s","state":"injected"}\n' "$hash" > "$journal"
  run 0 "cleanup too early" python3 "$BROKER" --db "$db" --now "$BEFORE_RETENTION_AT" cleanup --journal "$journal"
  assert_equals "[]" "$(json removed)" "receipts younger than seven days stay"
  run 0 "cleanup after retention" python3 "$BROKER" --db "$db" --now "$AFTER_RETENTION_AT" cleanup --journal "$journal"
  assert_equals '["cos-14"]' "$(json removed)" "only the journaled receipt is removed"
  assert_equals '["cos-15"]' "$(json kept_unjournaled)" "the unjournaled receipt is kept and named"
  assert_equals "<no-row>" "$(db_field "$db" cos-14 state)" "removed row is gone"
  assert_equals injected "$(db_field "$db" cos-15 state)" "kept row remains"
  run 4 "late doorbell after cleanup" "$RECEIVE" --db "$db" --dispatch-id cos-14 --vp-id vp/ai-harness/primary --route native
  assert_contains "$OUT" "expired/unknown" "after cleanup a late doorbell gets expired/unknown"
  pass "cleanup drops a receipt only after retention and only when the journal holds its id, hash and terminal state"
}

# --- the shell faces refuse to guess ------------------------------------------------------------

test_receive_wrapper_refuses_without_a_named_database_or_required_fields() {
  local home
  home=$(new_home wrapper)
  run 2 "no db anywhere" env -u FM_HOME -u FM_DISPATCH_BODY_DB "$RECEIVE" --dispatch-id cos-1 --vp-id vp --route native
  assert_contains "$OUT" "never guesses" "the gate says it never guesses the database"
  run 2 "no vp id" env FM_HOME="$home" "$RECEIVE" --dispatch-id cos-1 --route native
  assert_contains "$OUT" "vp-id is required" "the addressed VP is required"
  run 2 "no route" env FM_HOME="$home" "$RECEIVE" --dispatch-id cos-1 --vp-id vp
  assert_contains "$OUT" "route is required" "the route is required"
  run 2 "bad route" env FM_HOME="$home" "$RECEIVE" --dispatch-id cos-1 --vp-id vp --route pigeon
  assert_contains "$OUT" "route" "an unknown route is refused"
  run 2 "unknown flag" env FM_HOME="$home" "$RECEIVE" --dispatch-id cos-1 --vp-id vp --route native --loud
  assert_contains "$OUT" "unknown argument" "an unknown flag is refused"
  run 0 "help" "$RECEIVE" --help
  assert_contains "$OUT" "claim gate" "help prints the header"
  run 0 "help" "$FORWARD" --help
  assert_contains "$OUT" "forwarded dispatch" "help prints the header"
  pass "the shell faces refuse a missing database, target, or route instead of guessing"
}

# A claim token is only useful if its winner can pass it back on a command line.
# A token that begins with "-" is read as an option, so resume, inject and
# terminal all fail with a usage error and the dispatch can never be finished.
# One claim would only sample the generator, so this exercises it many times.
test_no_minted_claim_token_can_be_read_as_an_option() {
  run 0 "mint many claim tokens" python3 - "$BROKER" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("broker", sys.argv[1])
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)
tokens = [broker.mint_claim_token() for _ in range(2000)]
bad = [t for t in tokens if t.startswith("-")]
assert not bad, f"{len(bad)} minted tokens begin with a dash, e.g. {bad[0]}"
assert len(set(tokens)) == len(tokens), "minted tokens repeated"
assert all(len(t) >= 43 for t in tokens), "minted tokens are too short to be unguessable"
PY
  pass "a minted claim token can never be read as a command-line option"
}

test_stage_commits_a_private_database_and_a_verifiable_hash
test_stage_is_idempotent_for_same_content_and_a_conflict_otherwise
test_stage_refuses_invalid_input_before_any_change
test_no_home_is_refused_not_guessed
test_unowned_or_shared_database_is_refused
test_first_claim_wins_the_body_and_later_routes_get_the_receipt
test_three_route_race_has_exactly_one_winner
test_wrong_target_or_hash_gets_nothing_and_changes_nothing
test_unknown_id_is_expired_unknown
test_expired_object_yields_receipt_and_the_body_is_nulled
test_inject_and_terminal_null_the_body_and_need_the_winner_token
test_reconcile_required_is_surfaced_and_never_restaged
test_forward_receive_returns_metadata_only_and_refuses_a_stale_epoch
test_cleanup_removes_only_journaled_old_receipts
test_receive_wrapper_refuses_without_a_named_database_or_required_fields
test_no_minted_claim_token_can_be_read_as_an_option
