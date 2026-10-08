#!/usr/bin/env bash
# Behavior tests for bin/fm-vp-migrate.sh - the VP-to-secondmate migration
# planner (design AIH-62xkr, T-3.1).
#
# What these guard: a dry run plans every gate and touches nothing. The three
# gates that cannot be proved without a live session - reconcile,
# native-dispatch-proof, cutover - are recorded as skipped(dry-run) and are
# never reported as pass, because a receipt claiming a dispatch proof nobody
# observed is the one output that would make this tool dangerous. A failed gate
# is named in the receipt, exits non-zero, and leaves no half-seeded home, with
# the old VP still authoritative. --execute is refused outright: the live
# cutover stops and starts real CC sessions, so it stays with the operator, and
# no code path here can perform it. Unmeasurable inputs (an absent bd, a missing
# AI_SESSION_ROLE) are recorded as unmeasured rather than fabricated as a pass.
#
# Every case runs against a fixture sessions directory and a fixture home under
# a temp root, so no test here can read, signal, or migrate one of this host's
# live CC sessions.
set -u

# shellcheck source=tests/lib.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CLI="$ROOT/bin/fm-vp-migrate.sh"
TMP_ROOT=$(fm_test_tmproot fm-vp-migrate)

unset FM_HOME FM_CONFIG_OVERRIDE FM_DATA_OVERRIDE FM_ROOT_OVERRIDE FM_SECONDMATE_CHARTER

OUT=
RC=0
run() {
  local expected=$1 label=$2
  shift 2
  set +e
  OUT=$("$@" 2>&1)
  RC=$?
  set -e
  set +e
  expect_code "$expected" "$RC" "$label"
}
set +e

# make_world <name>: a fixture VP named vp-<name> whose cwd sits inside a
# fixture repo, with a fixture sessions dir, homes parent and receipt dir.
# Echoes the world root. Nothing here resembles a live session path.
make_world() {
  local name=$1 world="$TMP_ROOT/$1"
  mkdir -p "$world/sessions" "$world/repo/sub" "$world/homes" "$world/receipts"
  cat > "$world/sessions/4242.json" <<EOF
{"pid":4242,"name":"vp-$name","cwd":"$world/repo/sub","version":"2.1.283","entrypoint":"cli","kind":"interactive"}
EOF
  printf '%s\n' "$world"
}

migrate() {  # <world> <vp> [extra args...]
  local world=$1 vp=$2
  shift 2
  env -u FM_HOME -u FM_DATA_OVERRIDE "$CLI" "$vp" \
    --repo "$world/repo" \
    --sessions-dir "$world/sessions" \
    --home "$world/homes/$vp" \
    --receipt-dir "$world/receipts" \
    --dry-run "$@"
}

ALL_GATES="vp-record repo-scope charter harness-selection beads-ownership home-seed route-register reconcile native-dispatch-proof machine-handoff cutover"

# receipt_gates <receipt>: the gate names the receipt tables, in order. Used to
# compare the receipt's gate SET against ALL_GATES rather than only checking
# that each expected gate is present: a receipt may not quietly grow or drop a
# gate either.
receipt_gates() {
  sed -n 's/^gate: \([^:]*\):.*/\1/p' "$1" | tr '\n' ' ' | sed 's/ $//'
}

test_dry_run_happy_path_records_every_gate_and_touches_nothing() {
  local world receipt gate
  world=$(make_world happy)
  run 0 "dry-run happy path" migrate "$world" vp-happy --role vp
  receipt="$world/receipts/vp-happy.receipt"
  assert_present "$receipt" "a dry run must write a receipt"
  assert_contains "$OUT" "$receipt" "the command must print the receipt path"
  for gate in $ALL_GATES; do
    assert_grep "gate: $gate:" "$receipt" "the receipt must record the $gate gate"
  done
  assert_equals "$ALL_GATES" "$(receipt_gates "$receipt")" \
    "the receipt tables exactly the fixed gate set, in order"
  assert_grep "result: plan complete; no gate failed" "$receipt" "a clean plan says so"
  assert_grep "mode: dry-run" "$receipt" "the receipt records its mode"
  # Nothing seeded, nothing started.
  assert_absent "$world/homes/vp-happy" "a dry run must not create the secondmate home"
  assert_grep "rollback: no live session was touched by this run" "$receipt" "the receipt states the no-touch guarantee"
  pass "a dry run records every T-3.1 gate, writes a receipt, and creates no home"
}

test_dry_run_never_reports_a_proof_it_did_not_observe() {
  local world receipt gate
  world=$(make_world noproof)
  run 0 "dry-run" migrate "$world" vp-noproof --role vp
  receipt="$world/receipts/vp-noproof.receipt"
  # The three gates that need a live session must be skipped, never passed.
  for gate in reconcile native-dispatch-proof cutover; do
    assert_grep "gate: $gate: skipped(dry-run)" "$receipt" "$gate must be skipped under a dry run"
    assert_no_grep "gate: $gate: pass" "$receipt" "$gate must never be reported as pass by a dry run"
  done
  assert_grep "gate: home-seed: skipped(dry-run)" "$receipt" "the seed itself is planned, not performed"
  pass "the gates a dry run cannot reach are skipped(dry-run), never pass"
}

test_preserved_scope_and_unmeasurable_inputs_are_distinguished() {
  local world receipt
  world=$(make_world scope)
  run 0 "dry-run with a role" migrate "$world" vp-scope --role vp
  receipt="$world/receipts/vp-scope.receipt"
  assert_grep "gate: repo-scope: pass" "$receipt" "a repo containing the VP cwd preserves scope"
  assert_grep "contains the VP cwd" "$receipt" "the scope gate names what it compared"
  assert_grep "harness=claude role=vp" "$receipt" "a supplied role is carried over with the harness"
  # Without --role the record carries no AI_SESSION_ROLE, so the gate must say
  # unmeasured rather than invent one.
  world=$(make_world norole)
  run 0 "dry-run without a role" migrate "$world" vp-norole
  receipt="$world/receipts/vp-norole.receipt"
  assert_grep "gate: harness-selection: skipped" "$receipt" "a missing role is not a pass"
  assert_grep "no AI_SESSION_ROLE" "$receipt" "the receipt names why the role is unmeasured"
  # Beads ownership is recorded either way, and never fabricated.
  assert_grep "gate: beads-ownership:" "$receipt" "beads ownership is always recorded"
  assert_no_grep "gate: beads-ownership: fail" "$receipt" "an unreadable beads store is unmeasured, not a failure"
  pass "preserved scope passes while unmeasurable inputs are recorded as unmeasured"
}

test_a_mis_scoped_repo_fails_before_anything_is_seeded() {
  local world receipt
  world=$(make_world misscope)
  mkdir -p "$world/elsewhere"
  run 1 "repo that does not contain the VP cwd" \
    env -u FM_HOME "$CLI" vp-misscope \
      --repo "$world/elsewhere" \
      --sessions-dir "$world/sessions" \
      --home "$world/homes/vp-misscope" \
      --receipt-dir "$world/receipts" \
      --dry-run
  receipt="$world/receipts/vp-misscope.receipt"
  assert_grep "gate: repo-scope: fail" "$receipt" "a mis-scoped migration fails at repo-scope"
  assert_grep "result: FAILED at gate repo-scope" "$receipt" "the receipt names the failed gate"
  assert_contains "$OUT" "failed at gate repo-scope" "the command names the failed gate on stderr"
  assert_absent "$world/homes/vp-misscope" "no home may be seeded after a failed gate"
  assert_grep "stays authoritative" "$receipt" "the old VP stays authoritative"
  pass "a mis-scoped repo fails at its gate, names it, and seeds nothing"
}

test_a_failed_seed_names_the_gate_and_leaves_no_half_seeded_home() {
  local world receipt blocker
  world=$(make_world seedfail)
  # A real, unforced failure condition: the home path already exists as a
  # regular file, so seeding it would have to clobber something. No test seam.
  blocker="$world/homes/vp-seedfail"
  printf 'not a home\n' > "$blocker"
  run 1 "home path occupied by a file" migrate "$world" vp-seedfail --role vp
  receipt="$world/receipts/vp-seedfail.receipt"
  assert_grep "gate: home-seed: fail" "$receipt" "an unseedable home fails at home-seed"
  assert_grep "result: FAILED at gate home-seed" "$receipt" "the receipt names home-seed"
  assert_grep "exists and is not a directory" "$receipt" "the receipt says why the seed is impossible"
  assert_grep "preserved for diagnosis" "$receipt" "T-3.1 requires the failed home be preserved"
  # The blocker is untouched and no home was created around it.
  assert_equals "not a home" "$(cat "$blocker")" "the occupying file must not be overwritten"
  [ ! -d "$blocker" ] || fail "no directory may be created at the occupied home path"
  # The gates after the failure are tabled as blocked, never as passes and
  # never omitted: a receipt missing a gate cannot be told apart from one whose
  # gate passed silently, and T-3.1 asks for the whole gate table.
  assert_equals "$ALL_GATES" "$(receipt_gates "$receipt")" \
    "a failed run still tables the full fixed gate set, in order"
  for gate in route-register reconcile native-dispatch-proof machine-handoff cutover; do
    assert_grep "gate: $gate: skipped (blocked by home-seed)" "$receipt" \
      "$gate is recorded blocked by the gate that failed"
    assert_no_grep "gate: $gate: pass" "$receipt" "$gate must never read as a pass after a failure"
  done
  pass "a failed seed names the gate, preserves the blocker, and leaves no half-seeded home"
}

test_an_existing_non_firstmate_home_is_refused_rather_than_converted() {
  local world receipt
  world=$(make_world convert)
  mkdir -p "$world/homes/vp-convert/some-existing-work"
  run 1 "existing non-firstmate directory" migrate "$world" vp-convert --role vp
  receipt="$world/receipts/vp-convert.receipt"
  assert_grep "gate: home-seed: fail" "$receipt" "converting a populated directory is refused"
  assert_grep "not a firstmate secondmate home" "$receipt" "the refusal names the condition"
  assert_present "$world/homes/vp-convert/some-existing-work" "the existing content is untouched"
  pass "an existing non-firstmate directory is refused, never converted in place"
}

test_an_unknown_or_ambiguous_vp_is_refused_not_guessed() {
  local world receipt
  world=$(make_world unknown)
  run 1 "no record for this VP" migrate "$world" vp-absent
  receipt="$world/receipts/vp-absent.receipt"
  assert_grep "gate: vp-record: fail" "$receipt" "an unknown VP fails at vp-record"
  assert_grep "no session record names" "$receipt" "the receipt names the absence"
  # Two records claiming the same name must not be silently resolved.
  world=$(make_world ambiguous)
  cat > "$world/sessions/9999.json" <<EOF
{"pid":9999,"name":"vp-ambiguous","cwd":"$world/repo/sub","version":"2.1.283","entrypoint":"cli","kind":"interactive"}
EOF
  run 1 "two records name the same VP" migrate "$world" vp-ambiguous
  receipt="$world/receipts/vp-ambiguous.receipt"
  assert_grep "gate: vp-record: fail" "$receipt" "an ambiguous VP fails at vp-record"
  assert_grep "refusing to guess which is authoritative" "$receipt" "ambiguity is refused, not resolved"
  pass "an unknown or ambiguous VP name is refused rather than guessed"
}

test_execute_is_refused_and_names_what_it_would_do() {
  local world
  world=$(make_world execute)
  run 2 "--execute" env -u FM_HOME "$CLI" vp-execute --repo "$world/repo" --execute
  assert_contains "$OUT" "live cutover is an operator step" "the refusal names the reason"
  assert_contains "$OUT" "retire the old VP session" "the refusal enumerates what it would have done"
  assert_contains "$OUT" "stop and start live CC sessions" "the refusal names why it stays with the operator"
  # A refusal must not have written a receipt or seeded anything.
  assert_absent "$world/receipts/vp-execute.receipt" "a refused --execute writes no receipt"
  assert_absent "$world/homes/vp-execute" "a refused --execute seeds nothing"
  run 2 "--dry-run and --execute together" env -u FM_HOME "$CLI" vp-execute --repo "$world/repo" --dry-run --execute
  assert_contains "$OUT" "not both" "naming both modes is refused"
  pass "--execute is refused with status 2 and names exactly what it would have done"
}

test_the_cutover_is_not_implemented_at_all() {
  # The strongest available guarantee that no live session can be touched: the
  # script invokes no process-control command. A refusal that merely gates
  # reachable code would still be one edit away from running it.
  #
  # Scoped to shell commands that could actually stop or drive a session. The
  # script's own refusal text NAMES the steps it declines to perform ("prove one
  # native SendMessage ... cycle"), and matching that prose would be a substring
  # guard deciding something it never scoped - an agent tool is not reachable
  # from bash at all, so its name in a comment is not a capability.
  local verb
  for verb in 'kill ' 'kill -' 'pkill' 'killall' 'tmux '; do
    assert_no_grep "$verb" "$ROOT/bin/fm-vp-migrate.sh" \
      "fm-vp-migrate.sh must not invoke '$verb': the cutover is deliberately unimplemented"
  done
  pass "the live cutover is absent from the script, not merely gated"
}

test_a_receipt_never_references_a_live_session() {
  local world receipt live
  world=$(make_world isolated)
  run 0 "dry-run against fixtures only" migrate "$world" vp-isolated --role vp
  receipt="$world/receipts/vp-isolated.receipt"
  # No live sessions directory, and none of this host's live session names.
  assert_no_grep "/.claude/sessions" "$receipt" "the receipt must not name the live sessions directory"
  for live in aih-1 aih-2 aih-3 aih-4 kg-1 kg-2 kg-3; do
    assert_no_grep "$live" "$receipt" "the receipt must not reference the live session $live"
  done
  # Every path it does name is inside the fixture world.
  assert_grep "$world" "$receipt" "the receipt's paths are fixture paths"
  pass "a fixture dry-run receipt references no live session or live sessions directory"
}

# tasks_axi_shim <world> <<'JSON' ... JSON
# A fixture `tasks-axi` on PATH that prints the given canned body for
# `list --json` and nothing else. tasks-axi is not installed on this host, and
# installing a binary to test a parser would be the wrong trade: what the gate
# must get right is how it reads the rows, not how they were produced. Echoes
# the directory to prepend to PATH.
tasks_axi_shim() {  # <world> [exit-status]  (body on stdin)
  local world=$1 status=${2:-0} dir="$1/shim"
  mkdir -p "$dir" "$world/repo/data"
  cat > "$dir/payload.json"
  cat > "$dir/tasks-axi" <<SHIM
#!/usr/bin/env bash
# Fixture. Answers list --json only; every other invocation is a refusal, so a
# gate that fell back to a different command would not quietly pass.
case "\$*" in
  'list --json') cat "$dir/payload.json"; exit $status ;;
  *) printf 'fixture tasks-axi: unexpected invocation: %s\n' "\$*" >&2; exit 64 ;;
esac
SHIM
  chmod +x "$dir/tasks-axi"
  printf '%s\n' "$dir"
}

# migrate_with_shim <shim-dir> <world> <vp> [extra args...]: migrate() with the
# fixture tasks-axi ahead of PATH. A subshell, because `env` cannot invoke a
# shell function and a bare assignment prefix on one would leak into the suite.
migrate_with_shim() {
  local shim=$1
  shift
  ( PATH="$shim:$PATH"; migrate "$@" )
}

test_backlog_ownership_counts_only_an_owner_field_equal_to_the_vp() {
  local world receipt shim
  world=$(make_world ownactive)
  # Exactly one active row belongs to vp-ownactive: t-1, by its owner field.
  # The decoys are everything that must NOT count. t-2 is the sharp one: its
  # title names the VP, but its owner field gives the row to someone else, so
  # the row is not the VP's - counting it claimed ownership of work another
  # owner field had explicitly assigned away. t-3 is finished, t-4 is a longer
  # name the VP name is a prefix of, t-5 is a prose mention of that longer name.
  shim=$(tasks_axi_shim "$world" <<'JSON'
{"tasks": [
  {"id": "t-1", "state": "in_flight", "owner": "vp-ownactive", "title": "live work"},
  {"id": "t-2", "state": "Queued", "owner": "someone-else", "title": "hand off to vp-ownactive"},
  {"id": "t-3", "state": "Done", "owner": "vp-ownactive", "title": "finished work"},
  {"id": "t-4", "state": "in_flight", "owner": "vp-ownactive-deputy", "title": "a different owner"},
  {"id": "t-5", "state": "queued", "owner": "nobody", "title": "see vp-ownactive-deputy/notes"}
]}
JSON
  )
  run 0 "owner-field ownership" migrate_with_shim "$shim" "$world" vp-ownactive --role vp
  receipt="$world/receipts/vp-ownactive.receipt"
  assert_grep "gate: beads-ownership: pass (1 of 4 active row(s) name vp-ownactive in an owner field" "$receipt" \
    "only an owner field equal to the VP counts toward the pass"
  assert_grep "1 mention vp-ownactive in title/body, not counted" "$receipt" \
    "a title mention is reported and labelled not-counted, never counted as ownership"
  assert_no_grep "2 of 4" "$receipt" "the row owned by someone else must not be counted as the VP's"
  assert_grep "list --json" "$receipt" "the receipt names the structured query it ran"

  # A row whose id equals the VP name is not ownership either: an id is an
  # identifier, not an owner, and the VP's own name as a row id says nothing
  # about who holds the row.
  world=$(make_world ownid)
  shim=$(tasks_axi_shim "$world" <<'JSON'
{"tasks": [
  {"id": "vp-ownid", "state": "in_flight", "owner": "someone-else", "title": "a row named after the VP"}
]}
JSON
  )
  run 0 "id equal to the VP" migrate_with_shim "$shim" "$world" vp-ownid --role vp
  receipt="$world/receipts/vp-ownid.receipt"
  assert_grep "gate: beads-ownership: pass (0 of 1 active row(s) name vp-ownid in an owner field" "$receipt" \
    "a row id equal to the VP name is not an ownership claim"
  pass "backlog ownership counts an owner field equal to the VP and nothing else"
}

test_rows_with_no_owner_field_are_unmeasured_rather_than_counted_by_mention() {
  local world receipt shim
  # A listing that never expresses ownership cannot be read for ownership. A
  # zero here would be an artefact of the schema, and counting the mentions
  # instead was the false-ownership path: the gate says unmeasured and reports
  # the mentions as the reason to look, not as a count of owned work.
  world=$(make_world ownnofield)
  shim=$(tasks_axi_shim "$world" <<'JSON'
{"tasks": [
  {"id": "t-1", "state": "in_flight", "title": "vp-ownnofield is mentioned here"},
  {"id": "t-2", "state": "queued", "body": "escalate to vp-ownnofield"},
  {"id": "t-3", "state": "Done", "title": "vp-ownnofield finished this"}
]}
JSON
  )
  run 0 "rows carry no owner field" migrate_with_shim "$shim" "$world" vp-ownnofield --role vp
  receipt="$world/receipts/vp-ownnofield.receipt"
  assert_grep "gate: beads-ownership: skipped (unmeasured: rows carry no owner field; 2 active rows mention vp-ownnofield in title/body, not counted)" "$receipt" \
    "rows with no owner field are unmeasured, with the mentions reported and not counted"
  assert_no_grep "gate: beads-ownership: pass" "$receipt" \
    "a listing that never expresses ownership must not read as a measured zero or a count"
  pass "rows carrying no owner field are unmeasured, never ownership inferred from a mention"
}

test_a_real_zero_passes_while_an_unreadable_or_absent_backlog_does_not() {
  local world receipt shim
  # 1. A query that succeeded and found no active work is a pass, and says so.
  world=$(make_world ownzero)
  shim=$(tasks_axi_shim "$world" <<'JSON'
{"tasks": [{"id": "t-1", "state": "Done", "owner": "vp-ownzero", "title": "finished"}]}
JSON
  )
  run 0 "no active rows" migrate_with_shim "$shim" "$world" vp-ownzero --role vp
  receipt="$world/receipts/vp-ownzero.receipt"
  assert_grep "gate: beads-ownership: pass (0 active rows" "$receipt" \
    "a query that succeeded with no active work is a real zero"

  # 2. A shape nobody can parse is a failure, never a pass: an unreadable
  # listing is unknown ownership, not absent ownership.
  world=$(make_world ownjunk)
  shim=$(tasks_axi_shim "$world" <<'JSON'
this is not json
JSON
  )
  run 1 "unparseable listing" migrate_with_shim "$shim" "$world" vp-ownjunk --role vp
  receipt="$world/receipts/vp-ownjunk.receipt"
  assert_grep "gate: beads-ownership: fail" "$receipt" "an unparseable listing fails the gate"
  assert_grep "cannot read" "$receipt" "the receipt says the shape could not be read"
  assert_no_grep "gate: beads-ownership: pass" "$receipt" "an unreadable listing must never pass"
  assert_grep "result: FAILED at gate beads-ownership" "$receipt" "the run stops at the gate it could not measure"
  assert_grep "gate: home-seed: skipped (blocked by beads-ownership)" "$receipt" \
    "the later gates are still tabled, as blocked"

  # 3. Valid JSON of the wrong shape is a failure too: a gate that shrugged at
  # an object it did not recognise would report zero owned work for every
  # future schema change.
  world=$(make_world ownshape)
  shim=$(tasks_axi_shim "$world" <<'JSON'
{"schema": 9, "payload": {"things": 3}}
JSON
  )
  run 1 "valid JSON, unrecognised shape" migrate_with_shim "$shim" "$world" vp-ownshape --role vp
  receipt="$world/receipts/vp-ownshape.receipt"
  assert_grep "gate: beads-ownership: fail" "$receipt" "an unrecognised shape fails rather than counting zero"
  assert_grep "no row list found" "$receipt" "the receipt names what it could not find"

  # 4. A wrapper that failed is unmeasured, not a pass and not a failure: on a
  # host with no tasks-axi there is nothing to read, and an empty - therefore
  # falsely reassuring - ownership set is the one answer this must never give.
  world=$(make_world ownfail)
  shim=$(tasks_axi_shim "$world" 7 <<'JSON'
{"tasks": []}
JSON
  )
  run 0 "wrapper exits non-zero" migrate_with_shim "$shim" "$world" vp-ownfail --role vp
  receipt="$world/receipts/vp-ownfail.receipt"
  assert_grep "gate: beads-ownership: skipped (unmeasured:" "$receipt" \
    "a failed wrapper is unmeasured"
  assert_no_grep "gate: beads-ownership: pass" "$receipt" "a failed wrapper must not read as a pass"
  pass "a real zero passes; an unreadable shape fails; an unavailable wrapper is unmeasured"
}

test_the_machine_handoff_gate_is_tabled_and_never_passes() {
  local world receipt
  # A same-machine move does not invoke the handoff protocol, and says so
  # rather than leaving the requirement off the receipt.
  world=$(make_world handoffsame)
  run 0 "same-machine move" migrate "$world" vp-handoffsame --role vp
  receipt="$world/receipts/vp-handoffsame.receipt"
  assert_grep "gate: machine-handoff: skipped (not applicable: same-machine migration)" "$receipt" \
    "a same-machine move records the handoff gate as not applicable"

  # Naming the same key on both sides is still a same-machine move.
  world=$(make_world handoffsamekey)
  run 0 "same key both sides" migrate "$world" vp-handoffsamekey --role vp \
    --from-machine box-a --to-machine box-a
  receipt="$world/receipts/vp-handoffsamekey.receipt"
  assert_grep "gate: machine-handoff: skipped (not applicable: same-machine migration)" "$receipt" \
    "one machine named twice is a same-machine move"

  # A cross-machine move needs the prepared/accepted handoff protocol, which is
  # not implemented here, so the plan FAILS at this gate and exits non-zero. A
  # pass would assert agreement between a destination-bound epoch and an
  # acceptance receipt that nobody produced; a skip plus exit 0 plus "plan
  # complete" is the same lie one step quieter - it reports a cross-machine
  # migration as fully planned when its one cross-machine requirement has no
  # implementation.
  world=$(make_world handoffcross)
  run 1 "cross-machine move" migrate "$world" vp-handoffcross --role vp \
    --from-machine box-a --to-machine box-b
  receipt="$world/receipts/vp-handoffcross.receipt"
  assert_grep "gate: machine-handoff: fail (unimplemented: cross-machine handoff protocol is gated; see design T-3.1)" "$receipt" \
    "a cross-machine move fails on the unimplemented handoff protocol"
  assert_grep "result: FAILED at gate machine-handoff" "$receipt" \
    "a required gate nobody implemented is not a complete plan"
  assert_no_grep "result: plan complete" "$receipt" \
    "a cross-machine plan must never read as complete"
  assert_grep "gate: cutover: skipped (blocked by machine-handoff)" "$receipt" \
    "the gates after the failure are tabled as blocked"
  assert_equals "$ALL_GATES" "$(receipt_gates "$receipt")" \
    "the failed cross-machine run still tables the full fixed gate set, in order"
  assert_contains "$OUT" "failed at gate machine-handoff" "the command names the failed gate on stderr"
  assert_no_grep "gate: machine-handoff: pass" "$receipt" \
    "the handoff gate must never report a pass"
  assert_absent "$world/homes/vp-handoffcross" "a failed cross-machine plan seeds nothing"

  # --to-machine alone, with no source named, is a cross-machine move: a
  # planner that treated an unnamed source as 'this machine' would call it
  # same-machine and skip the protocol.
  world=$(make_world handoffto)
  run 1 "--to-machine with no --from-machine" migrate "$world" vp-handoffto --role vp \
    --to-machine box-b
  receipt="$world/receipts/vp-handoffto.receipt"
  assert_grep "gate: machine-handoff: fail (unimplemented" "$receipt" \
    "naming only a destination machine is a cross-machine move"
  pass "the machine-handoff requirement is always tabled: not-applicable, or a failure, never a pass"
}

test_a_receipt_destination_inside_the_live_chief_home_is_refused() {
  local world home receipt_link
  world=$(make_world receiptguard)
  # A fixture standing in for a live chief home, with the real live receipt
  # location under it. Nothing here is this host's actual chief home.
  home="$world/chief-home"
  mkdir -p "$home/state/migrations"

  # 1. The live receipt location itself, named directly.
  run 2 "--receipt-dir inside FM_HOME" \
    env FM_HOME="$home" "$CLI" vp-receiptguard \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --home "$world/homes/vp-receiptguard" \
      --receipt-dir "$home/state/migrations" --dry-run
  assert_contains "$OUT" "resolves inside the live chief home" "the refusal names the guarantee"
  assert_contains "$OUT" "$home/state/migrations" "the refusal names the resolved path"
  assert_absent "$home/state/migrations/vp-receiptguard.receipt" "no receipt may land in the live chief home"

  # 2. FM_HOME itself.
  run 2 "--receipt-dir equal to FM_HOME" \
    env FM_HOME="$home" "$CLI" vp-receiptguard \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --receipt-dir "$home" --dry-run
  assert_absent "$home/vp-receiptguard.receipt" "the home root is refused too"

  # 3. A symlink pointing in. A literal prefix test says this is outside the
  # home; the physical resolution says otherwise, and the physical answer is the
  # one the write obeys.
  receipt_link="$world/looks-outside"
  ln -s "$home/state/migrations" "$receipt_link"
  run 2 "--receipt-dir is a symlink into FM_HOME" \
    env FM_HOME="$home" "$CLI" vp-receiptguard \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --receipt-dir "$receipt_link" --dry-run
  assert_contains "$OUT" "resolves inside the live chief home" "a symlinked destination is resolved, not trusted"
  assert_absent "$home/state/migrations/vp-receiptguard.receipt" "a symlinked destination writes nothing into the home"

  # 4. The default destination: TMPDIR pointing into the home must be refused
  # before mktemp creates anything there.
  run 2 "TMPDIR inside FM_HOME with no --receipt-dir" \
    env FM_HOME="$home" TMPDIR="$home/state" "$CLI" vp-receiptguard \
      --repo "$world/repo" --sessions-dir "$world/sessions" --dry-run
  assert_contains "$OUT" "TMPDIR" "the refusal names TMPDIR as the destination it rejected"
  [ -z "$(find "$home/state" -maxdepth 1 -name 'fm-vp-migrate.*' -print -quit)" ] \
    || fail "a refused TMPDIR must not leave a temp receipt directory in the chief home"

  # Negative arm: with FM_HOME set, a destination OUTSIDE it still works. Without
  # this the refusals above would also be satisfied by a guard that refuses
  # everything.
  run 0 "--receipt-dir outside FM_HOME while FM_HOME is set" \
    env FM_HOME="$home" "$CLI" vp-receiptguard \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --home "$world/homes/vp-receiptguard" \
      --receipt-dir "$world/receipts" --dry-run --role vp
  assert_present "$world/receipts/vp-receiptguard.receipt" "a destination outside the chief home is accepted"
  pass "a receipt destination resolving into the live chief home is refused, named, and writes nothing"
}

test_the_receipt_guard_uses_the_same_fallback_home_the_gates_do() {
  local world
  # With FM_HOME unset the gates below fall back to the repo root as the home:
  # the backlog query runs with FM_HOME=<repo>, the default secondmate home is
  # <repo>/secondmates/<vp>, and the registry is read from <repo>/data. A guard
  # that keyed on FM_HOME alone returned immediately in exactly that case, so a
  # receipt could land in the directory the same run calls the live home.
  world=$(make_world guardfallback)
  mkdir -p "$world/repo/state/migrations"
  run 2 "--receipt-dir inside the fallback home, FM_HOME unset" \
    env -u FM_HOME -u FM_DATA_OVERRIDE "$CLI" vp-guardfallback \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --home "$world/homes/vp-guardfallback" \
      --receipt-dir "$world/repo/state/migrations" --dry-run
  assert_contains "$OUT" "resolves inside the live chief home" "the fallback home is guarded too"
  assert_contains "$OUT" "$world/repo/state/migrations" "the refusal names the resolved path"
  assert_absent "$world/repo/state/migrations/vp-guardfallback.receipt" \
    "no receipt may land in the home the gates fall back to"

  # The repo root itself, and the default destination's TMPDIR, are the same
  # question asked twice more.
  run 2 "--receipt-dir equal to the fallback home" \
    env -u FM_HOME -u FM_DATA_OVERRIDE "$CLI" vp-guardfallback \
      --repo "$world/repo" --sessions-dir "$world/sessions" \
      --receipt-dir "$world/repo" --dry-run
  assert_absent "$world/repo/vp-guardfallback.receipt" "the fallback home root is refused too"
  run 2 "TMPDIR inside the fallback home, FM_HOME unset" \
    env -u FM_HOME -u FM_DATA_OVERRIDE TMPDIR="$world/repo/state" "$CLI" vp-guardfallback \
      --repo "$world/repo" --sessions-dir "$world/sessions" --dry-run
  assert_contains "$OUT" "TMPDIR" "the refusal names TMPDIR as the destination it rejected"
  [ -z "$(find "$world/repo/state" -maxdepth 1 -name 'fm-vp-migrate.*' -print -quit)" ] \
    || fail "a refused TMPDIR must not leave a temp receipt directory in the fallback home"

  # Negative arm: with FM_HOME unset, a destination outside the repo still
  # works, so the arms above are not satisfied by a guard that refuses
  # everything once FM_HOME is absent.
  run 0 "--receipt-dir outside the fallback home, FM_HOME unset" \
    migrate "$world" vp-guardfallback --role vp
  assert_present "$world/receipts/vp-guardfallback.receipt" \
    "a destination outside the fallback home is accepted"
  pass "the receipt guard refuses the fallback home the gates use, not only an explicit FM_HOME"
}

test_arguments_are_validated_before_any_work() {
  local world
  world=$(make_world args)
  run 2 "no mode named" env -u FM_HOME "$CLI" vp-args --repo "$world/repo"
  assert_contains "$OUT" "name a mode" "a missing mode is refused"
  run 2 "no repo" env -u FM_HOME "$CLI" vp-args --dry-run
  assert_contains "$OUT" "--repo is required" "a missing repo scope is refused, never inferred"
  run 2 "no vp" env -u FM_HOME "$CLI" --repo "$world/repo" --dry-run
  assert_contains "$OUT" "a VP name is required" "a missing VP name is refused"
  run 2 "two vps" env -u FM_HOME "$CLI" vp-a vp-b --repo "$world/repo" --dry-run
  assert_contains "$OUT" "exactly one VP" "two VP names are refused"
  run 2 "unsafe vp name" env -u FM_HOME "$CLI" 'vp;rm' --repo "$world/repo" --dry-run
  assert_contains "$OUT" "not a safe session name" "an unsafe VP name is refused"
  run 2 "unknown option" env -u FM_HOME "$CLI" vp-args --repo "$world/repo" --dry-run --wat
  assert_contains "$OUT" "unknown option" "an unknown option is refused"
  pass "arguments are validated and refused before any gate runs"
}

test_dry_run_happy_path_records_every_gate_and_touches_nothing
test_dry_run_never_reports_a_proof_it_did_not_observe
test_preserved_scope_and_unmeasurable_inputs_are_distinguished
test_a_mis_scoped_repo_fails_before_anything_is_seeded
test_a_failed_seed_names_the_gate_and_leaves_no_half_seeded_home
test_an_existing_non_firstmate_home_is_refused_rather_than_converted
test_an_unknown_or_ambiguous_vp_is_refused_not_guessed
test_execute_is_refused_and_names_what_it_would_do
test_the_cutover_is_not_implemented_at_all
test_a_receipt_never_references_a_live_session
test_backlog_ownership_counts_only_an_owner_field_equal_to_the_vp
test_rows_with_no_owner_field_are_unmeasured_rather_than_counted_by_mention
test_a_real_zero_passes_while_an_unreadable_or_absent_backlog_does_not
test_the_machine_handoff_gate_is_tabled_and_never_passes
test_a_receipt_destination_inside_the_live_chief_home_is_refused
test_the_receipt_guard_uses_the_same_fallback_home_the_gates_do
test_arguments_are_validated_before_any_work
