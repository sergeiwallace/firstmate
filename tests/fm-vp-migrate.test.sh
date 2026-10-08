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

ALL_GATES="vp-record repo-scope charter harness-selection beads-ownership home-seed route-register reconcile native-dispatch-proof cutover"

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
  # The gates after the failure are not reported at all, rather than as passes.
  assert_no_grep "gate: native-dispatch-proof:" "$receipt" "gates after a failure are not reached"
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
test_arguments_are_validated_before_any_work
