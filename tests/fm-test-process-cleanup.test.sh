#!/usr/bin/env bash
# Failure-unwind regressions for live-cell and disowned teardown fixtures.
# Only a private tmux server and owned sleep processes are started.
# shellcheck disable=SC2016 # Inner shell programs expand their own positional arguments.
set -u
# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
TMP_ROOT=$(fm_test_tmproot fm-process-cleanup)
OWNED_PIDS=()
OWNED_IDENTITIES=()
remember_pid() {
  OWNED_PIDS+=("$1")
  OWNED_IDENTITIES+=("$(fm_test_pid_identity "$1")")
}
emergency_cleanup() {
  local i pid identity
  for ((i=0; i<${#OWNED_PIDS[@]}; i++)); do
    pid=${OWNED_PIDS[i]}
    identity=$(fm_test_pid_identity "$pid" 2>/dev/null) || continue
    [ "$identity" = "${OWNED_IDENTITIES[i]}" ] || continue
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  fm_test_cleanup
}
trap emergency_cleanup EXIT

# A zombie has stopped executing; its init-owned reap is outside the fixture.
pid_running() {
  local state
  state=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
  case "$state" in ''|*Z*) return 1 ;; esac
}
assert_stopped() {
  local i
  for ((i=0; i<50; i++)); do
    pid_running "$1" || return 0
    sleep 0.1
  done
  fail "$2"
}

test_failed_grok_cell_is_cleaned() {
  local lab rc=0 server pane pid
  command -v tmux >/dev/null || fail 'tmux required for private-cell regression'
  lab=$(mktemp -d "$TMP_ROOT/cell.XXXXXX")
  mkdir "$lab/bin"
  cat > "$lab/bin/tmux" <<'SH'
#!/usr/bin/env bash
exec "$REAL_TMUX" -S "$FM_E2E_TMUX_SOCKET_ID" "$@"
SH
  chmod +x "$lab/bin/tmux"
  bash -c '
    . "$1/tests/lib.sh"
    REAL_TMUX=$(command -v tmux); export REAL_TMUX
    ACTIVE_LAB=$2
    . "$1/tests/grok-stop-cell-helpers.sh"
    start_cell_server "$2" fake || exit 70
    "$REAL_TMUX" -S "$2/dedicated.sock" new-window -d -t fake: -n target "exec sleep 300" || exit 71
    "$REAL_TMUX" -S "$2/dedicated.sock" display-message -p -t fake:target \
      "target-pane=#{pane_id}
target-pid=#{pane_pid}" > "$2/target.identity"
    "$REAL_TMUX" -S "$2/dedicated.sock" list-panes -a -F "#{pane_pid}" > "$2/panes"
    "$REAL_TMUX" -S "$2/dedicated.sock" display-message -p "#{pid}" > "$2/server"
    printf "diagnostic\n" > "$2/failure.log"
    fail "injected cell failure"
  ' _ "$ROOT" "$lab" > "$lab/stdout" 2> "$lab/stderr" || rc=$?
  server=$(cat "$lab/server")
  remember_pid "$server"
  while read -r pane; do remember_pid "$pane"; done < "$lab/panes"
  expect_code 1 "$rc" 'fake cell must preserve failure status'
  assert_present "$lab/failure.log" 'failed cell lost diagnostics'
  assert_grep 'injected cell failure' "$lab/stderr" 'fake failure never executed'
  assert_stopped "$server" 'failed cell left its private tmux server alive'
  while read -r pid; do assert_stopped "$pid" 'failed cell left a pane alive'; done < "$lab/panes"
  pass 'failed Grok cell keeps diagnostics and removes its server and panes'
}

test_failed_teardown_case_reaps_sleeper() {
  local name case_dir rc pid
  for name in test_leaked_worktree_process_is_reaped test_leaked_tasktmp_process_is_reaped; do
    case_dir=$(mktemp -d "$TMP_ROOT/teardown.XXXXXX")
    rc=0
    CASE_DIR="$case_dir" bash -c '
      . "$1/tests/fm-teardown.test.sh"
      make_case() { mkdir -p "$CASE_DIR/wt"; printf "%s\n" "$CASE_DIR"; }
      write_meta() { :; }
      land_shippable_commit() { :; }
      run_teardown() {
        printf "%s\n" "$pid" > "$CASE_DIR/sleeper.pid"
        return 73
      }
      "$3"
    ' _ "$ROOT" "$case_dir" "$name" > "$case_dir/stdout" 2> "$case_dir/stderr" || rc=$?
    pid=$(cat "$case_dir/sleeper.pid")
    remember_pid "$pid"
    expect_code 1 "$rc" 'unexpected teardown status must fail the original assertion'
    assert_grep 'got 73' "$case_dir/stderr" 'the injected status did not reach expect_code'
    assert_stopped "$pid" "$name leaked its sleeper after expect_code exited"
  done
  pass 'both teardown fixtures reap sleepers when teardown returns an unexpected status'
}

# Exercise the same finalizer without a socket when a restricted sandbox cannot
# start tmux. The stand-in server is an owned sleep, never a live CLI.
test_early_cell_failure_with_fake_server() {
  local lab rc=0 server
  lab=$(mktemp -d "$TMP_ROOT/early-cell.XXXXXX")
  cat > "$lab/tmux" <<'SH'
#!/usr/bin/env bash
case " $* " in
  *' -D '*) exec sleep 300 ;;
  *' show-options '*) [ -s "$CELL_LAB/server.identity" ] ;;
  *' new-session '*) exit 0 ;;
  *' display-message '*) cat "$CELL_LAB/server.pid" ;;
  *) exit 92 ;;
esac
SH
  chmod +x "$lab/tmux"
  CELL_LAB="$lab" bash -c '
    . "$1/tests/lib.sh"
    REAL_TMUX="$2/tmux"
    . "$1/tests/grok-stop-cell-helpers.sh"
    start_cell_server "$2" fake || exit 70
    printf "early diagnostic\n" > "$2/failure.log"
    fail "injected early failure"
  ' _ "$ROOT" "$lab" > "$lab/stdout" 2> "$lab/stderr" || rc=$?
  server=$(cat "$lab/server.pid")
  remember_pid "$server"
  expect_code 1 "$rc" 'early cell must retain failure status'
  assert_grep 'injected early failure' "$lab/stderr" 'early failure was not reached'
  assert_present "$lab/failure.log" 'early cell lost diagnostics'
  assert_stopped "$server" 'early cell stranded its server without pane metadata'
  pass 'early cell failure cleans an owned server before pane metadata exists'
}

test_pid_mismatch_is_never_signalled() {
  local pid
  sleep 300 &
  pid=$!
  remember_pid "$pid"
  fm_test_track_pid "$pid" || fail 'could not register mismatch fixture'
  # Replace the creation record, rather than faking the real identity probe.
  printf '%s\t%s\n' "$pid" wrong-identity > "$FM_TEST_PID_REGISTRY"
  fm_test_reap_pids 2> "$TMP_ROOT/mismatch.err"
  kill -0 "$pid" 2>/dev/null || fail 'cleanup signalled a mismatched identity'
  assert_grep 'refusing to signal' "$TMP_ROOT/mismatch.err" 'mismatch was not reported'
  # Restore the owned identity so the real finalizer can clean this fixture.
  : > "$FM_TEST_PID_REGISTRY"
  fm_test_track_pid "$pid" || fail 'could not restore mismatch fixture'
  fm_test_reap_pids
  assert_stopped "$pid" 'restored fixture was not cleaned'
  pass 'PID finalizer refuses an identity mismatch'
}

test_live_child_deadline_and_parent_death() {
  local mode lab owner pid rc
  for mode in deadline parent-death; do
    lab=$(mktemp -d "$TMP_ROOT/child.XXXXXX")
    cat > "$lab/sleeper.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$$" > "$1/sleeper.pid"
exec sleep 300
SH
    bash -c '
      . "$1/tests/lib.sh"
      . "$1/tests/grok-stop-cell-helpers.sh"
      export FM_GROK_STOP_LIVE_TIMEOUT=$3
      run_cell_child "$2" bash "$2/sleeper.sh" "$2"
      exit $?
    ' _ "$ROOT" "$lab" "$([ "$mode" = deadline ] && echo 1 || echo 30)" \
      > "$lab/stdout" 2> "$lab/stderr" &
    owner=$!
    fm_test_track_pid "$owner" || fail 'could not register child owner'
    remember_pid "$owner"
    for ((rc=0; rc<50; rc++)); do
      [ ! -s "$lab/sleeper.pid" ] || break
      sleep 0.1
    done
    [ -s "$lab/sleeper.pid" ] || fail 'bounded sleeper never started'
    pid=$(cat "$lab/sleeper.pid")
    remember_pid "$pid"
    if [ "$mode" = parent-death ]; then
      [ "$(fm_test_pid_identity "$owner")" = "${OWNED_IDENTITIES[${#OWNED_IDENTITIES[@]}-2]}" ] \
        || fail 'child owner identity changed'
      kill -TERM "$owner"
    fi
    rc=0
    wait "$owner" || rc=$?
    if [ "$mode" = deadline ]; then expect_code 124 "$rc" 'child deadline was not enforced'; fi
    assert_stopped "$pid" "$mode left a live child behind"
  done
  pass 'live-child wrapper enforces its deadline and cleans up after parent death'
}

test_teardown_siblings_unwind_safely() {
  local name case_dir rc pid child
  for name in test_parked_own_run_refuses_when_abort_is_unconfirmed \
      test_lsof_absent_reaps_tmux_process_group test_reused_pid_identity_is_not_force_killed \
      test_exec_changed_process_is_still_reaped test_process_spawned_during_grace_is_reaped_on_later_pass \
      test_run_abort_precedes_process_reap_precedes_worktree_removal; do
    case_dir=$(mktemp -d "$TMP_ROOT/sibling.XXXXXX")
    rc=0
    CASE_DIR="$case_dir" bash -c '
      . "$1/tests/fm-teardown.test.sh"
      make_case() {
        mkdir -p "$CASE_DIR/wt" "$CASE_DIR/fakebin" "$CASE_DIR/empty-path"
        printf "%s\n" "$CASE_DIR"
      }
      write_meta() { :; }
      land_shippable_commit() { :; }
      parked_axi_status_toon() { :; }
      git() { :; }
      make_path_without_lsof() { printf "%s\n" "$CASE_DIR/empty-path"; }
      run_teardown() { printf "%s\n" "$pid" > "$CASE_DIR/sleeper.pid"; return 73; }
      "$3"
    ' _ "$ROOT" "$case_dir" "$name" > "$case_dir/stdout" 2> "$case_dir/stderr" || rc=$?
    pid=$(cat "$case_dir/sleeper.pid")
    remember_pid "$pid"
    expect_code 1 "$rc" 'sibling must fail its original assertion'
    assert_grep 'got 73' "$case_dir/stderr" 'sibling did not exercise the injected result'
    assert_stopped "$pid" "$name left its captured process alive"
    if [ -f "$case_dir/child.pid" ]; then
      child=$(cat "$case_dir/child.pid")
      remember_pid "$child"
      assert_stopped "$child" 'grace handler leaked its late-spawned child'
    fi
  done
  pass 'six sibling teardown fixtures unwind safely after an unexpected status'
}

test_pid_mismatch_survives_root_fallback() {
  local lab pid rc=0
  lab=$(mktemp -d "$TMP_ROOT/mismatch-root.XXXXXX")
  bash -c '
    . "$1/tests/lib.sh"
    d=$(fm_test_tmproot fm-mismatch-root)
    ( exec -a "$d/sleeper" sleep 300 ) &
    pid=$!
    fm_test_track_pid "$pid" || exit 70
    printf "%s\n" "$pid" > "$2/pid"
    printf "%s\twrong-identity\n" "$pid" > "$FM_TEST_PID_REGISTRY"
    fm_test_cleanup
    kill -0 "$pid" 2>/dev/null || fail "root sweep overrode the identity refusal"
  ' _ "$ROOT" "$lab" > "$lab/stdout" 2> "$lab/stderr" || rc=$?
  pid=$(cat "$lab/pid")
  remember_pid "$pid"
  expect_code 0 "$rc" 'root fallback must respect a registered identity mismatch'
  fm_test_track_pid "$pid" || fail 'could not register surviving owned process'
  fm_test_reap_pids
  pass 'root discovery cannot override a registered PID identity refusal'
}

case ${1:-all} in
  cell) test_failed_grok_cell_is_cleaned ;;
  teardown) test_failed_teardown_case_reaps_sleeper ;;
  fake-cell) test_early_cell_failure_with_fake_server ;;
  identity) test_pid_mismatch_is_never_signalled ;;
  child) test_live_child_deadline_and_parent_death ;;
  siblings) test_teardown_siblings_unwind_safely ;;
  mismatch-root) test_pid_mismatch_survives_root_fallback ;;
  all) test_failed_grok_cell_is_cleaned; test_failed_teardown_case_reaps_sleeper; test_early_cell_failure_with_fake_server; test_pid_mismatch_is_never_signalled; test_live_child_deadline_and_parent_death; test_teardown_siblings_unwind_safely; test_pid_mismatch_survives_root_fallback ;;
  *) fail 'unknown cleanup regression' ;;
esac
