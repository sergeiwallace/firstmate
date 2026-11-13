#!/usr/bin/env bash
# Failure-unwind coverage for sleeper and private-server fixtures.
# Each case executes the original fixture, injecting failure at a later boundary.
# No live agent, credentials, network, or production teardown is used.
# shellcheck disable=SC2016 # The child shell expands its own variables.
set -u
# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
TMP_ROOT=$(fm_test_tmproot fm-fixture-unwind)

pid_running() {
  local state
  state=$(ps -o stat= -p "$1" 2>/dev/null) || return 1
  case "$state" in ''|*Z*) return 1 ;; esac
}

test_failure_unwind() {
  local name=$1 lab rc=0 pid identity i
  lab=$(mktemp -d "$TMP_ROOT/case.XXXXXX")
  bash -c '
    export FM_PROCESS_CLEANUP_TEST_SOURCE_ONLY=1
    observer=$2
    # Record birth stamps while the children are alive, outside the fixture
    # tree removed by the child EXIT trap. The parent also owns RED cleanup.
    observe() {
      local child
      for child in "$@"; do
        kill -0 "$child" || exit 70
        printf "%s\t%s\n" "$child" "$(fm_test_pid_start_time "$child")" >> "$observer/pids"
      done
    }
    case $3 in
      turnend)
        . "$1/tests/fm-turnend-guard.test.sh"
        record_autoarm_owner() { observe "$pid"; fail "injected fixture failure"; }
        test_hook_claude_mode_blocks_on_stuck_arming_claim
        ;;
      watch-arm)
        . "$1/tests/fm-watch-arm.test.sh"
        start_seed_watcher() { :; }
        WATCH_ARM="$observer/arm"
        printf "#!/usr/bin/env bash\nexit 73\n" > "$WATCH_ARM"
        chmod +x "$WATCH_ARM"
        expect_code() { observe "$other"; fail "injected fixture failure"; }
        test_take_over_attaches_to_a_cycle_the_named_arm_does_not_own
        ;;
      watcher-lock)
        . "$1/tests/fm-watcher-lock.test.sh"
        LIB="$observer/identity.sh"
        printf "fm_pid_identity() { return 73; }\n" > "$LIB"
        fail() { observe "$holder"; printf "injected fixture failure\n" >&2; exit 1; }
        test_live_stalled_watch_lock_is_replaced_past_hard_bound
        ;;
      startup-network)
        . "$1/tests/fm-startup-network.test.sh"
        run_stage() { observe "$claimant"; fail "injected fixture failure"; }
        test_harvest_acknowledgement_suppresses_the_wake_and_no_claim_produces_it
        ;;
      lint)
        . "$1/tests/fm-lint.test.sh"
        fm_lint_bounds_supported() { return 0; }
        LINT=/bin/true
        fail() { observe "$sentinel_pid"; printf "injected fixture failure\n" >&2; exit 1; }
        test_root_deadline_names_the_root_and_reaps_the_tree
        ;;
      omp)
        . "$1/tests/fm-omp-harness.test.sh"
        record_omp_session() { observe "$pid"; fail "injected fixture failure"; }
        test_ownership_proof_is_omp_keyed
        ;;
      herdr)
        . "$1/tests/fm-herdr-lab.test.sh"
        start_viewer_fixture() { FIXTURE_LAUNCHER_PID=2147483647; FIXTURE_VIEWER_PID=2147483647; }
        write_viewer_record() { : > "$1"; }
        stops=0
        run_with_fake() {
          case $1 in
            fm_herdr_lab_viewer_record_path) printf "%s/record\n" "$TMP_ROOT" ;;
            fm_herdr_lab_viewer_stop)
              if [ -n "${holder_pid:-}" ]; then observe "$holder_pid"; fail "injected fixture failure"; fi
              stops=$((stops + 1))
              [ "$stops" -eq 1 ]
              ;;
            *) return 0 ;;
          esac
        }
        test_viewer_stop_only_signals_owned_processes
        ;;
      procevent)
        . "$1/tests/fm-procevent.test.sh"
        pe_register() { mkdir -p "$FM_PROCEVENT_CLAIM_ROOT"; }
        pe() { observe "$innocent_pid"; fail "injected fixture failure"; }
        test_reused_claim_preserves_innocent_process
        ;;
      endpoint)
        . "$1/tests/fm-teardown-endpoint-safety.test.sh"
        ps() {
          if [ "${1:-}" = -p ]; then
            observe "$control_pid" "$target_pid"; printf "wrong-command\n"
          else command ps "$@"; fi
        }
        fail() { printf "injected fixture failure\n" >&2; exit 1; }
        test_recorded_process_identity_cleanup_is_exact
        ;;
      tmux-invalid|tmux-close|tmux-forced|tmux-unreadable|tmux-child|tmux-gone|tmux-birth-mismatch|tmux-socket-mismatch)
        . "$1/tests/fm-teardown-endpoint-safety.test.sh"
        # A socket-free server stand-in exercises the same fixture and
        # finalizer in sandboxes which prohibit private Unix sockets.
        export UNWIND_OBSERVER=$observer
        export -f fm_test_pid_start_time
        REAL_TMUX="$observer/tmux"
        cat > "$REAL_TMUX" <<\SH
#!/usr/bin/env bash
shift 2 # -S <private socket>
case $1 in
  new-session)
    sleep 300 </dev/null >/dev/null 2>&1 &
    child=$!
    birth=$(fm_test_pid_start_time "$child") || exit 70
    printf "%s\t%s\n" "$child" "$birth" >> "$UNWIND_OBSERVER/pids"
    printf "%s\n%s\n" "$child" "$birth" > "$UNWIND_OBSERVER/server"
    case " $* " in *" -P "*) printf "%s\n" "$child" ;; esac
    ;;
  new-window) : ;;
  display-message)
    child=$(head -n 1 "$UNWIND_OBSERVER/server")
    if [ "${UNWIND_WRONG_SOCKET:-0}" = 1 ]; then child=$((child + 1)); fi
    printf "%s\n" "$child"
    ;;
  kill-server)
    child=$(head -n 1 "$UNWIND_OBSERVER/server")
    birth=$(tail -n 1 "$UNWIND_OBSERVER/server")
    [ "$(fm_test_pid_start_time "$child")" = "$birth" ] || exit 71
    kill -TERM "$child"
    ;;
  *) exit 72 ;;
esac
SH
        chmod +x "$REAL_TMUX"
        isolated_tmux_window_exists() {
          local server
          server=$(cd "$1" && "$REAL_TMUX" -S "$2" display-message -p "#{pid}") || exit 70
          observe "$server"
          case $unwind_case in
            tmux-birth-mismatch) PRIVATE_TMUX_IDENTITIES[0]=wrong-birth ;;
            tmux-socket-mismatch) export UNWIND_WRONG_SOCKET=1 ;;
          esac
          fail "injected fixture failure"
        }
        unwind_case=$3
        case $3 in
          tmux-invalid)
            # Stop before the production teardown can run.
            TEARDOWN=/bin/false
            test_isolated_tmux_invalid_and_valid_cleanup
            ;;
          tmux-forced|tmux-unreadable|tmux-child)
            write_close_failing_tmux_shim() { isolated_tmux_window_exists "$1" "$2"; }
            case $3 in
              tmux-forced) test_forced_teardown_continues_past_a_close_it_could_not_make ;;
              tmux-unreadable) test_unreadable_close_read_refuses_while_a_definitive_absence_completes ;;
              tmux-child) test_forced_secondmate_child_close_failure_still_refuses ;;
            esac
            ;;
          tmux-gone) test_already_gone_endpoint_still_completes_without_a_refusal ;;
          *) test_failed_endpoint_close_refuses_before_removing_the_record ;;
        esac
        ;;
      *) exit 72 ;;
    esac
  ' _ "$ROOT" "$lab" "$name" > "$lab/stdout" 2> "$lab/stderr" || rc=$?
  [ -s "$lab/pids" ] || fail "$name did not reach its live fixture (exit $rc): $(cat "$lab/stderr")"
  # Register the original birth records before assertions, so a RED run also
  # reaps only its own sleepers (including the socket-free server stand-ins).
  cat "$lab/pids" >> "$FM_TEST_PID_REGISTRY"
  expect_code 1 "$rc" "$name must fail while the fixture is alive"
  assert_grep 'injected fixture failure' "$lab/stderr" "$name failed before injection"
  case $name in
    tmux-birth-mismatch|tmux-socket-mismatch)
      while IFS=$'\t' read -r pid identity; do
        pid_running "$pid" || fail "$name signalled an unproved server"
      done < "$lab/pids"
      pass "$name refuses to signal an unproved server"
      return
      ;;
  esac
  while IFS=$'\t' read -r pid identity; do
    for ((i=0; i<50; i++)); do
      pid_running "$pid" || break
      sleep 0.1
    done
    if pid_running "$pid"; then
      fail "$name leaked its live fixture after failure"
    fi
  done < "$lab/pids"
  pass "$name unwinds its live fixture after failure"
}

test_startup_artifact_unwind() {
  local lab rc=0 leftovers
  lab=$(mktemp -d "$TMP_ROOT/artifacts.XXXXXX")
  mkdir "$lab/tmp"
  TMPDIR="$lab/tmp" bash -c '
    FM_PROCESS_CLEANUP_TEST_SOURCE_ONLY=1
    . "$1/tests/fm-startup-network.test.sh"
    pass() { fail "injected fixture failure"; }
    test_locked_start_is_not_satisfied_by_an_inflight_probe
  ' _ "$ROOT" > "$lab/stdout" 2> "$lab/stderr" || rc=$?
  expect_code 1 "$rc" "startup artifact fixture must unwind on failure"
  assert_grep 'injected fixture failure' "$lab/stderr" "startup artifact fixture failed before injection"
  leftovers=$(find "$lab/tmp" -mindepth 1 -maxdepth 1 -print)
  [ -z "$leftovers" ] || fail "startup worker leaked temporary artifacts after failure: $leftovers"
  pass "startup worker temporary artifacts unwind after failure"
}

case ${1:-all} in
  all)
    for name in turnend watch-arm watcher-lock startup-network lint omp herdr procevent endpoint tmux-invalid tmux-close tmux-forced tmux-unreadable tmux-child tmux-gone tmux-birth-mismatch tmux-socket-mismatch; do
      test_failure_unwind "$name"
    done
    test_startup_artifact_unwind
    ;;
  sleepers)
    for name in turnend watch-arm watcher-lock startup-network lint omp herdr procevent endpoint; do
      test_failure_unwind "$name"
    done
    ;;
  tmux)
    for name in tmux-invalid tmux-close tmux-forced tmux-unreadable tmux-child tmux-gone tmux-birth-mismatch tmux-socket-mismatch; do
      test_failure_unwind "$name"
    done
    ;;
  startup-artifacts) test_startup_artifact_unwind ;;
  *) test_failure_unwind "$1" ;;
esac
