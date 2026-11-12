#!/usr/bin/env bash
# Private Grok Stop cell lifecycle; shared with fake-process cleanup regressions.
cell_tmux() {
  local lab=$1
  shift
  ( cd "$lab" && env -u TMUX -u TMUX_PANE "$REAL_TMUX" -S dedicated.sock "$@" )
}

cleanup_exact_cell() {  # <lab> <session> <target> [keep-diagnostics]
  local lab=$1 session=$2 target=$3 keep=${4:-0} server expected live socket_pid
  local pane_expected pid_expected pane_live pid_live windows
  [ -f "$lab/server.pid" ] && [ -f "$lab/server.identity" ] || return 1
  server=$(cat "$lab/server.pid")
  expected=$(cat "$lab/server.identity")
  live=$(fm_test_pid_start_time "$server" 2>/dev/null) || live=
  if [ -n "$live" ]; then
    [ -n "$expected" ] && [ "$live" = "$expected" ] || {
      echo "blocked: server identity differs from creation record; preserving $lab" >&2
      return 1
    }
    socket_pid=$(cell_tmux "$lab" display-message -p '#{pid}' 2>/dev/null) || socket_pid=
    [ -z "$socket_pid" ] || [ "$socket_pid" = "$server" ] || {
      echo "blocked: socket names another server; preserving $lab" >&2
      return 1
    }
    # Before target metadata exists, the creation-time server identity still
    # proves ownership. A recorded target mismatch must continue to refuse.
    if [ -f "$lab/target.identity" ]; then
      pane_expected=$(sed -n 's/^target-pane=//p' "$lab/target.identity")
      pid_expected=$(sed -n 's/^target-pid=//p' "$lab/target.identity")
      [ -n "$pane_expected" ] && [ -n "$pid_expected" ] || {
        echo "blocked: missing recorded target identity; preserving $lab" >&2
        return 1
      }
      pane_live=$(cell_tmux "$lab" display-message -p -t "$session:$target" '#{pane_id}') || return 1
      pid_live=$(cell_tmux "$lab" display-message -p -t "$session:$target" '#{pane_pid}') || return 1
      [ "$pane_live" = "$pane_expected" ] && [ "$pid_live" = "$pid_expected" ] || {
        echo "blocked: live target identity differs from creation record; preserving $lab" >&2
        return 1
      }
      FM_E2E_TMUX_SOCKET_ID="$lab/dedicated.sock" PATH="$lab/bin:$PATH" \
        env -u TMUX -u TMUX_PANE "$lab/bin/tmux" kill-window -t "$session:$target" || return 1
      windows=$(cell_tmux "$lab" list-windows -t "$session" -F '#{window_name}') || return 1
      printf '%s\n' "$windows" | grep -Fqx control || {
        echo "blocked: control window did not survive exact target cleanup; preserving $lab" >&2
        return 1
      }
      printf '%s\n' "$windows" | grep -Fqx "$target" && {
        echo "blocked: exact target survived cleanup; preserving $lab" >&2
        return 1
      }
    fi
    # Recheck birth identity immediately before signalling our foreground server.
    [ "$(fm_test_pid_start_time "$server" 2>/dev/null)" = "$expected" ] || return 1
    kill -TERM "$server" 2>/dev/null || true
    wait "$server" 2>/dev/null || true
  fi
  [ ! -S "$lab/dedicated.sock" ] || rm -- "$lab/dedicated.sock"
  if [ "$keep" -eq 0 ]; then
    [ -d "$lab" ] && [ ! -L "$lab" ] || return 1
    rm -r -- "$lab" || return 1
  fi
  ACTIVE_LAB=
}

preserve_on_failure() {
  local rc=$? cleanup_rc=0
  trap - EXIT
  if [ -n "${ACTIVE_LAB:-}" ]; then
    if [ "$rc" -ne 0 ]; then
      echo "blocked: keeping failed Grok cell diagnostics at $ACTIVE_LAB" >&2
    fi
    cleanup_exact_cell "$ACTIVE_LAB" "${ACTIVE_SESSION:-fake}" "${ACTIVE_TARGET:-target}" \
      "$((rc != 0))" || cleanup_rc=$?
  fi
  fm_test_cleanup
  [ "$rc" -ne 0 ] || rc=$cleanup_rc
  exit "$rc"
}
trap preserve_on_failure EXIT

start_cell_server() {  # <lab> <session>
  local lab=$1 session=$2 server i=0
  ACTIVE_LAB=$lab
  ACTIVE_SESSION=$session
  # Foreground mode gives us the server PID before any window creation can fail.
  env -u TMUX -u TMUX_PANE "$REAL_TMUX" -D -f /dev/null -S "$lab/dedicated.sock" \
    > "$lab/server.log" 2>&1 &
  server=$!
  printf '%s\n' "$server" > "$lab/server.pid"
  fm_test_pid_start_time "$server" > "$lab/server.identity" || return 1
  while [ "$i" -lt 50 ]; do
    cell_tmux "$lab" show-options -s >/dev/null 2>&1 && break
    sleep 0.1
    i=$((i + 1))
  done
  [ "$i" -lt 50 ] || return 1
  cell_tmux "$lab" new-session -d -s "$session" -n control 'exec sleep 1800'
}

run_cell_child() {  # <lab> <command> [args...], called from the target pane
  local lab=$1 child rc
  shift
  # The existing bounded runner supplies an independent deadline and detects
  # pane-shell death, including when the outer test cannot run its EXIT trap.
  # shellcheck source=/dev/null
  . "$ROOT/bin/fm-timeout-lib.sh"
  ( FM_EXEC_TIMED_OWNER_PID=$$ fm_exec_timed "${FM_GROK_STOP_LIVE_TIMEOUT:-600}" 2 "$@" ) &
  child=$!
  fm_test_track_pid "$child" || return 1
  printf 'child_pid=%s\n' "$child" > "$lab/process.identity"
  printf 'child_pgid=%s\n' "$(ps -o pgid= -p "$child" 2>/dev/null | tr -d ' ')" >> "$lab/process.identity"
  wait "$child"; rc=$?
  fm_test_reap_pids
  return "$rc"
}
