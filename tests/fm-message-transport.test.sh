#!/usr/bin/env bash
# Behavior tests for the ordered messaging-transport policy
# (bin/fm-message-transport-lib.sh, bin/fm-message-transport.sh) and the
# fail-closed required-backend rule (config/backlog-backend-required) that keeps
# a chief-of-staff home on its Beads tasks-axi adapter.
#
# What these guard: the approved chain native -> agent-mail -> fm-send is the
# only shape the loader accepts, and every deviation fails closed naming the
# field, so a dispatch can never start against a reordered, widened, or
# unbounded policy. The next-step table is total and deterministic over the
# known outcomes: held never releases a fallback, accepted-offline and an
# unclaimed native doorbell release Agent Mail only through their deadlines,
# and ambiguity stops rather than resends. A bare slash command is refused
# before any send. And a home that requires the beads adapter refuses every
# tasks-axi lifecycle operation, rather than writing data/backlog.md, when the
# resolved adapter is anything else or tasks-axi is missing.
set -u

# shellcheck source=tests/lib.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CLI="$ROOT/bin/fm-message-transport.sh"
WRAPPER="$ROOT/bin/fm-tasks-axi.sh"
TMP_ROOT=$(fm_test_tmproot fm-message-transport)
BASE_PATH=${FM_TEST_BASE_PATH:-/usr/bin:/bin:/usr/sbin:/sbin}

unset FM_HOME FM_CONFIG_OVERRIDE FM_DATA_OVERRIDE FM_ROOT_OVERRIDE TASKS_AXI_FILE TASKS_AXI_BACKEND

command -v jq >/dev/null 2>&1 || { printf 'skip: jq not found\n'; exit 0; }

# run <expected-exit> <label> <cmd...>: capture combined output into OUT, exit into RC.
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
# lib.sh does not enable errexit; keep every assertion explicit.
set +e

write_config() {  # <home> <json>
  mkdir -p "$1/config"
  printf '%s\n' "$2" > "$1/config/message-transports.json"
}

VALID='{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":600,"native_activation_timeout_seconds":600}'

# --- loader: the approved shape --------------------------------------------------------------

test_dry_run_prints_the_approved_order() {
  local home="$TMP_ROOT/valid"
  write_config "$home" "$VALID"
  run 0 "dry-run on a valid config" env FM_HOME="$home" "$CLI" --dry-run
  assert_equals "native -> agent-mail -> fm-send" "$OUT" "dry-run must print the approved chain"
  run 0 "order alias" env FM_HOME="$home" "$CLI" order
  assert_equals "native -> agent-mail -> fm-send" "$OUT" "order must print the approved chain"
  pass "a valid config dry-runs as native -> agent-mail -> fm-send"
}

test_validate_reports_resolved_fields_and_defaults() {
  local home="$TMP_ROOT/defaults"
  write_config "$home" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"]}'
  run 0 "validate with omitted timeouts" env FM_HOME="$home" "$CLI" validate
  assert_contains "$OUT" "primary=native" "resolved primary"
  assert_contains "$OUT" "fallbacks=agent-mail fm-send" "resolved fallbacks"
  assert_contains "$OUT" "offline_pending_timeout_seconds=600" "omitted offline timeout defaults to 600"
  assert_contains "$OUT" "native_activation_timeout_seconds=600" "omitted activation timeout defaults to 600"
  pass "omitted timeouts default to 600 each"
}

test_example_config_is_valid() {
  run 0 "the shipped example validates" "$CLI" --config "$ROOT/docs/examples/message-transports.json" --dry-run
  assert_equals "native -> agent-mail -> fm-send" "$OUT" "example must express the approved chain"
  pass "docs/examples/message-transports.json is a valid policy"
}

test_config_override_wins_over_home() {
  local home="$TMP_ROOT/override-home" other="$TMP_ROOT/override-dir"
  write_config "$home" '{"schema_version":2}'
  mkdir -p "$other"
  printf '%s\n' "$VALID" > "$other/message-transports.json"
  run 0 "FM_CONFIG_OVERRIDE selects the config dir" env FM_HOME="$home" FM_CONFIG_OVERRIDE="$other" "$CLI" --dry-run
  pass "FM_CONFIG_OVERRIDE takes precedence over \$FM_HOME/config"
}

# --- loader: every deviation fails closed and names the field ------------------------------------

expect_invalid() {  # <label> <json> <field-text>
  local home="$TMP_ROOT/invalid-$RANDOM$RANDOM"
  write_config "$home" "$2"
  run 2 "$1" env FM_HOME="$home" "$CLI" --dry-run
  assert_contains "$OUT" "invalid transport config" "$1 must be reported as invalid config"
  assert_contains "$OUT" "$3" "$1 must name the offending field"
}

test_invalid_configs_fail_closed_naming_the_field() {
  expect_invalid "wrong schema version" '{"schema_version":2,"primary":"native","fallbacks":["agent-mail","fm-send"]}' "schema_version"
  expect_invalid "missing schema version" '{"primary":"native","fallbacks":["agent-mail","fm-send"]}' "schema_version"
  expect_invalid "agent-mail as primary" '{"schema_version":1,"primary":"agent-mail","fallbacks":["native","fm-send"]}' "primary"
  expect_invalid "reordered fallbacks" '{"schema_version":1,"primary":"native","fallbacks":["fm-send","agent-mail"]}' "fallbacks"
  expect_invalid "unknown adapter" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","carrier-pigeon"]}' "fallbacks"
  expect_invalid "missing fallbacks" '{"schema_version":1,"primary":"native"}' "fallbacks"
  expect_invalid "unknown key" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"retry_forever":true}' "retry_forever"
  expect_invalid "offline timeout below range" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":30}' "offline_pending_timeout_seconds"
  expect_invalid "activation timeout above range" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"native_activation_timeout_seconds":3601}' "native_activation_timeout_seconds"
  expect_invalid "zero timeout" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":0}' "offline_pending_timeout_seconds"
  expect_invalid "negative timeout" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"native_activation_timeout_seconds":-600}' "native_activation_timeout_seconds"
  expect_invalid "fractional timeout" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":600.5}' "offline_pending_timeout_seconds"
  expect_invalid "string timeout" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":"600"}' "offline_pending_timeout_seconds"
  expect_invalid "non-object top level" '["native"]' "config"
  pass "every deviation from the approved shape fails closed and names the field"
}

test_boundary_timeouts_are_accepted() {
  local home="$TMP_ROOT/bounds"
  write_config "$home" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":60,"native_activation_timeout_seconds":3600}'
  run 0 "60 and 3600 are within range" env FM_HOME="$home" "$CLI" validate
  assert_contains "$OUT" "offline_pending_timeout_seconds=60" "60 accepted"
  assert_contains "$OUT" "native_activation_timeout_seconds=3600" "3600 accepted"
  pass "the 60 and 3600 second bounds are inclusive"
}

test_missing_and_malformed_config_fail_closed() {
  local home="$TMP_ROOT/missing"
  mkdir -p "$home/config"
  run 2 "missing config" env FM_HOME="$home" "$CLI" --dry-run
  assert_contains "$OUT" "missing or unreadable" "missing config names the condition"
  printf '%s\n' '{"schema_version":1,' > "$home/config/message-transports.json"
  run 2 "malformed config" env FM_HOME="$home" "$CLI" --dry-run
  assert_contains "$OUT" "not valid JSON" "malformed config is named as such"
  pass "a missing or malformed config fails closed before dispatch"
}

test_no_home_is_refused_not_guessed() {
  run 2 "no FM_HOME and no override" env -u FM_HOME -u FM_CONFIG_OVERRIDE "$CLI" --dry-run
  assert_contains "$OUT" "FM_HOME is unset" "the refusal names the missing home"
  pass "with no home named the policy is refused rather than guessed"
}

# --- next-step decision table ----------------------------------------------------------------

expect_next() {  # <transport> <outcome> <token>
  run 0 "next $1 $2" "$CLI" next "$1" "$2"
  assert_equals "$3" "$OUT" "next $1 $2"
}

test_next_step_table_is_deterministic_and_total() {
  expect_next native delivered pending:native-activation
  expect_next native held pending:held
  expect_next native offline pending:native-offline
  expect_next native offline-timeout fallback:agent-mail:native-timeout
  expect_next native activation-timeout fallback:agent-mail:native-activation-timeout
  expect_next native unresolved fallback:agent-mail
  expect_next native refused fallback:agent-mail
  expect_next native denied fallback:agent-mail
  expect_next native expired fallback:agent-mail
  expect_next native claimed done:native
  expect_next native ambiguous stop:reconcile
  expect_next agent-mail unconfigured fallback:fm-send
  expect_next agent-mail cancelled fallback:fm-send
  expect_next agent-mail expired fallback:fm-send
  expect_next agent-mail pending pending:agent-mail
  expect_next agent-mail receipt done:agent-mail
  expect_next agent-mail ambiguous stop:reconcile
  expect_next fm-send sent done:fm-send
  expect_next fm-send inconclusive stop:verify-pane
  expect_next fm-send failed stop:exhausted
  expect_next fm-send ambiguous stop:reconcile
  pass "the next-step table maps every known outcome deterministically"
}

test_held_never_releases_a_fallback() {
  run 0 "held" "$CLI" next native held
  assert_not_contains "$OUT" "fallback" "a held native copy must stay pending"
  pass "held stays pending until its documented terminal outcome"
}

test_unknown_transport_or_outcome_is_refused() {
  run 2 "unknown outcome" "$CLI" next native teleported
  assert_contains "$OUT" "not a known native outcome" "unknown outcome is named"
  run 2 "unknown transport" "$CLI" next smoke-signal delivered
  assert_contains "$OUT" "not one of native, agent-mail, fm-send" "unknown transport is named"
  pass "an unknown transport or outcome is refused, never guessed"
}

# --- durable deadlines ------------------------------------------------------------------------

test_deadline_is_acceptance_plus_configured_timeout() {
  local home="$TMP_ROOT/deadline"
  write_config "$home" '{"schema_version":1,"primary":"native","fallbacks":["agent-mail","fm-send"],"offline_pending_timeout_seconds":900}'
  run 0 "offline deadline" env FM_HOME="$home" "$CLI" deadline 1000 offline
  assert_equals 1900 "$OUT" "offline deadline = accepted + 900"
  run 0 "activation deadline (default)" env FM_HOME="$home" "$CLI" deadline 1000 activation
  assert_equals 1600 "$OUT" "activation deadline = accepted + default 600"
  run 2 "non-integer acceptance" env FM_HOME="$home" "$CLI" deadline yesterday offline
  assert_contains "$OUT" "epoch-seconds integer" "bad acceptance time is named"
  run 2 "unknown kind" env FM_HOME="$home" "$CLI" deadline 1000 someday
  pass "deadlines are acceptance time plus the configured timeout, computed once"
}

# --- dispatch phrasing gate -----------------------------------------------------------------

GOOD_DISPATCH='Chief-of-staff dispatch cos-dispatch-1 for aih-3 (ai-harness).

Please invoke your /next skill now, via the Skill tool, to pick the highest-WSJF ready issue.

When you have invoked the skill, reply with exactly this line, filled in:
invoked /next, run id cos-dispatch-1, outcome <ok|blocked|declined>'

test_templated_dispatch_passes() {
  run 0 "templated dispatch" "$CLI" check-dispatch "$GOOD_DISPATCH"
  assert_equals ok "$OUT" "templated dispatch prints ok"
  run 0 "templated dispatch via stdin" bash -c 'printf "%s" "$1" | "$2" check-dispatch -' _ "$GOOD_DISPATCH" "$CLI"
  assert_equals ok "$OUT" "stdin form prints ok"
  pass "a templated dispatch (skill named, ack line quoted) passes the gate"
}

test_bare_slash_command_is_refused() {
  run 1 "bare /summary" "$CLI" check-dispatch "/summary"
  assert_contains "$OUT" "bare slash command refused" "the refusal names the bare command"
  assert_contains "$OUT" "the bare form did not fire" "the refusal cites the negative result"
  run 1 "leading whitespace then slash" "$CLI" check-dispatch "   /summary please"
  assert_contains "$OUT" "bare slash command refused" "leading whitespace does not launder a bare command"
  pass "a bare slash command is refused before any send"
}

test_dispatch_without_skill_or_ack_is_refused() {
  run 1 "no skill named" "$CLI" check-dispatch "Could you look at the backlog at some point? Reply: invoked / done"
  assert_contains "$OUT" "no skill named" "missing skill is named"
  run 1 "no ack line" "$CLI" check-dispatch "Please invoke your /next skill now to pick the top issue."
  assert_contains "$OUT" "missing the required ack line" "missing ack line is named"
  run 1 "empty" "$CLI" check-dispatch "   "
  assert_contains "$OUT" "empty message" "empty is named"
  pass "a dispatch without a named skill or ack line is refused"
}

# --- required backend: fail closed instead of markdown -----------------------------------------

make_home() {  # <name> -> prints the home; single-home layout with a markdown backlog
  local home="$TMP_ROOT/$1"
  mkdir -p "$home/data" "$home/config" "$home/state"
  cp "$ROOT/.tasks.toml" "$home/.tasks.toml"
  printf '## In flight\n\n## Queued\n\n## Done\n' > "$home/data/backlog.md"
  printf '%s\n' "$home"
}

# A fake tasks-axi that passes the compatibility probes and records any real
# invocation into $FAKE_MARKER, so a test can prove the wrapper did or did not
# reach its exec.
FAKEBIN="$TMP_ROOT/fakebin"
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/tasks-axi" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  --version) printf 'tasks-axi 0.2.6\n' ;;
  update) printf -- '--archive-body\n' ;;
  mv) printf '[<id>...]\n' ;;
  *) printf '%s\n' "$*" > "${FAKE_MARKER:?}" ;;
esac
EOF
chmod +x "$FAKEBIN/tasks-axi"

test_required_beads_refuses_a_markdown_home() {
  local home marker
  home=$(make_home required-markdown)
  printf 'beads\n' > "$home/config/backlog-backend-required"
  marker="$TMP_ROOT/required-markdown.exec"
  run 2 "required beads over markdown" env PATH="$FAKEBIN:$BASE_PATH" FM_HOME="$home" FAKE_MARKER="$marker" "$WRAPPER" list
  assert_contains "$OUT" "backlog-backend-required=beads" "the refusal names the requirement"
  assert_contains "$OUT" "resolves backend 'markdown'" "the refusal names the resolved adapter"
  assert_absent "$marker" "tasks-axi must not be executed when the required adapter is not resolved"
  pass "required=beads over a markdown home refuses before exec, naming both adapters"
}

test_required_beads_passes_through_when_beads_resolves() {
  local home marker
  home=$(make_home required-beads)
  printf 'beads\n' > "$home/config/backlog-backend-required"
  marker="$TMP_ROOT/required-beads.exec"
  run 0 "required beads with beads resolved" env PATH="$FAKEBIN:$BASE_PATH" FM_HOME="$home" TASKS_AXI_BACKEND=beads FAKE_MARKER="$marker" "$WRAPPER" list
  assert_present "$marker" "tasks-axi must run when the required adapter is resolved"
  assert_grep "list" "$marker" "the original command reaches tasks-axi"
  pass "required=beads with the beads adapter resolved runs tasks-axi normally"
}

test_required_beads_refuses_manual_editing() {
  local home marker
  home=$(make_home required-manual)
  printf 'beads\n' > "$home/config/backlog-backend-required"
  printf 'manual\n' > "$home/config/backlog-backend"
  marker="$TMP_ROOT/required-manual.exec"
  run 2 "required beads with manual selected" env PATH="$FAKEBIN:$BASE_PATH" FM_HOME="$home" TASKS_AXI_BACKEND=beads FAKE_MARKER="$marker" "$WRAPPER" list
  assert_contains "$OUT" "manual editing" "the refusal names the manual conflict"
  assert_absent "$marker" "tasks-axi must not be executed on a manual conflict"
  pass "required=beads refuses a home that also selects manual editing"
}

test_required_beads_refuses_when_tasks_axi_is_missing() {
  local home marker
  home=$(make_home required-missing)
  printf 'beads\n' > "$home/config/backlog-backend-required"
  marker="$TMP_ROOT/required-missing.exec"
  run 2 "required beads, tasks-axi absent" env PATH="$(fm_test_base_path_sans "$BASE_PATH" tasks-axi)" FM_HOME="$home" TASKS_AXI_BACKEND=beads FAKE_MARKER="$marker" "$WRAPPER" list
  assert_absent "$marker" "nothing may run without tasks-axi"
  pass "required=beads with tasks-axi missing refuses instead of editing markdown"
}

test_no_requirement_keeps_the_markdown_default() {
  local home marker
  home=$(make_home unrequired)
  marker="$TMP_ROOT/unrequired.exec"
  run 0 "no requirement file" env PATH="$FAKEBIN:$BASE_PATH" FM_HOME="$home" FAKE_MARKER="$marker" "$WRAPPER" list
  assert_present "$marker" "without a requirement the markdown default still runs"
  pass "a home without backlog-backend-required keeps today's markdown behavior"
}

test_required_backend_check_library_contract() {
  # shellcheck source=bin/fm-tasks-axi-lib.sh disable=SC1091
  . "$ROOT/bin/fm-tasks-axi-lib.sh"
  local home
  home=$(make_home lib-contract)
  [ -z "$(fm_tasks_axi_required_backend "$home/config")" ] || fail "no file means no requirement"
  printf '  \n' > "$home/config/backlog-backend-required"
  [ -z "$(fm_tasks_axi_required_backend "$home/config")" ] || fail "a blank file means no requirement"
  printf 'beads\n' > "$home/config/backlog-backend-required"
  assert_equals beads "$(fm_tasks_axi_required_backend "$home/config")" "the requirement is read trimmed"
  fm_tasks_axi_required_backend_check "$home/config" "$home"
  expect_code 2 "$?" "required beads over markdown toml"
  assert_contains "$FM_TASKS_AXI_REQUIRED_ERROR" "no markdown fallback" "library error names the missing fallback"
  pass "fm_tasks_axi_required_backend_check refuses a mismatched adapter with status 2"
}

test_dry_run_prints_the_approved_order
test_validate_reports_resolved_fields_and_defaults
test_example_config_is_valid
test_config_override_wins_over_home
test_invalid_configs_fail_closed_naming_the_field
test_boundary_timeouts_are_accepted
test_missing_and_malformed_config_fail_closed
test_no_home_is_refused_not_guessed
test_next_step_table_is_deterministic_and_total
test_held_never_releases_a_fallback
test_unknown_transport_or_outcome_is_refused
test_deadline_is_acceptance_plus_configured_timeout
test_templated_dispatch_passes
test_bare_slash_command_is_refused
test_dispatch_without_skill_or_ack_is_refused
test_required_beads_refuses_a_markdown_home
test_required_beads_passes_through_when_beads_resolves
test_required_beads_refuses_manual_editing
test_required_beads_refuses_when_tasks_axi_is_missing
test_no_requirement_keeps_the_markdown_default
test_required_backend_check_library_contract
