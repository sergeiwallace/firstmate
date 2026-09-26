# shellcheck shell=bash
# fm-message-transport-lib.sh - the ordered messaging-transport policy behind the
# chief-of-staff dispatch path.
# Usage: . bin/fm-message-transport-lib.sh
#
# This file is the single owner of three things the chief-of-staff session and
# its tests need to agree on:
#   1. Loading and validating config/message-transports.json (schema 1). The
#      approved order is fixed - native ListAgents/SendMessage first, Agent
#      Mail second, the existing fm-send.sh route last - so the loader accepts
#      exactly that shape and FAILS CLOSED, naming the invalid field, on any
#      other: a missing file, malformed JSON, an unknown adapter, a reordered
#      chain, an unknown key, or a timeout outside 60-3600 seconds. A missing
#      timeout defaults to 600; zero, negative, fractional, or out-of-range
#      values are refused, never clamped.
#   2. The next-step decision table for one dispatch attempt (fm_mt_next). It
#      is deterministic and total over the known outcomes so that the same
#      observation always yields the same transition, whichever path observed
#      it. `held` stays pending until its documented terminal outcome and never
#      releases a fallback; accepted-offline and a delivered-but-unclaimed
#      native doorbell release Agent Mail only through their persisted
#      deadlines; every other ambiguity stops for reconciliation rather than
#      resending. Agent Mail that is unconfigured, cancelled, or expired
#      releases exactly one fm-send attempt, whose own exit contract is
#      preserved unchanged.
#   3. The dispatch-phrasing gate (fm_mt_check_dispatch). A bare slash command
#      is refused before any send: in the 2026-09-16 live test the bare form did
#      not fire the recipient's skill, and Claude Code documents that a command
#      inside a received message arrives as plain text and never executes. A
#      dispatch must name the skill as /<skill> and quote the ack line.
#
# Nothing here sends anything. The native adapter is agent-owned (ListAgents and
# SendMessage are the recipient harness's tools, not shell commands); this
# library tells that adapter, and the fm-send fallback, what the policy allows
# next. bin/fm-message-transport.sh is the command-line face of this file.
#
# Every function reports failure through FM_MT_ERROR and a status of 2 (policy
# refusal / invalid config) or 1 (dispatch text refused); it never exits the
# caller's shell.

FM_MT_SCHEMA_VERSION=1
FM_MT_APPROVED_PRIMARY=native
FM_MT_APPROVED_FALLBACKS="agent-mail fm-send"
FM_MT_TIMEOUT_MIN=60
FM_MT_TIMEOUT_MAX=3600
FM_MT_TIMEOUT_DEFAULT=600

FM_MT_ERROR=
FM_MT_PRIMARY=
FM_MT_FALLBACKS=
FM_MT_OFFLINE_TIMEOUT=
FM_MT_ACTIVATION_TIMEOUT=

# fm_mt_config_path
# Resolve the config path for this home into FM_MT_CONFIG_PATH (and print it).
# Mirrors fm-send.sh: an operational home must be named explicitly
# (FM_CONFIG_OVERRIDE or FM_HOME), because a transport policy must not silently
# resolve against the wrong home. Callers read the variable rather than a
# command substitution so the refusal in FM_MT_ERROR survives (a subshell would
# discard it).
FM_MT_CONFIG_PATH=
fm_mt_config_path() {
  local dir
  FM_MT_ERROR=
  FM_MT_CONFIG_PATH=
  if [ -n "${FM_CONFIG_OVERRIDE:-}" ]; then
    dir=$FM_CONFIG_OVERRIDE
  elif [ -n "${FM_HOME:-}" ]; then
    dir=$FM_HOME/config
  else
    FM_MT_ERROR="FM_HOME is unset and FM_CONFIG_OVERRIDE is unset: name the operational home before loading the transport policy"
    return 2
  fi
  FM_MT_CONFIG_PATH="$dir/message-transports.json"
  printf '%s\n' "$FM_MT_CONFIG_PATH"
}

# fm_mt_load <path>
# Validate the transport config and export the resolved policy into
# FM_MT_PRIMARY, FM_MT_FALLBACKS (space-separated), FM_MT_OFFLINE_TIMEOUT and
# FM_MT_ACTIVATION_TIMEOUT. Returns 2 with FM_MT_ERROR="<field>: <reason>" on any
# deviation from the approved shape.
fm_mt_load() {
  local path=$1 verdict field reason
  FM_MT_ERROR=
  FM_MT_PRIMARY=
  FM_MT_FALLBACKS=
  FM_MT_OFFLINE_TIMEOUT=
  FM_MT_ACTIVATION_TIMEOUT=
  if ! command -v jq >/dev/null 2>&1; then
    FM_MT_ERROR="jq: required to load $path and not on PATH"
    return 2
  fi
  if [ ! -f "$path" ] || [ ! -r "$path" ]; then
    FM_MT_ERROR="config: $path is missing or unreadable (the chief home seed writes the approved default)"
    return 2
  fi
  # One jq pass produces either "ok <primary> <fallbacks,joined> <offline> <activation>"
  # or "error <field> <reason...>". Doing the whole check in jq keeps one
  # definition of validity; the shell only relays it.
  verdict=$(jq -r \
    --argjson want_schema "$FM_MT_SCHEMA_VERSION" \
    --arg want_primary "$FM_MT_APPROVED_PRIMARY" \
    --arg want_fallbacks "$FM_MT_APPROVED_FALLBACKS" \
    --argjson tmin "$FM_MT_TIMEOUT_MIN" \
    --argjson tmax "$FM_MT_TIMEOUT_MAX" \
    --argjson tdefault "$FM_MT_TIMEOUT_DEFAULT" '
    def err(f; r): "error \(f) \(r)";
    def timeout(f):
      if has(f) then
        (.[f]) as $v
        | if ($v|type) != "number" then err(f; "must be an integer number of seconds")
          elif ($v|floor) != $v then err(f; "must be a whole number of seconds")
          elif $v < $tmin or $v > $tmax then err(f; "must be within \($tmin)-\($tmax) seconds (got \($v))")
          else ($v|tostring) end
      else ($tdefault|tostring) end;
    if type != "object" then err("config"; "top level must be a JSON object")
    else
      ((keys - ["schema_version","primary","fallbacks","offline_pending_timeout_seconds","native_activation_timeout_seconds"])) as $unknown
      | if ($unknown|length) > 0 then err($unknown[0]; "unknown field")
        elif (has("schema_version")|not) then err("schema_version"; "required")
        elif .schema_version != $want_schema then err("schema_version"; "must be \($want_schema)")
        elif (has("primary")|not) then err("primary"; "required")
        elif .primary != $want_primary then err("primary"; "must be \"\($want_primary)\" (approved order is fixed)")
        elif (has("fallbacks")|not) then err("fallbacks"; "required")
        elif (.fallbacks|type) != "array" then err("fallbacks"; "must be an array")
        elif ((.fallbacks|map(type)|unique) != ["string"] and (.fallbacks|length) > 0) then err("fallbacks"; "must contain adapter names")
        elif (.fallbacks|join(" ")) != $want_fallbacks then err("fallbacks"; "must be [\($want_fallbacks|split(" ")|map("\"\(.)\"")|join(", "))] in that order")
        else
          (timeout("offline_pending_timeout_seconds")) as $off
          | if ($off|startswith("error ")) then $off
            else (timeout("native_activation_timeout_seconds")) as $act
            | if ($act|startswith("error ")) then $act
              else "ok \(.primary) \(.fallbacks|join(",")) \($off) \($act)" end
            end
        end
    end' "$path" 2>/dev/null) || {
    FM_MT_ERROR="config: $path is not valid JSON"
    return 2
  }
  case "$verdict" in
    ok\ *)
      # shellcheck disable=SC2086
      set -- $verdict
      FM_MT_PRIMARY=$2
      FM_MT_FALLBACKS=${3//,/ }
      FM_MT_OFFLINE_TIMEOUT=$4
      FM_MT_ACTIVATION_TIMEOUT=$5
      return 0
      ;;
    error\ *)
      field=${verdict#error }
      reason=${field#* }
      field=${field%% *}
      FM_MT_ERROR="$field: $reason"
      return 2
      ;;
    *)
      FM_MT_ERROR="config: $path could not be validated"
      return 2
      ;;
  esac
}

# fm_mt_order
# Print the approved chain in display form. Requires a successful fm_mt_load.
fm_mt_order() {
  if [ -z "$FM_MT_PRIMARY" ]; then
    FM_MT_ERROR="policy: load the transport config before printing the order"
    return 2
  fi
  printf '%s' "$FM_MT_PRIMARY"
  local t
  for t in $FM_MT_FALLBACKS; do
    printf ' -> %s' "$t"
  done
  printf '\n'
}

# fm_mt_next <transport> <outcome>
# Print the next action for one dispatch given the outcome the named transport
# just reported. Tokens:
#   pending:<what>            keep waiting; no fallback (held, native-offline,
#                             native-activation, agent-mail)
#   fallback:<next>[:<record>] attempt <next> with the SAME dispatch id, after
#                             recording <record> when present
#   done:<transport>          the dispatch reached its recipient's gate
#   stop:<why>                do not try a later transport or resend blindly;
#                             surface the dispatch id (reconcile, verify-pane,
#                             exhausted)
# Unknown transport or outcome: status 2 with FM_MT_ERROR.
fm_mt_next() {
  local transport=$1 outcome=$2
  FM_MT_ERROR=
  case "$transport/$outcome" in
    native/delivered) printf '%s\n' pending:native-activation ;;
    native/held) printf '%s\n' pending:held ;;
    native/offline) printf '%s\n' pending:native-offline ;;
    native/offline-timeout) printf '%s\n' fallback:agent-mail:native-timeout ;;
    native/activation-timeout) printf '%s\n' fallback:agent-mail:native-activation-timeout ;;
    native/unresolved|native/refused|native/denied|native/expired) printf '%s\n' fallback:agent-mail ;;
    native/claimed) printf '%s\n' done:native ;;
    native/ambiguous) printf '%s\n' stop:reconcile ;;
    agent-mail/unconfigured|agent-mail/cancelled|agent-mail/expired) printf '%s\n' fallback:fm-send ;;
    agent-mail/pending) printf '%s\n' pending:agent-mail ;;
    agent-mail/receipt|agent-mail/claimed) printf '%s\n' done:agent-mail ;;
    agent-mail/ambiguous) printf '%s\n' stop:reconcile ;;
    fm-send/sent|fm-send/claimed) printf '%s\n' done:fm-send ;;
    fm-send/inconclusive) printf '%s\n' stop:verify-pane ;;
    fm-send/failed) printf '%s\n' stop:exhausted ;;
    fm-send/ambiguous) printf '%s\n' stop:reconcile ;;
    native/*|agent-mail/*|fm-send/*)
      FM_MT_ERROR="outcome: '$outcome' is not a known $transport outcome"
      return 2
      ;;
    *)
      FM_MT_ERROR="transport: '$transport' is not one of native, agent-mail, fm-send"
      return 2
      ;;
  esac
}

# fm_mt_deadline <accepted-epoch-seconds> <timeout-seconds>
# Print the durable deadline for an accepted-offline or delivered native copy.
# Computed once from the acceptance timestamp; a restart re-reads the stored
# value rather than calling this again, so the pending period is never extended.
fm_mt_deadline() {
  local accepted=$1 timeout=$2
  FM_MT_ERROR=
  case "$accepted" in
    ''|*[!0-9]*) FM_MT_ERROR="accepted: '$accepted' is not an epoch-seconds integer"; return 2 ;;
  esac
  case "$timeout" in
    ''|*[!0-9]*) FM_MT_ERROR="timeout: '$timeout' is not an integer number of seconds"; return 2 ;;
  esac
  if [ "$timeout" -lt "$FM_MT_TIMEOUT_MIN" ] || [ "$timeout" -gt "$FM_MT_TIMEOUT_MAX" ]; then
    FM_MT_ERROR="timeout: $timeout is outside $FM_MT_TIMEOUT_MIN-$FM_MT_TIMEOUT_MAX seconds"
    return 2
  fi
  printf '%s\n' $((accepted + timeout))
}

# fm_mt_check_dispatch <text>
# Refuse a dispatch that the phrasing discipline says will not fire: a bare
# slash command, no named skill, or no ack line. Returns 1 with FM_MT_ERROR.
fm_mt_check_dispatch() {
  local text=$1 trimmed
  FM_MT_ERROR=
  trimmed=${text#"${text%%[![:space:]]*}"}
  if [ -z "$trimmed" ]; then
    FM_MT_ERROR="dispatch: empty message"
    return 1
  fi
  case "$trimmed" in
    /*)
      FM_MT_ERROR="dispatch: bare slash command refused - a command in a received message arrives as plain text and never executes (in the 2026-09-16 live test the bare form did not fire); render it through the dispatch template"
      return 1
      ;;
  esac
  if ! printf '%s\n' "$trimmed" | grep -Eq '(^|[^[:alnum:]])/[a-z][a-z0-9-]+'; then
    FM_MT_ERROR="dispatch: no skill named as /<skill>; the recipient cannot tell what to invoke"
    return 1
  fi
  if ! printf '%s\n' "$trimmed" | grep -Fq 'invoked /'; then
    FM_MT_ERROR="dispatch: missing the required ack line ('invoked /<skill>, run id <dispatch-id>, outcome <ok|blocked|declined>'); silence would be indistinguishable from refusal"
    return 1
  fi
  return 0
}
