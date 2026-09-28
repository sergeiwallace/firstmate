# shellcheck shell=bash
# fm-message-transport-lib.sh - the declared messaging-transport chain behind the
# chief-of-staff dispatch path.
# Usage: . bin/fm-message-transport-lib.sh
#
# This file is the single owner of three things the chief-of-staff session and
# its tests need to agree on:
#   1. Loading and validating config/message-transports.json (schema 1). The
#      chain is DECLARED by the config, not fixed here: native
#      ListAgents/SendMessage is always the primary (its outcomes - held,
#      accepted-offline, activation - are native-specific, so the native-first
#      principle is not configurable), and `fallbacks` is any subset of the
#      known fallback adapters - Agent Mail and the existing fm-send.sh route -
#      in any order, INCLUDING NONE. No fallback adapter is mandatory, so a home
#      with no Agent Mail configured declares a valid chain by leaving it out.
#      The loader still FAILS CLOSED, naming the invalid field, on anything
#      else: a missing file, malformed JSON, a missing `fallbacks` key, an
#      unknown adapter, `native` repeated as a fallback, a repeated adapter, an
#      unknown key, or a timeout outside 60-3600 seconds. A missing timeout
#      defaults to 600; zero, negative, fractional, or out-of-range values are
#      refused, never clamped.
#   2. The next-step decision table for one dispatch attempt (fm_mt_next),
#      resolved against that declared chain. It is in two pure parts: each
#      (adapter, outcome) pair maps to exactly one OUTCOME CLASS - pending,
#      advance, done or stop, with an optional record - and the class then maps
#      to a token against the declared chain, so the table is adapter-agnostic
#      and stays total and deterministic: the same observation always yields the
#      same transition, whichever path observed it. `held` stays pending until
#      its documented terminal outcome and never releases a fallback;
#      accepted-offline and a delivered-but-unclaimed native doorbell release
#      the next declared adapter only through their persisted deadlines; every
#      other ambiguity stops for reconciliation rather than resending. An
#      `advance` from the LAST adapter in the declared chain is `stop:exhausted`
#      rather than an invented successor, so a chain of any length - native
#      alone included - terminates. Because "next" is a property of the declared
#      chain, fm_mt_next requires a loaded config and refuses an adapter the
#      chain does not declare. The fm-send exit contract is unchanged.
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
# The known fallback adapters. Membership is a vocabulary check, not an order:
# a config may declare any subset of these, in any order, or none at all.
FM_MT_KNOWN_FALLBACKS="agent-mail fm-send"
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
# FM_MT_PRIMARY, FM_MT_FALLBACKS (space-separated, in the order declared, empty
# when the config declares no fallback), FM_MT_OFFLINE_TIMEOUT and
# FM_MT_ACTIVATION_TIMEOUT. Returns 2 with FM_MT_ERROR="<field>: <reason>" on any
# deviation from the accepted shape.
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
    --arg known_fallbacks "$FM_MT_KNOWN_FALLBACKS" \
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
        elif .primary != $want_primary then err("primary"; "must be \"\($want_primary)\" (native is always the primary)")
        elif (has("fallbacks")|not) then err("fallbacks"; "required (declare the chain explicitly, even as an empty list)")
        elif (.fallbacks|type) != "array" then err("fallbacks"; "must be an array")
        elif ((.fallbacks|length) > 0 and (.fallbacks|map(type)|unique) != ["string"]) then err("fallbacks"; "must contain adapter names")
        elif ((.fallbacks|index($want_primary)) != null) then err("fallbacks"; "must not name \"\($want_primary)\": it is always the primary")
        elif ((.fallbacks|unique|length) != (.fallbacks|length)) then err("fallbacks"; "must not name an adapter twice")
        elif ((.fallbacks - ($known_fallbacks|split(" ")))|length) > 0 then err("fallbacks"; "must name only known adapters (\($known_fallbacks|split(" ")|map("\"\(.)\"")|join(", "))); got \"\((.fallbacks - ($known_fallbacks|split(" ")))[0])\"")
        else
          (timeout("offline_pending_timeout_seconds")) as $off
          | if ($off|startswith("error ")) then $off
            else (timeout("native_activation_timeout_seconds")) as $act
            | if ($act|startswith("error ")) then $act
              # "-" stands for an empty chain: the verdict is read as whitespace-
              # separated fields, where an empty one would shift the timeouts.
              else "ok \(.primary) \(if (.fallbacks|length) == 0 then "-" else (.fallbacks|join(",")) end) \($off) \($act)" end
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
      if [ "$3" = - ]; then
        FM_MT_FALLBACKS=
      else
        FM_MT_FALLBACKS=${3//,/ }
      fi
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
# Print the declared chain in display form, in declared order (just the primary
# when no fallback is declared). Requires a successful fm_mt_load.
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

# fm_mt_classify <transport> <outcome>
# Step one of the decision table: map one (adapter, outcome) pair to its outcome
# CLASS in FM_MT_CLASS and, where the class carries one, a detail in
# FM_MT_DETAIL - the pending reason, the record to persist before advancing, or
# the reason to stop. Adapter-agnostic by construction: nothing here knows which
# adapter comes next, or whether one exists. Returns 2 with FM_MT_ERROR on an
# outcome the named adapter does not report.
FM_MT_CLASS=
FM_MT_DETAIL=
fm_mt_classify() {
  local transport=$1 outcome=$2
  FM_MT_ERROR=
  FM_MT_CLASS=
  FM_MT_DETAIL=
  case "$transport/$outcome" in
    native/delivered) FM_MT_CLASS=pending; FM_MT_DETAIL=native-activation ;;
    native/held) FM_MT_CLASS=pending; FM_MT_DETAIL=held ;;
    native/offline) FM_MT_CLASS=pending; FM_MT_DETAIL=native-offline ;;
    native/offline-timeout) FM_MT_CLASS=advance; FM_MT_DETAIL=native-timeout ;;
    native/activation-timeout) FM_MT_CLASS=advance; FM_MT_DETAIL=native-activation-timeout ;;
    native/unresolved|native/refused|native/denied|native/expired) FM_MT_CLASS=advance ;;
    native/claimed) FM_MT_CLASS=done ;;
    native/ambiguous) FM_MT_CLASS=stop; FM_MT_DETAIL=reconcile ;;
    agent-mail/unconfigured|agent-mail/cancelled|agent-mail/expired) FM_MT_CLASS=advance ;;
    agent-mail/pending) FM_MT_CLASS=pending; FM_MT_DETAIL=agent-mail ;;
    agent-mail/receipt|agent-mail/claimed) FM_MT_CLASS=done ;;
    agent-mail/ambiguous) FM_MT_CLASS=stop; FM_MT_DETAIL=reconcile ;;
    fm-send/sent|fm-send/claimed) FM_MT_CLASS=done ;;
    # Possibly delivered: stop and read the pane rather than resend.
    fm-send/inconclusive) FM_MT_CLASS=stop; FM_MT_DETAIL=verify-pane ;;
    fm-send/failed) FM_MT_CLASS=advance ;;
    fm-send/ambiguous) FM_MT_CLASS=stop; FM_MT_DETAIL=reconcile ;;
    *)
      FM_MT_ERROR="outcome: '$outcome' is not a known $transport outcome"
      return 2
      ;;
  esac
}

# fm_mt_next <transport> <outcome>
# Print the next action for one dispatch given the outcome the named transport
# just reported, resolving the outcome's class against the DECLARED chain
# (primary first, then the fallbacks in declared order). Requires a successful
# fm_mt_load, because a successor is a property of that chain. Tokens:
#   pending:<what>            keep waiting; no fallback (held, native-offline,
#                             native-activation, agent-mail)
#   fallback:<next>[:<record>] attempt <next>, the adapter declared after this
#                             one, with the SAME dispatch id, after recording
#                             <record> when present
#   done:<transport>          the dispatch reached its recipient's gate
#   stop:<why>                do not try a later transport or resend blindly;
#                             surface the dispatch id (reconcile, verify-pane,
#                             exhausted - the last declared adapter has no
#                             successor)
# No loaded policy, an adapter the chain does not declare, an unknown adapter,
# or an unknown outcome: status 2 with FM_MT_ERROR.
fm_mt_next() {
  local transport=$1 outcome=$2 chain successor= seen=0 t
  FM_MT_ERROR=
  if [ -z "$FM_MT_PRIMARY" ]; then
    FM_MT_ERROR="policy: load the transport config before asking for the next step"
    return 2
  fi
  case " $FM_MT_APPROVED_PRIMARY $FM_MT_KNOWN_FALLBACKS " in
    *" $transport "*) ;;
    *)
      FM_MT_ERROR="transport: '$transport' is not one of ${FM_MT_APPROVED_PRIMARY}, ${FM_MT_KNOWN_FALLBACKS// /, }"
      return 2
      ;;
  esac
  chain="$FM_MT_PRIMARY${FM_MT_FALLBACKS:+ $FM_MT_FALLBACKS}"
  case " $chain " in
    *" $transport "*) ;;
    *)
      FM_MT_ERROR="transport: '$transport' is not in the declared chain ($(fm_mt_order))"
      return 2
      ;;
  esac
  fm_mt_classify "$transport" "$outcome" || return 2
  for t in $chain; do
    if [ "$seen" = 1 ]; then
      successor=$t
      break
    fi
    if [ "$t" = "$transport" ]; then
      seen=1
    fi
  done
  case "$FM_MT_CLASS" in
    pending) printf 'pending:%s\n' "$FM_MT_DETAIL" ;;
    done) printf 'done:%s\n' "$transport" ;;
    stop) printf 'stop:%s\n' "$FM_MT_DETAIL" ;;
    advance)
      if [ -z "$successor" ]; then
        printf 'stop:exhausted\n'
      elif [ -n "$FM_MT_DETAIL" ]; then
        printf 'fallback:%s:%s\n' "$successor" "$FM_MT_DETAIL"
      else
        printf 'fallback:%s\n' "$successor"
      fi
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
