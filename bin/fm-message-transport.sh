#!/usr/bin/env bash
# fm-message-transport.sh - command-line face of the declared messaging-transport
# policy (bin/fm-message-transport-lib.sh) used by the chief-of-staff dispatch path.
#
# Usage: fm-message-transport.sh [--config <path>] <command> [args...]
#   validate                     load the policy; print the resolved fields, or the
#                                invalid field and exit 2 (fail closed before dispatch)
#   --dry-run | order            validate, then print the declared chain, e.g.
#                                native -> buzz -> agent-mail -> fm-send
#   next <transport> <outcome>   print the next action token for one dispatch attempt,
#                                resolved against the declared chain, so this command
#                                loads the config too (see the library header for the
#                                token grammar)
#   deadline <accepted-epoch> offline|activation
#                                print the durable deadline: acceptance time plus the
#                                configured timeout, computed once
#   check-dispatch [<text>|-]    exit 0 when the text obeys the dispatch phrasing
#                                discipline; exit 1 and name the refusal otherwise
#                                (`-` reads the text from stdin)
#   --help
#
# The config is <FM_CONFIG_OVERRIDE or $FM_HOME/config>/message-transports.json
# unless --config names a file. Like fm-send.sh, this command refuses to guess a
# home: with neither FM_HOME nor FM_CONFIG_OVERRIDE set it exits 2.
#
# Exit codes: 0 ok; 1 dispatch text refused (check-dispatch only); 2 invalid
# config, unknown transport/outcome, bad arguments, or unresolvable home.
# Nothing here sends a message or touches a task; it only answers "what does the
# declared policy allow next", so a chief and its tests share one definition.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/fm-message-transport-lib.sh disable=SC1091
. "$SCRIPT_DIR/fm-message-transport-lib.sh"

usage() {
  awk '
    NR == 1 { next }
    /^#/ { sub(/^# ?/, ""); print; next }
    { exit }
  ' "$0"
}

refuse() {  # <status> <message>
  printf 'fm-message-transport: %s\n' "$2" >&2
  exit "$1"
}

CONFIG=
while [ $# -gt 0 ]; do
  case "$1" in
    --config)
      [ $# -ge 2 ] || refuse 2 "--config requires a path"
      CONFIG=$2
      shift 2
      ;;
    --config=*)
      CONFIG=${1#--config=}
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) break ;;
  esac
done

[ $# -ge 1 ] || { usage >&2; exit 2; }
COMMAND=$1
shift

load_config() {
  if [ -z "$CONFIG" ]; then
    fm_mt_config_path >/dev/null || refuse 2 "$FM_MT_ERROR"
    CONFIG=$FM_MT_CONFIG_PATH
  fi
  fm_mt_load "$CONFIG" || refuse 2 "invalid transport config ($CONFIG): $FM_MT_ERROR"
}

case "$COMMAND" in
  validate)
    load_config
    printf 'config=%s\nprimary=%s\nfallbacks=%s\noffline_pending_timeout_seconds=%s\nnative_activation_timeout_seconds=%s\n' \
      "$CONFIG" "$FM_MT_PRIMARY" "$FM_MT_FALLBACKS" "$FM_MT_OFFLINE_TIMEOUT" "$FM_MT_ACTIVATION_TIMEOUT"
    ;;
  --dry-run|order)
    load_config
    fm_mt_order || refuse 2 "$FM_MT_ERROR"
    ;;
  next)
    [ $# -eq 2 ] || refuse 2 "next requires <transport> <outcome>"
    load_config
    fm_mt_next "$1" "$2" || refuse 2 "$FM_MT_ERROR"
    ;;
  deadline)
    [ $# -eq 2 ] || refuse 2 "deadline requires <accepted-epoch> offline|activation"
    load_config
    case "$2" in
      offline) fm_mt_deadline "$1" "$FM_MT_OFFLINE_TIMEOUT" || refuse 2 "$FM_MT_ERROR" ;;
      activation) fm_mt_deadline "$1" "$FM_MT_ACTIVATION_TIMEOUT" || refuse 2 "$FM_MT_ERROR" ;;
      *) refuse 2 "deadline kind must be offline or activation (got '$2')" ;;
    esac
    ;;
  check-dispatch)
    [ $# -eq 1 ] || refuse 2 "check-dispatch requires one text argument or -"
    if [ "$1" = - ]; then
      TEXT=$(cat)
    else
      TEXT=$1
    fi
    if fm_mt_check_dispatch "$TEXT"; then
      printf 'ok\n'
    else
      refuse 1 "$FM_MT_ERROR"
    fi
    ;;
  *)
    refuse 2 "unknown command '$COMMAND' (see --help)"
    ;;
esac
