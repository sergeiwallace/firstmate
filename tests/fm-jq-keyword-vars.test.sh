#!/usr/bin/env bash
# Portability guard: no jq program under bin/ binds a named argument to a jq
# keyword.
#
# jq 1.6 (Ubuntu 22.04's package) lexes `$end` or `$label` as `$` followed by
# the keyword and refuses to compile the program ("syntax error, unexpected
# end/label, expecting IDENT"); jq 1.7 accepts them. A host with jq 1.7 never
# sees the failure, so this is a static check rather than a jq run.
# Regression origin: --arg end in fm-devin-config.sh and fm-cortex-plugin.sh,
# and --arg label in fm-contributions.sh and backends/paseo.sh.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TMP_ROOT=$(fm_test_tmproot fm-jq-keyword-vars)

# The jq 1.6 lexer's reserved words (src/lexer.l).
JQ_KEYWORDS='as|def|module|import|include|if|then|elif|else|end|and|or|reduce|foreach|try|catch|label|__loc__'

# keyword_bindings <dir>: print every file:line under <dir> that binds a jq
# named argument (--arg, --argjson, --slurpfile, --rawfile) to a keyword.
keyword_bindings() {
  grep -rnE -- "--(arg|argjson|slurpfile|rawfile)[[:space:]]+($JQ_KEYWORDS)([[:space:]]|$)" "$1"
}

test_detects_a_keyword_binding() {
  local dir="$TMP_ROOT/positive"
  mkdir -p "$dir"
  printf '%s\n' "jq -n --arg end \"\$end\" '{e: \$end}'" > "$dir/end.sh"
  printf '%s\n' "jq -r --arg id x --arg label y '.[] | select(.name == \$label)'" > "$dir/label.sh"
  keyword_bindings "$dir" > "$TMP_ROOT/positive.out" || fail "keyword bindings were not detected"
  assert_grep "end.sh" "$TMP_ROOT/positive.out" "--arg end was not detected"
  assert_grep "label.sh" "$TMP_ROOT/positive.out" "--arg label was not detected"
  pass "a named argument bound to a jq keyword is detected"
}

test_ignores_non_keyword_names() {
  local dir="$TMP_ROOT/negative"
  mkdir -p "$dir"
  printf '%s\n' "jq -n --arg session_end \"\$end\" --arg ready_label x --argjson endpoint 1 --arg want y '.'" > "$dir/ok.sh"
  if keyword_bindings "$dir" > "$TMP_ROOT/negative.out"; then
    fail "a non-keyword name was flagged: $(cat "$TMP_ROOT/negative.out")"
  fi
  pass "names that only contain a keyword are not flagged"
}

test_bin_binds_no_jq_keyword() {
  [ -d "$ROOT/bin" ] || fail "bin/ is missing"
  if keyword_bindings "$ROOT/bin" > "$TMP_ROOT/bin.out"; then
    fail "jq 1.6 cannot compile these named arguments: $(cat "$TMP_ROOT/bin.out")"
  fi
  pass "no jq program under bin/ binds a named argument to a jq keyword"
}

test_detects_a_keyword_binding
test_ignores_non_keyword_names
test_bin_binds_no_jq_keyword
