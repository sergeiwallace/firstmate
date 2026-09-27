#!/usr/bin/env bash
# Behavior tests for the VP-owner authority layer (bin/fm-vp-owner.py): signer
# identity, unattended self-provisioning, self-verifying owner records, and
# owner-route resolution.
#
# What these guard: a document that claims to be an owner record either is one or
# is rejected by name. A key id is the SHA-256 of its own public key, and the
# record carries that public key, so a record cannot name one key id while
# carrying another key's material. An owner record verifies only as byte-for-byte
# canonical JSON, under Ed25519, with a chief_instance_key that derives from its
# own owner_machine_key. Those document-validity failures exit 4 and name the
# failed check; bad input and an unresolved route exit 2.
#
# What these deliberately do NOT guard: that the asserted machine key is this
# machine's. Ownership is self-asserted (see the tool's header). There is no
# expiry, no registry, no revocation and no signing window, so nothing here can
# refuse a well-formed record for a trust reason. The one identity expectation a
# caller can express, --expected-owner-machine-key, is a soft warning that still
# exits 0, and a test below pins exactly that.
#
# self-provision is the unattended install path, so its tests are the
# self-healing ones: every way its state can be missing, garbage, or hand-edited
# heals and exits 0, naming what it healed in JSON and on stderr.
#
# Positive controls run first in every group, so a refuse-everything
# implementation cannot pass: a valid record verifies, a good route resolves, a
# second self-provision run is a no-op, and the signature and key id are
# recomputed here independently of the tool. Every command runs as a subprocess
# against real files and a real openssl in a fresh private temp home. No
# privileged path is written: the /etc and /var guards are proved with path
# strings only.
set -u

# shellcheck source=tests/lib.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TOOL="$ROOT/bin/fm-vp-owner.py"
TMP_ROOT=$(fm_test_tmproot fm-vp-owner)

command -v python3 >/dev/null 2>&1 || { printf 'skip: python3 not found\n'; exit 0; }
command -v openssl >/dev/null 2>&1 || { printf 'skip: openssl not found\n'; exit 0; }
openssl genpkey -algorithm ed25519 -out "$TMP_ROOT/probe.pem" 2>/dev/null ||
  { printf 'skip: this openssl has no Ed25519 (genpkey -algorithm ed25519 failed)\n'; exit 0; }

# run <expected-exit> <label> <cmd...>: capture combined output into OUT, exit into RC.
OUT=
ERR=
RC=0
run() {
  local expected=$1 label=$2
  shift 2
  set +e
  OUT=$("$@" 2>&1)
  RC=$?
  expect_code "$expected" "$RC" "$label"
}

# run_split <expected-exit> <label> <cmd...>: stdout into OUT, stderr into ERR.
# Needed wherever a command prints one JSON object on stdout AND warnings on
# stderr: combining the two streams would make the JSON unparseable.
run_split() {
  local expected=$1 label=$2
  shift 2
  set +e
  OUT=$("$@" 2>"$TMP_ROOT/.stderr")
  RC=$?
  ERR=$(cat "$TMP_ROOT/.stderr")
  expect_code "$expected" "$RC" "$label"
}
set +e

# json <path-expr> reads one field from $OUT: json healed.0
json() {
  printf '%s' "$OUT" | python3 -c '
import json, sys
obj = json.loads(sys.stdin.read())
for key in sys.argv[1].split("."):
    obj = obj[key] if not isinstance(obj, list) else obj[int(key)]
print(obj if not isinstance(obj, (dict, list)) else json.dumps(obj, sort_keys=True))
' "$1"
}

# file_json <file> <path-expr>: the same read against a file on disk.
file_json() {
  python3 -c '
import json, sys
obj = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    obj = obj[key] if not isinstance(obj, list) else obj[int(key)]
print(obj if not isinstance(obj, (dict, list)) else json.dumps(obj, sort_keys=True))
' "$1" "$2"
}

mode_of() {  # <path> -> the octal permission bits, on Linux or macOS
  stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"
}

new_dir() {  # <name> -> a fresh private directory
  local dir="$TMP_ROOT/$1"
  mkdir -p "$dir"
  chmod 700 "$dir"
  printf '%s\n' "$dir"
}

# mutate <in> <out> <python-body>: rewrite a JSON document; `doc` is the parsed object,
# and the result is canonical JSON plus one LF unless the body sets `raw`.
mutate() {
  local src=$1 dst=$2 body=$3
  python3 - "$src" "$dst" "$body" <<'PY'
import json, sys
src, dst, body = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(src))
raw = None
exec(body)  # noqa: S102 - fixture surgery, test-local
if raw is None:
    raw = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
open(dst, "wb").write(raw)
PY
}

# --- two machine signers, generated once with real openssl -----------------------------------------

MK1_DIR=$(new_dir keys-mk-1)
MK2_DIR=$(new_dir keys-mk-2)
run 0 "keygen mk-1" python3 "$TOOL" keygen --key-dir "$MK1_DIR/vp-owner"
KEY1=$(json key_id); PUB1=$(json public_key); PRIV1=$(json private_key_path)
run 0 "keygen mk-2" python3 "$TOOL" keygen --key-dir "$MK2_DIR/vp-owner"
KEY2=$(json key_id); PUB2=$(json public_key); PRIV2=$(json private_key_path)

# sign_record <out> <epoch> <signed_at> [extra sign-owner args...]
sign_record() {
  local out=$1 epoch=$2 signed_at=$3
  shift 3
  python3 "$TOOL" sign-owner --private-key "$PRIV1" --vp-id vp/ai-harness/primary \
    --owner-machine-key mk-1 --owner-epoch "$epoch" --chief-instance-key firstmate-chief/mk-1 \
    --ownership-state active --signed-at "$signed_at" --out "$out" "$@"
}

# --- keygen: a content-addressed identity, never a privileged write -------------------------------

test_keygen_creates_a_private_key_whose_id_is_the_hash_of_its_own_public_key() {
  local dir recomputed
  dir=$(new_dir keygen)
  run 0 "keygen" python3 "$TOOL" keygen --key-dir "$dir/vp-owner"
  assert_equals 700 "$(mode_of "$dir/vp-owner")" "key dir is 0700"
  assert_equals 600 "$(mode_of "$(json private_key_path)")" "private key is 0600"
  assert_not_contains "$OUT" "PRIVATE KEY" "keygen never prints private key material"
  assert_equals "$dir/vp-owner/$(json key_id).key" "$(json private_key_path)" "the key file is named by its key id"
  # Positive control on the identity contract, recomputed here from the private key.
  recomputed=$(openssl pkey -in "$(json private_key_path)" -pubout -outform DER | python3 -c '
import base64, hashlib, sys
der = sys.stdin.buffer.read()
raw = der[12:]
print("ed25519-sha256:" + hashlib.sha256(raw).hexdigest(), base64.urlsafe_b64encode(raw).decode().rstrip("="))')
  assert_equals "$recomputed" "$(json key_id) $(json public_key)" "key_id is the SHA-256 of the raw 32-byte public key"
  pass "keygen writes a 0600 key in a 0700 caller-owned directory and prints only its content-addressed identity"
}

test_keygen_refuses_a_privileged_or_unowned_directory_without_writing() {
  local dir
  dir=$(new_dir keygen-guard)
  run 2 "under /etc" python3 "$TOOL" keygen --key-dir /etc/ai-harness/trust/vp-owner
  assert_contains "$OUT" "/etc" "the refusal names the installer-owned root"
  assert_contains "$OUT" "never writes there" "the refusal says it never writes there"
  run 2 "under /var/lib" python3 "$TOOL" keygen --key-dir /var/lib/ai-harness/keys/vp-owner
  assert_contains "$OUT" "/var/lib" "the /var/lib key root is refused too"
  run 2 "the root directory" python3 "$TOOL" keygen --key-dir /
  assert_contains "$OUT" "never a key or trust directory" "/ is refused"
  if [ "$(stat -c %u / 2>/dev/null || stat -f %u /)" != "$(id -u)" ]; then
    run 2 "a directory this identity does not own" python3 "$TOOL" keygen --key-dir /
    assert_contains "$OUT" "refused" "an unowned directory refuses"
  fi
  chmod 777 "$dir"
  run 2 "a world-writable directory" python3 "$TOOL" keygen --key-dir "$dir"
  assert_contains "$OUT" "accessible to other users" "a world-writable key directory is refused"
  chmod 700 "$dir"
  ln -s /etc "$dir/etc-link"
  run 2 "a symlink into /etc" python3 "$TOOL" keygen --key-dir "$dir/etc-link/ai-harness-keys"
  assert_contains "$OUT" "/etc" "a symlink into a reserved root is resolved and refused"
  assert_absent "/etc/ai-harness-keys" "no refused keygen created the path it was asked for"
  assert_absent "/etc/ai-harness/trust/vp-owner" "no refused keygen created the /etc trust path either"
  run 0 "positive control: a private caller-owned directory works" python3 "$TOOL" keygen --key-dir "$dir/ok"
  pass "keygen refuses an installer-owned, unowned, or shared directory and writes nothing there"
}

# --- self-provision: the unattended install path, self-healing in every direction ------------------

test_self_provision_creates_a_signer_identity_unattended_and_never_prints_the_key() {
  local dir recomputed
  dir=$(new_dir provision)
  run_split 0 "positive control: first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals True "$(json provisioned)" "the machine is provisioned"
  assert_equals mk-1 "$(json machine_key)" "the caller-supplied machine key is carried"
  assert_equals firstmate-chief/mk-1 "$(json chief_instance_key)" "the chief instance key derives from the machine key"
  assert_equals '["key-generated"]' "$(json healed)" "a first provision generates the one key it needs"
  assert_contains "$ERR" "warning: key-generated" "the generated key is warned about on stderr"
  assert_not_contains "$OUT" "PRIVATE KEY" "self-provision never prints private key material"
  assert_not_contains "$ERR" "PRIVATE KEY" "self-provision never warns with private key material"
  assert_equals 700 "$(mode_of "$dir/vp-owner")" "the state directory is 0700"
  assert_equals 700 "$(mode_of "$dir/vp-owner/keys")" "the key directory is 0700"
  assert_equals 600 "$(mode_of "$(json key_path)")" "the private key is 0600"
  assert_equals 600 "$(mode_of "$dir/vp-owner/self.json")" "self.json is 0600"
  assert_equals "$dir/vp-owner/self.json" "$(json self_path)" "the self record path is reported"
  assert_equals 1 "$(file_json "$dir/vp-owner/self.json" schema_version)" "self.json carries its schema version"
  assert_equals 2026-09-27T10:00:00Z "$(file_json "$dir/vp-owner/self.json" provisioned_at)" "the provisioning instant is recorded"
  # Positive control: self.json is byte-for-byte canonical JSON plus one LF, and its
  # identity fields are the openssl-recomputed identity of the key on disk.
  recomputed=$(python3 - "$dir/vp-owner/self.json" "$(json key_path)" <<'PY'
import base64, hashlib, json, subprocess, sys
raw = open(sys.argv[1], "rb").read()
doc = json.loads(raw)
canonical = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
der = subprocess.run(["openssl", "pkey", "-in", sys.argv[2], "-pubout", "-outform", "DER"],
                     stdout=subprocess.PIPE, check=True).stdout
pub = der[12:]
print("canonical" if raw == canonical else "not-canonical",
      "key-id-ok" if doc["key_id"] == "ed25519-sha256:" + hashlib.sha256(pub).hexdigest() else "key-id-wrong",
      "public-key-ok" if doc["public_key"] == base64.urlsafe_b64encode(pub).decode().rstrip("=") else "public-key-wrong")
PY
)
  assert_equals "canonical key-id-ok public-key-ok" "$recomputed" "self.json is canonical and names the identity of the key on disk"
  # And the identity it wrote is usable as a signing identity with no further argument.
  run 0 "the provisioned identity signs" python3 "$TOOL" --now 2026-09-27T11:00:00Z sign-owner \
    --state-dir "$dir/vp-owner" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 \
    --owner-epoch 1 --chief-instance-key firstmate-chief/mk-1 --ownership-state active \
    --out "$dir/owner.json"
  assert_equals "$(file_json "$dir/vp-owner/self.json" key_id)" "$(json key_id)" "the record is signed by the provisioned key"
  run 0 "and that record verifies" python3 "$TOOL" verify-owner --record "$dir/owner.json"
  assert_equals True "$(json verified)" "the provisioned identity produces a verifiable record"
  pass "self-provision creates a 0600 key and a canonical 0600 self.json in a 0700 directory, prints no key material, and yields a usable signing identity"
}

test_a_second_self_provision_run_changes_nothing() {
  local dir first_key first_sha
  dir=$(new_dir provision-idempotent)
  run_split 0 "first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  first_key=$(json key_id)
  first_sha=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$dir/vp-owner/self.json")
  run_split 0 "second provision" python3 "$TOOL" --now 2026-09-27T12:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '[]' "$(json healed)" "a healthy second run heals nothing"
  assert_equals "" "$ERR" "a healthy second run warns about nothing"
  assert_equals "$first_key" "$(json key_id)" "the key id is unchanged"
  assert_equals "$first_sha" "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$dir/vp-owner/self.json")" "self.json is byte-identical, so provisioned_at was not churned"
  assert_equals 1 "$(find "$dir/vp-owner/keys" -name '*.key' | wc -l | tr -d ' ')" "no second key was generated"
  pass "self-provision is idempotent: a healthy second run generates no key, rewrites nothing, and heals nothing"
}

test_self_provision_heals_a_deleted_or_garbage_self_record_by_adopting_the_existing_key() {
  local dir first_key
  dir=$(new_dir provision-heal-self)
  run_split 0 "first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  first_key=$(json key_id)

  rm -f "$dir/vp-owner/self.json"
  run_split 0 "a deleted self.json heals" python3 "$TOOL" --now 2026-09-27T12:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["self-missing"]' "$(json healed)" "the missing self record is named"
  assert_contains "$ERR" "warning: self-missing" "the heal is warned about on stderr"
  assert_equals "$first_key" "$(json key_id)" "the existing key was adopted rather than replaced"
  assert_present "$dir/vp-owner/self.json" "self.json is back"

  printf 'not json at all\x00\xff' > "$dir/vp-owner/self.json"
  run_split 0 "garbage bytes heal" python3 "$TOOL" --now 2026-09-27T13:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["self-unparseable"]' "$(json healed)" "the unparseable self record is named"
  assert_contains "$ERR" "warning: self-unparseable" "the unparseable heal is warned about on stderr"
  assert_equals "$first_key" "$(json key_id)" "garbage in self.json never costs the machine its key"
  assert_equals 1 "$(find "$dir/vp-owner/keys" -name '*.key' | wc -l | tr -d ' ')" "still exactly one key"
  pass "a deleted or unparseable self.json regenerates from the key on disk instead of refusing or minting a new identity"
}

test_self_provision_heals_a_self_record_naming_a_key_that_is_not_there() {
  local dir first_key
  dir=$(new_dir provision-heal-key)
  run_split 0 "first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  first_key=$(json key_id)
  mutate "$dir/vp-owner/self.json" "$dir/vp-owner/self.json" \
    'doc["key_id"] = "ed25519-sha256:" + "0" * 64'
  run_split 0 "a self.json naming an absent key heals" python3 "$TOOL" --now 2026-09-27T12:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["self-key-missing"]' "$(json healed)" "the absent key is named"
  assert_contains "$ERR" "warning: self-key-missing" "the heal is warned about on stderr"
  assert_equals "$first_key" "$(json key_id)" "the key that is actually on disk is adopted"
  assert_equals "$first_key" "$(file_json "$dir/vp-owner/self.json" key_id)" "self.json is rewritten to the adopted key"
  assert_equals 1 "$(find "$dir/vp-owner/keys" -name '*.key' | wc -l | tr -d ' ')" "adoption did not mint a second key"
  pass "a self.json naming a key that is not on disk adopts the key that is, rather than refusing or minting a new identity"
}

test_self_provision_heals_a_hand_edited_machine_key_and_public_key() {
  local dir first_key
  dir=$(new_dir provision-heal-edits)
  run_split 0 "first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  first_key=$(json key_id)

  mutate "$dir/vp-owner/self.json" "$dir/vp-owner/self.json" \
    'doc["machine_key"] = "mk-9"; doc["chief_instance_key"] = "firstmate-chief/mk-9"'
  run_split 0 "a hand-edited machine key heals" python3 "$TOOL" --now 2026-09-27T12:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["self-machine-key"]' "$(json healed)" "the disagreeing machine key is named"
  assert_contains "$ERR" "warning: self-machine-key" "the heal is warned about on stderr"
  assert_contains "$ERR" mk-9 "the warning names the value it replaced"
  assert_equals mk-1 "$(file_json "$dir/vp-owner/self.json" machine_key)" "the argument wins over the file"
  assert_equals firstmate-chief/mk-1 "$(file_json "$dir/vp-owner/self.json" chief_instance_key)" "the chief key is re-derived"

  # A key id that names a key file that IS there, with the wrong public key beside it.
  cp "$PRIV2" "$dir/vp-owner/keys/$KEY2.key"
  mutate "$dir/vp-owner/self.json" "$dir/vp-owner/self.json" \
    "doc['key_id'] = '$KEY2'"
  run_split 0 "a hand-edited key id heals" python3 "$TOOL" --now 2026-09-27T13:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["self-key-id"]' "$(json healed)" "the disagreeing key id is named"
  assert_contains "$ERR" "warning: self-key-id" "the heal is warned about on stderr"
  assert_equals "$KEY2" "$(file_json "$dir/vp-owner/self.json" key_id)" "the key id that names a real key file is kept"
  assert_equals "$PUB2" "$(file_json "$dir/vp-owner/self.json" public_key)" "the public key is rewritten from the key on disk"
  run_split 0 "and the healed state is then stable" python3 "$TOOL" --now 2026-09-27T14:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '[]' "$(json healed)" "healing converges: the next run heals nothing"
  pass "a hand-edited machine key or public key is rewritten from the argument and the key on disk, each heal named in JSON and on stderr, and healing converges"
}

test_self_provision_tightens_a_shared_state_directory_and_drops_legacy_fields() {
  local dir
  dir=$(new_dir provision-mode)
  run_split 0 "first provision" python3 "$TOOL" --now 2026-09-27T10:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  chmod 755 "$dir/vp-owner"
  run_split 0 "a group-readable state directory heals" python3 "$TOOL" --now 2026-09-27T12:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals '["state-dir-mode"]' "$(json healed)" "the loosened mode is named"
  assert_contains "$ERR" "warning: state-dir-mode" "the mode heal is warned about on stderr"
  assert_equals 700 "$(mode_of "$dir/vp-owner")" "the directory was tightened rather than refused"

  # A self.json carrying the retired expiry and registry fields is accepted and
  # rewritten without them: legacy state never blocks an install.
  mutate "$dir/vp-owner/self.json" "$dir/vp-owner/self.json" \
    'doc["expires_at"] = "2027-01-01T00:00:00Z"; doc["trust_registry_revision"] = 4'
  run_split 0 "legacy fields heal" python3 "$TOOL" --now 2026-09-27T13:00:00Z \
    self-provision --state-dir "$dir/vp-owner" --machine-key mk-1
  assert_equals 6 "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$dir/vp-owner/self.json")" \
    "the rewritten self.json carries exactly its six fields"
  assert_not_contains "$(cat "$dir/vp-owner/self.json")" "2027-01-01" "the retired expiry field is gone"

  run 2 "a state directory owned by another identity is still refused" python3 "$TOOL" \
    self-provision --state-dir /var/lib/ai-harness/vp-owner --machine-key mk-1
  assert_contains "$OUT" "never writes there" "the write-safety guard survives the simplification"
  pass "self-provision tightens a loosened state directory and drops retired fields instead of refusing, while the write-safety guard still refuses an installer-owned root"
}

# --- owner records -------------------------------------------------------------------------------

test_a_validly_signed_owner_record_verifies_from_its_own_public_key() {
  local dir recomputed
  dir=$(new_dir verify)
  run 0 "sign" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  assert_equals "$KEY1" "$(json key_id)" "the record is signed by this machine's key"
  run 0 "positive control: verify" python3 "$TOOL" verify-owner --record "$dir/owner.json"
  assert_equals True "$(json verified)" "a validly signed record verifies"
  assert_equals '[]' "$(json warnings)" "a record with nothing to warn about carries no warnings"
  assert_equals active "$(json ownership_state)" "the ownership state is projected"
  assert_equals 4 "$(json owner_epoch)" "the owner epoch is projected"
  assert_equals mk-1 "$(json owner_machine_key)" "the owner machine key is projected"
  assert_equals "$PUB1" "$(file_json "$dir/owner.json" protected.public_key)" "the record carries its own public key"
  assert_contains "$OUT" "is not a current record" "verification does not claim to be a CAS read"
  # Positive control on the envelope: recompute the signed bytes from the record's own
  # protected public key and verify with openssl.
  recomputed=$(python3 - "$dir/owner.json" "$dir" <<'PY'
import base64, json, subprocess, sys
raw = open(sys.argv[1], "rb").read()
doc = json.loads(raw)
work = sys.argv[2]
canonical = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
if raw != canonical:
    print("not-canonical"); sys.exit(0)
msg = b"ai-harness/vp-owner/v1\0" + json.dumps({"protected": doc["protected"], "payload": doc["payload"]},
                                               sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
pub = doc["protected"]["public_key"]
raw_pub = base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))
open(work + "/v.der", "wb").write(bytes.fromhex("302a300506032b6570032100") + raw_pub)
open(work + "/v.msg", "wb").write(msg)
sig = doc["signature"]
open(work + "/v.sig", "wb").write(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
rc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", work + "/v.der", "-keyform", "DER",
                     "-rawin", "-in", work + "/v.msg", "-sigfile", work + "/v.sig"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
print("canonical-and-verified" if rc == 0 else "signature-failed")
PY
)
  assert_equals canonical-and-verified "$recomputed" "the stored blob is canonical and its signature covers the domain prefix plus the protected and payload objects"
  pass "a record verifies against the public key it carries, and its envelope matches the specified signed bytes exactly"
}

test_a_flipped_signature_or_payload_byte_fails_verification() {
  local dir
  dir=$(new_dir tamper)
  run 0 "sign" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  mutate "$dir/owner.json" "$dir/flipped-sig.json" \
    'sig = doc["signature"]; doc["signature"] = ("B" if sig[0] != "B" else "C") + sig[1:]'
  run 4 "one flipped signature byte" python3 "$TOOL" verify-owner --record "$dir/flipped-sig.json"
  assert_equals signature "$(json failed_check)" "a flipped signature byte fails the signature check"
  mutate "$dir/owner.json" "$dir/flipped-payload.json" 'doc["payload"]["owner_epoch"] = 5'
  run 4 "one flipped payload byte" python3 "$TOOL" verify-owner --record "$dir/flipped-payload.json"
  assert_equals signature "$(json failed_check)" "an edited payload fails the signature check"
  mutate "$dir/owner.json" "$dir/other-alg.json" 'doc["protected"]["alg"] = "RSA"'
  run 4 "another algorithm" python3 "$TOOL" verify-owner --record "$dir/other-alg.json"
  assert_equals alg "$(json failed_check)" "another algorithm is rejected before any signature work"
  mutate "$dir/owner.json" "$dir/missing.json" 'del doc["payload"]["chief_instance_key"]'
  run 4 "missing field" python3 "$TOOL" verify-owner --record "$dir/missing.json"
  assert_equals structure "$(json failed_check)" "a missing payload field is rejected"
  assert_contains "$OUT" "chief_instance_key" "the missing field is named"
  mutate "$dir/owner.json" "$dir/padded.json" 'doc["signature"] = doc["signature"] + "=="'
  run 4 "padded base64" python3 "$TOOL" verify-owner --record "$dir/padded.json"
  assert_equals base64 "$(json failed_check)" "a padded signature is not canonical unpadded base64url"
  mutate "$dir/owner.json" "$dir/bad-ts.json" 'doc["payload"]["signed_at"] = "2026-09-26 10:00:00"'
  run 4 "non-canonical timestamp" python3 "$TOOL" verify-owner --record "$dir/bad-ts.json"
  assert_equals timestamp "$(json failed_check)" "a non-RFC-3339 signed_at is rejected"
  mutate "$dir/owner.json" "$dir/legacy.json" 'doc["protected"]["trust_registry_revision"] = 4'
  run 4 "a record from the retired registry schema" python3 "$TOOL" verify-owner --record "$dir/legacy.json"
  assert_equals structure "$(json failed_check)" "a protected header carrying the retired registry field is not an owner record"
  pass "a flipped signature or payload byte, another algorithm, a missing or retired field, padded base64, and a non-canonical timestamp each fail a named check"
}

test_a_non_canonical_serialization_is_refused_even_with_a_valid_signature() {
  local dir
  dir=$(new_dir canonical)
  run 0 "sign" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  mutate "$dir/owner.json" "$dir/reordered.json" \
    'raw = (__import__("json").dumps({k: doc[k] for k in ("signature", "schema_version", "protected", "payload")}, sort_keys=False, separators=(",", ":")) + "\n").encode()'
  run 4 "reordered keys" python3 "$TOOL" verify-owner --record "$dir/reordered.json"
  assert_equals canonical-serialization "$(json failed_check)" "a reordered blob is not the canonical serialization"
  mutate "$dir/owner.json" "$dir/spaced.json" \
    'raw = (__import__("json").dumps(doc, sort_keys=True, separators=(", ", ": ")) + "\n").encode()'
  run 4 "inserted whitespace" python3 "$TOOL" verify-owner --record "$dir/spaced.json"
  assert_equals canonical-serialization "$(json failed_check)" "inserted whitespace is not canonical"
  python3 -c 'import sys; raw = open(sys.argv[1], "rb").read(); open(sys.argv[2], "wb").write(raw.rstrip(b"\n"))' \
    "$dir/owner.json" "$dir/no-lf.json"
  run 4 "missing trailing LF" python3 "$TOOL" verify-owner --record "$dir/no-lf.json"
  assert_equals canonical-serialization "$(json failed_check)" "the one trailing LF is part of the stored blob"
  run 0 "positive control: the untouched blob still verifies" python3 "$TOOL" verify-owner --record "$dir/owner.json"
  pass "a blob that is not byte-for-byte the canonical serialization is refused before its signature is even consulted"
}

test_a_record_cannot_name_one_key_id_while_carrying_another_key() {
  local dir
  dir=$(new_dir self-verifying)
  run 0 "sign" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  run 0 "positive control: verify" python3 "$TOOL" verify-owner --record "$dir/owner.json"
  # Swap in another key's public key: the key id no longer hashes to the material
  # the record carries, so the record is not an owner record at all. Without this
  # check a forged record could carry any key and claim the real machine's key id.
  mutate "$dir/owner.json" "$dir/swapped.json" "doc['protected']['public_key'] = '$PUB2'"
  run 4 "public key swapped for another key's" python3 "$TOOL" verify-owner --record "$dir/swapped.json"
  assert_equals key-id-mismatch "$(json failed_check)" "the key id must be the SHA-256 of the public key beside it"
  assert_contains "$OUT" "$KEY1" "the refusal names the key id that does not match"
  # The other direction: keep the key, rename the id.
  mutate "$dir/owner.json" "$dir/renamed.json" "doc['protected']['key_id'] = '$KEY2'"
  run 4 "key id swapped for another key's" python3 "$TOOL" verify-owner --record "$dir/renamed.json"
  assert_equals key-id-mismatch "$(json failed_check)" "renaming the key id fails the same check"
  pass "a record whose key id is not the hash of the public key it carries is rejected as a document, in both directions"
}

test_a_chief_instance_key_must_derive_from_its_own_owner_machine_key() {
  local dir
  dir=$(new_dir chief-binding)
  run 0 "positive control: a derived chief key signs" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  run 0 "and verifies" python3 "$TOOL" verify-owner --record "$dir/owner.json"
  assert_equals firstmate-chief/mk-1 "$(json chief_instance_key)" "the chief instance key is projected"
  mutate "$dir/owner.json" "$dir/other-chief.json" \
    'doc["payload"]["chief_instance_key"] = "firstmate-chief/mk-9"'
  run 4 "a chief key from another machine" python3 "$TOOL" verify-owner --record "$dir/other-chief.json"
  assert_equals chief-binding "$(json failed_check)" "a chief key that does not derive from the owner machine key is rejected"
  assert_contains "$OUT" firstmate-chief/mk-1 "the refusal names the only chief key that record could carry"
  run 2 "signing refuses the same contradiction" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-9 --ownership-state active --out "$dir/nope.json"
  assert_contains "$OUT" firstmate-chief/mk-1 "signing names the derived chief key it expected"
  assert_absent "$dir/nope.json" "a refused signing wrote no record"
  pass "chief_instance_key is derived, not asserted: a record whose chief key does not follow from its owner machine key is refused at signing and rejected at verification"
}

test_an_unexpected_owner_machine_key_warns_and_still_verifies() {
  local dir
  dir=$(new_dir expected-owner)
  run 0 "sign" sign_record "$dir/owner.json" 4 2026-09-26T10:00:00Z
  run_split 0 "positive control: the expected owner produces no warning" python3 "$TOOL" verify-owner \
    --record "$dir/owner.json" --expected-owner-machine-key mk-1
  assert_equals True "$(json verified)" "the matching expectation verifies"
  assert_equals '[]' "$(json warnings)" "a matching expectation warns about nothing"
  assert_equals "" "$ERR" "and says nothing on stderr"
  # The whole point of the simplification: an identity expectation that disagrees is a
  # soft warning that still dispatches, never a refusal that blocks.
  run_split 0 "a disagreeing expectation still verifies" python3 "$TOOL" verify-owner \
    --record "$dir/owner.json" --expected-owner-machine-key mk-9
  assert_equals True "$(json verified)" "a disagreeing expectation does not stop verification"
  assert_contains "$(json warnings)" machine-binding "the warning is named in the JSON object"
  assert_contains "$(json warnings)" mk-9 "the warning names the expectation that was not met"
  assert_contains "$ERR" "warning: machine-binding" "the same warning is written to stderr"
  assert_contains "$ERR" mk-1 "the stderr warning names the record's own owner machine key"
  pass "an owner machine key that is not the expected one is a soft warning in the JSON and on stderr, and still exits 0"
}

test_a_prepared_handoff_record_round_trips_with_its_destination_and_nonce() {
  local dir
  dir=$(new_dir handoff)
  cat > "$dir/handoff.json" <<'JSON'
{"handoff_id": "ho-1", "destination_machine_key": "mk-2", "next_owner_epoch": 5,
 "nonce": "nonce-abc", "prepared_at": "2026-09-26T10:00:00Z"}
JSON
  run 0 "sign the prepared handoff" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --predecessor-object-id 1111111111111111111111111111111111111111 \
    --handoff-file "$dir/handoff.json" --out "$dir/prepared.json"
  run 0 "verify the prepared handoff" python3 "$TOOL" verify-owner --record "$dir/prepared.json"
  assert_equals handoff-prepared "$(json ownership_state)" "the prepared state is projected"
  assert_equals mk-2 "$(json handoff.destination_machine_key)" "the destination machine is projected"
  assert_equals 5 "$(json handoff.next_owner_epoch)" "the next epoch is projected"
  assert_equals nonce-abc "$(json handoff.nonce)" "the single-use nonce is projected"
  mutate "$dir/prepared.json" "$dir/retargeted.json" 'doc["payload"]["handoff"]["destination_machine_key"] = "mk-9"'
  run 4 "a retargeted handoff" python3 "$TOOL" verify-owner --record "$dir/retargeted.json"
  assert_equals signature "$(json failed_check)" "changing the destination invalidates the signature"
  run 2 "a next epoch that does not advance" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 9 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --handoff-file "$dir/handoff.json" --out "$dir/stale-epoch.json"
  assert_contains "$OUT" "must be greater than the current" "a prepared handoff must advance the epoch"
  run 2 "a prepared state with no handoff at all" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --out "$dir/bad-handoff.json"
  assert_contains "$OUT" "must name its handoff" "a prepared record without a handoff object is refused"
  assert_absent "$dir/bad-handoff.json" "a refused signing wrote no record"
  pass "a prepared handoff carries its destination, next epoch and nonce inside the signed payload, and signing refuses a prepared state with no handoff or a next epoch that does not advance"
}

# --- owner-route resolution ----------------------------------------------------------------------

routes_file() {  # <out> <json-body>
  printf '%s\n' "$2" > "$1"
}

ROUTE_ROW_MK2='{"machine_key":"mk-2","route_revision":3,"chief_instance_key":"firstmate-chief/mk-2","native_agent_name":"cos-mk-2","agent_mail":{"project_key":"fleet","agent_name":"cos-mk-2"},"fm_send":{"ssh_host":"mk-2","firstmate_task_id":"cos"}}'

test_route_resolve_projects_local_ownership_without_a_routes_lookup() {
  local dir
  dir=$(new_dir route-local)
  routes_file "$dir/chief-routes.json" "{\"schema_version\":1,\"routes\":[$ROUTE_ROW_MK2]}"
  run 0 "the owner is this machine" python3 "$TOOL" route-resolve --routes "$dir/chief-routes.json" \
    --owner-machine-key mk-1 --owner-epoch 4 --local-machine-key mk-1
  assert_equals local "$(json owner_route_status)" "the owner route is local"
  assert_equals local-owner "$(json dispatch_authority)" "dispatch authority is local-owner"
  assert_contains "$OUT" "chief lock" "local dispatch still names the lock and authority record it does not hold"
  pass "an owner machine key equal to the local machine key resolves local, with no route lookup"
}

test_route_resolve_returns_exactly_one_row_and_the_ordered_endpoints() {
  local dir
  dir=$(new_dir route-ok)
  routes_file "$dir/chief-routes.json" "{\"schema_version\":1,\"routes\":[$ROUTE_ROW_MK2]}"
  run 0 "positive control: one complete row" python3 "$TOOL" route-resolve --routes "$dir/chief-routes.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_equals resolved "$(json owner_route_status)" "the route resolves"
  assert_equals forward-to-owner "$(json dispatch_authority)" "the dispatch is forwarded to the owning chief"
  assert_equals False "$(json direct_vp_delivery)" "a resolved remote route never permits direct VP delivery"
  assert_equals 3 "$(json route_revision)" "the route revision is carried"
  assert_equals native "$(json endpoints.0.transport)" "native is attempted first"
  assert_equals cos-mk-2 "$(json endpoints.0.native_agent_name)" "the owning chief's native agent name is resolved"
  assert_equals agent-mail "$(json endpoints.1.transport)" "agent-mail is second"
  assert_equals fleet "$(json endpoints.1.project_key)" "the Agent Mail project key is resolved"
  assert_equals cos-mk-2 "$(json endpoints.1.agent_name)" "the Agent Mail agent name is resolved"
  assert_equals fm-send "$(json endpoints.2.transport)" "fm-send is last"
  assert_equals mk-2 "$(json endpoints.2.ssh_host)" "the fm-send ssh host is resolved"
  assert_equals cos "$(json endpoints.2.firstmate_task_id)" "the fm-send task id is resolved"
  assert_contains "$OUT" "never address the VP directly" "the resolved route says the VP is never addressed directly"
  pass "one complete row yields the ordered native, agent-mail and fm-send endpoints of the owning chief and no direct VP target"
}

test_route_resolve_blocks_forwarding_on_a_missing_duplicate_or_incomplete_row() {
  local dir
  dir=$(new_dir route-bad)
  routes_file "$dir/chief-routes.json" "{\"schema_version\":1,\"routes\":[$ROUTE_ROW_MK2]}"
  run 2 "no row for the owner" python3 "$TOOL" route-resolve --routes "$dir/chief-routes.json" \
    --owner-machine-key mk-9 --owner-epoch 4 --local-machine-key mk-1
  assert_equals unresolved "$(json owner_route_status)" "a missing row is unresolved"
  assert_equals forwarding-blocked "$(json dispatch_authority)" "a missing row blocks forwarding"
  assert_equals machine_key "$(json invalid_field)" "the invalid field is named"
  assert_equals False "$(json direct_vp_delivery)" "an unresolved route never falls back to the VP"

  routes_file "$dir/dup.json" "{\"schema_version\":1,\"routes\":[$ROUTE_ROW_MK2,$ROUTE_ROW_MK2]}"
  run 2 "two rows for one owner" python3 "$TOOL" route-resolve --routes "$dir/dup.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_equals forwarding-blocked "$(json dispatch_authority)" "a duplicate row blocks forwarding"
  assert_contains "$OUT" "duplicate row resolves nothing" "the duplicate is named"

  routes_file "$dir/incomplete.json" '{"schema_version":1,"routes":[{"machine_key":"mk-2","route_revision":3,"chief_instance_key":"firstmate-chief/mk-2","native_agent_name":"cos-mk-2","agent_mail":{"project_key":"fleet"},"fm_send":{"ssh_host":"mk-2","firstmate_task_id":"cos"}}]}'
  run 2 "an incomplete row" python3 "$TOOL" route-resolve --routes "$dir/incomplete.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_equals agent_mail.agent_name "$(json invalid_field)" "the exact missing field is named"

  routes_file "$dir/no-native.json" '{"schema_version":1,"routes":[{"machine_key":"mk-2","route_revision":3,"chief_instance_key":"firstmate-chief/mk-2","agent_mail":{"project_key":"fleet","agent_name":"cos-mk-2"},"fm_send":{"ssh_host":"mk-2","firstmate_task_id":"cos"}}]}'
  run 2 "no native agent name" python3 "$TOOL" route-resolve --routes "$dir/no-native.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_equals native_agent_name "$(json invalid_field)" "a missing native agent name is named"

  routes_file "$dir/no-revision.json" '{"schema_version":1,"routes":[{"machine_key":"mk-2","chief_instance_key":"firstmate-chief/mk-2","native_agent_name":"cos-mk-2","agent_mail":{"project_key":"fleet","agent_name":"cos-mk-2"},"fm_send":{"ssh_host":"mk-2","firstmate_task_id":"cos"}}]}'
  run 2 "no route revision" python3 "$TOOL" route-resolve --routes "$dir/no-revision.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_equals route_revision "$(json invalid_field)" "a missing route revision is named"

  printf 'not a routes document\n' > "$dir/garbage.txt"
  run 2 "a routes file of the wrong shape" python3 "$TOOL" route-resolve --routes "$dir/garbage.txt" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_contains "$OUT" "refused" "a non-routes file is refused"
  pass "a missing, duplicate, or incomplete route row blocks forwarding, names the invalid field, and never yields a direct VP target"
}

# --- the shipped examples, and the vocabulary this tool no longer carries --------------------------

test_the_shipped_documentation_examples_are_real() {
  local dir checked machine
  dir=$(new_dir examples)
  # Nothing can sign with the example self.json here - its private key exists on no
  # machine - so it is checked two ways. First recomputed here: it is canonical, it
  # carries exactly the six fields the tool writes, its key id is the SHA-256 of the
  # public key beside it, and its chief instance key derives from its machine key.
  checked=$(python3 - "$ROOT/docs/examples/vp-owner-self.json" <<'PY'
import base64, hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
doc = json.loads(raw)
pub = base64.urlsafe_b64decode(doc["public_key"] + "=" * (-len(doc["public_key"]) % 4))
canonical = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
print("canonical" if raw == canonical else "not-canonical",
      "fields-ok" if sorted(doc) == ["chief_instance_key", "key_id", "machine_key", "provisioned_at",
                                     "public_key", "schema_version"] else "fields-wrong",
      "key-id-ok" if doc["key_id"] == "ed25519-sha256:" + hashlib.sha256(pub).hexdigest() else "key-id-wrong",
      "chief-ok" if doc["chief_instance_key"] == "firstmate-chief/" + doc["machine_key"] else "chief-wrong")
PY
)
  assert_equals "canonical fields-ok key-id-ok chief-ok" "$checked" "the example self.json is canonical, complete, and self-consistent"
  # Second, read by the tool: sign-owner --state-dir accepts the document and resolves
  # its key id to the key path it names, which is the only part that is absent here.
  mkdir -p "$dir/state/keys"
  chmod 700 "$dir/state" "$dir/state/keys"
  cp "$ROOT/docs/examples/vp-owner-self.json" "$dir/state/self.json"
  machine=$(file_json "$dir/state/self.json" machine_key)
  run 2 "the tool reads the example as a signing identity" python3 "$TOOL" sign-owner \
    --state-dir "$dir/state" --vp-id vp/ai-harness/primary --owner-machine-key "$machine" \
    --owner-epoch 1 --chief-instance-key "firstmate-chief/$machine" --ownership-state active
  assert_contains "$OUT" "$(file_json "$dir/state/self.json" key_id).key" \
    "the refusal names the key path the example's own key id resolves to, so the document itself was accepted"
  # The routes example resolves a remote owner, and the two examples name the same fleet.
  run 0 "the shipped routes example resolves" python3 "$TOOL" route-resolve \
    --routes "$ROOT/docs/examples/chief-routes.json" \
    --owner-machine-key e2a94c17-8b06-4d3f-a571-0c9e4b18d6f2 --owner-epoch 4 \
    --local-machine-key "$machine"
  assert_equals resolved "$(json owner_route_status)" "the shipped routes example resolves a remote owner"
  assert_equals cos-hetzner "$(json endpoints.0.native_agent_name)" "the example's native agent name is resolved"
  run 0 "and the example self machine is local in that same routes file" python3 "$TOOL" route-resolve \
    --routes "$ROOT/docs/examples/chief-routes.json" \
    --owner-machine-key "$machine" --owner-epoch 4 --local-machine-key "$machine"
  assert_equals local "$(json owner_route_status)" "the two shipped examples describe the same machine"
  pass "the shipped self and routes examples are accepted by the tool and describe the same fleet, not illustrative pseudo-JSON"
}

test_the_tool_carries_no_expiry_revocation_or_registry_vocabulary() {
  local dir pattern hits
  dir=$(new_dir vocabulary)
  pattern='non-dispatching|expires_at|not_after|not_before|revoked|registry_revision|trust_registry_revision|root-pub'
  hits=$(grep -cE "$pattern" "$TOOL" || true)
  assert_equals 0 "$hits" "the tool carries no expiry, revocation, registry or root-key vocabulary"
  # Canary: the same grep over a file that does carry that vocabulary must fire, so a
  # typo in the pattern cannot make this test pass by matching nothing anywhere.
  printf 'this line says not_after and revoked\n' > "$dir/canary.txt"
  hits=$(grep -cE "$pattern" "$dir/canary.txt" || true)
  assert_equals 1 "$hits" "the canary proves the pattern can still fire"
  pass "the retired expiry, revocation, registry and root-key vocabulary is absent from the tool, under a pattern proved able to fire"
}

test_keygen_creates_a_private_key_whose_id_is_the_hash_of_its_own_public_key
test_keygen_refuses_a_privileged_or_unowned_directory_without_writing
test_self_provision_creates_a_signer_identity_unattended_and_never_prints_the_key
test_a_second_self_provision_run_changes_nothing
test_self_provision_heals_a_deleted_or_garbage_self_record_by_adopting_the_existing_key
test_self_provision_heals_a_self_record_naming_a_key_that_is_not_there
test_self_provision_heals_a_hand_edited_machine_key_and_public_key
test_self_provision_tightens_a_shared_state_directory_and_drops_legacy_fields
test_a_validly_signed_owner_record_verifies_from_its_own_public_key
test_a_flipped_signature_or_payload_byte_fails_verification
test_a_non_canonical_serialization_is_refused_even_with_a_valid_signature
test_a_record_cannot_name_one_key_id_while_carrying_another_key
test_a_chief_instance_key_must_derive_from_its_own_owner_machine_key
test_an_unexpected_owner_machine_key_warns_and_still_verifies
test_a_prepared_handoff_record_round_trips_with_its_destination_and_nonce
test_route_resolve_projects_local_ownership_without_a_routes_lookup
test_route_resolve_returns_exactly_one_row_and_the_ordered_endpoints
test_route_resolve_blocks_forwarding_on_a_missing_duplicate_or_incomplete_row
test_the_shipped_documentation_examples_are_real
test_the_tool_carries_no_expiry_revocation_or_registry_vocabulary
