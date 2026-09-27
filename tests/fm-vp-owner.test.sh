#!/usr/bin/env bash
# Behavior tests for the VP-owner authority layer (bin/fm-vp-owner.py): signer
# identity, the root-signed trust registry, signed owner records, and owner-route
# resolution.
#
# What these guard: nothing about VP ownership is self-asserted. A key id is the
# SHA-256 of its own public key, so a registry cannot bind a key id to someone
# else's key. A trust registry is trusted only when a detached signature by an
# explicitly named root key verifies its exact canonical bytes, it has not
# expired, and its revision is newer than the installed one; installation is
# atomic and a refused install leaves the installed file byte-identical. An owner
# record verifies only as byte-for-byte canonical JSON, under Ed25519, against a
# current registry binding whose machine and chief identity match the payload and
# whose signing-time window covers signed_at, and only while the record's
# provenance revision is no newer than the installed registry. Every rejection
# names the failed trust check and exits 4; bad input and an unresolved route exit
# 2; a rolled-back install exits 3. An owner route resolves to exactly one row or
# to forwarding-blocked, never to a direct VP target.
#
# Positive controls run first in every group, so a refuse-everything
# implementation cannot pass: a valid record verifies, a valid registry installs,
# a good route resolves, and the signature and key id are recomputed here
# independently of the tool. Every command runs as a subprocess against real
# files and a real openssl in a fresh private temp home. No privileged path is
# written: the /etc and /var guards are proved with path strings only.
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
RC=0
run() {
  local expected=$1 label=$2
  shift 2
  set +e
  OUT=$("$@" 2>&1)
  RC=$?
  expect_code "$expected" "$RC" "$label"
}
set +e

# json <path-expr> reads one field from $OUT: json signers.0.status
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

new_dir() {  # <name> -> a fresh private directory
  local dir="$TMP_ROOT/$1"
  mkdir -p "$dir"
  chmod 700 "$dir"
  printf '%s\n' "$dir"
}

# --- one fleet root and two machine signers, generated once with real openssl ----------------------

KEYS=$(new_dir keys)
ROOT_KEY="$KEYS/root.pem"
ROOT_PUB="$KEYS/root.pub"
openssl genpkey -algorithm ed25519 -out "$ROOT_KEY" 2>/dev/null || fail "could not generate the fleet root key"
openssl pkey -in "$ROOT_KEY" -pubout -out "$ROOT_PUB" 2>/dev/null || fail "could not export the fleet root public key"

MK1_DIR=$(new_dir keys-mk-1)
MK2_DIR=$(new_dir keys-mk-2)
run 0 "keygen mk-1" python3 "$TOOL" keygen --key-dir "$MK1_DIR/vp-owner"
KEY1=$(json key_id); PUB1=$(json public_key); PRIV1=$(json private_key_path)
run 0 "keygen mk-2" python3 "$TOOL" keygen --key-dir "$MK2_DIR/vp-owner"
KEY2=$(json key_id); PUB2=$(json public_key); PRIV2=$(json private_key_path)

# signer <key_id> <public_key> <machine_key> <chief_instance_key> <status> <not_before> <not_after|-> <revoked_at|->
signer() {
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
}

# registry <out> <revision> <issued_at> <expires_at> <signer-spec...>: write canonical JSON.
registry() {
  local out=$1
  shift
  python3 - "$@" > "$out" <<'PY'
import json, sys
rev, issued, expires = int(sys.argv[1]), sys.argv[2], sys.argv[3]
signers = []
for spec in sys.argv[4:]:
    key_id, pub, machine, chief, status, nb, na, rev_at = spec.split("|")
    signers.append({
        "key_id": key_id, "public_key": pub, "machine_key": machine,
        "chief_instance_key": chief, "status": status, "not_before": nb,
        "not_after": None if na == "-" else na,
        "revoked_at": None if rev_at == "-" else rev_at,
        "supersedes": None,
    })
doc = {"schema_version": 1, "registry_revision": rev, "issued_at": issued,
       "expires_at": expires, "signers": signers}
sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
PY
}

# good_registry <out> <revision>: revision N binding mk-1 active with a wide window.
good_registry() {
  registry "$1" "$2" 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)"
  run 0 "root-sign revision $2" python3 "$TOOL" registry-sign --registry "$1" --root-key "$ROOT_KEY"
}

# sign_record <out> <provenance-revision> <epoch> <signed_at> [extra sign-owner args...]
sign_record() {
  local out=$1 revision=$2 epoch=$3 signed_at=$4
  shift 4
  python3 "$TOOL" sign-owner --private-key "$PRIV1" --vp-id vp/ai-harness/primary \
    --owner-machine-key mk-1 --owner-epoch "$epoch" --chief-instance-key firstmate-chief/mk-1 \
    --ownership-state active --trust-registry-revision "$revision" --signed-at "$signed_at" \
    --out "$out" "$@"
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

# --- keygen: a content-addressed identity, never a privileged write -------------------------------

test_keygen_creates_a_private_key_whose_id_is_the_hash_of_its_own_public_key() {
  local dir recomputed
  dir=$(new_dir keygen)
  run 0 "keygen" python3 "$TOOL" keygen --key-dir "$dir/vp-owner"
  assert_equals 700 "$(stat -c %a "$dir/vp-owner" 2>/dev/null || stat -f %Lp "$dir/vp-owner")" "key dir is 0700"
  assert_equals 600 "$(stat -c %a "$(json private_key_path)" 2>/dev/null || stat -f %Lp "$(json private_key_path)")" "private key is 0600"
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

# --- enrollment: proof of possession a human verifies out of band ----------------------------------

test_enroll_request_is_canonical_and_its_proof_of_possession_verifies() {
  local dir verified
  dir=$(new_dir enroll)
  run 0 "enroll-request" python3 "$TOOL" --now 2026-09-26T10:00:00Z enroll-request \
    --private-key "$PRIV1" --machine-key mk-1 --chief-instance-key firstmate-chief/mk-1 \
    --nonce enroll-nonce-1 --out "$dir/enroll.json"
  assert_equals "$KEY1" "$(json key_id)" "the request names the key id of the key that signed it"
  assert_contains "$OUT" "non-dispatching until a human" "the request says the machine stays non-dispatching"
  assert_equals enroll-nonce-1 "$(file_json "$dir/enroll.json" nonce)" "the one-use nonce is carried"
  assert_equals "$PUB1" "$(file_json "$dir/enroll.json" public_key)" "the public key is carried"
  # Positive control: verify the proof of possession here, with openssl, over the
  # canonical request minus its signature field.
  verified=$(python3 - "$dir/enroll.json" "$dir" <<'PY'
import base64, json, subprocess, sys
doc = json.load(open(sys.argv[1]))
work = sys.argv[2]
sig = doc.pop("proof_of_possession")
msg = b"ai-harness/vp-owner-enroll/v1\0" + json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
raw = base64.urlsafe_b64decode(doc["public_key"] + "=" * (-len(doc["public_key"]) % 4))
open(work + "/p.der", "wb").write(bytes.fromhex("302a300506032b6570032100") + raw)
open(work + "/m", "wb").write(msg)
open(work + "/s", "wb").write(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
rc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", work + "/p.der", "-keyform", "DER",
                     "-rawin", "-in", work + "/m", "-sigfile", work + "/s"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
print("verified" if rc == 0 else "failed")
PY
)
  assert_equals verified "$verified" "the proof of possession verifies under the enrolled public key"
  # The same check over a request whose machine key was edited must fail.
  mutate "$dir/enroll.json" "$dir/edited.json" 'doc["machine_key"] = "mk-9"'
  verified=$(python3 - "$dir/edited.json" "$dir" <<'PY'
import base64, json, subprocess, sys
doc = json.load(open(sys.argv[1]))
work = sys.argv[2]
sig = doc.pop("proof_of_possession")
msg = b"ai-harness/vp-owner-enroll/v1\0" + json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
open(work + "/m2", "wb").write(msg)
open(work + "/s2", "wb").write(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
rc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", work + "/p.der", "-keyform", "DER",
                     "-rawin", "-in", work + "/m2", "-sigfile", work + "/s2"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
print("verified" if rc == 0 else "failed")
PY
)
  assert_equals failed "$verified" "an edited enrollment request no longer proves possession"
  pass "an enrollment request is canonical, carries its nonce and public key, and proves possession of the new key"
}

# --- trust registry ------------------------------------------------------------------------------

test_a_root_signed_registry_verifies_and_any_local_edit_does_not() {
  local dir
  dir=$(new_dir registry)
  good_registry "$dir/vp-owner-trust.json" 3
  run 0 "positive control: verify" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "a root-signed registry verifies"
  assert_equals 3 "$(json registry_revision)" "the revision is reported"
  assert_equals active "$(json signers.0.status)" "the binding status is reported"

  mutate "$dir/vp-owner-trust.json" "$dir/edited.json" 'doc["signers"][0]["machine_key"] = "mk-9"'
  cp "$dir/vp-owner-trust.json.sig" "$dir/edited.json.sig"
  run 4 "locally edited registry" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/edited.json" --root-pub "$ROOT_PUB"
  assert_equals registry-signature "$(json failed_check)" "an edited registry fails the root signature check"

  rm -f "$dir/edited.json.sig"
  run 2 "unsigned registry" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/edited.json" --root-pub "$ROOT_PUB"
  assert_contains "$OUT" "not a readable file" "a missing detached signature is refused"

  mutate "$dir/vp-owner-trust.json" "$dir/pretty.json" \
    'raw = (__import__("json").dumps(doc, indent=2) + "\n").encode()'
  cp "$dir/vp-owner-trust.json.sig" "$dir/pretty.json.sig"
  run 4 "non-canonical whitespace" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/pretty.json" --root-pub "$ROOT_PUB"
  assert_equals registry-canonical-serialization "$(json failed_check)" "re-indented JSON is not canonical"

  registry "$dir/expired.json" 3 2026-01-01T00:00:00Z 2026-02-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-01-01T00:00:00Z - -)"
  run 0 "sign the expired registry" python3 "$TOOL" registry-sign --registry "$dir/expired.json" --root-key "$ROOT_KEY"
  run 4 "expired registry" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/expired.json" --root-pub "$ROOT_PUB"
  assert_equals registry-expired "$(json failed_check)" "an expired registry is refused even though it is root-signed"

  registry "$dir/dup.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)" \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the duplicate registry" python3 "$TOOL" registry-sign --registry "$dir/dup.json" --root-key "$ROOT_KEY"
  run 4 "duplicate binding" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/dup.json" --root-pub "$ROOT_PUB"
  assert_equals registry-duplicate-binding "$(json failed_check)" "a duplicate binding is invalid"

  registry "$dir/swapped.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB2" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the swapped registry" python3 "$TOOL" registry-sign --registry "$dir/swapped.json" --root-key "$ROOT_KEY"
  run 4 "key id bound to another key" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/swapped.json" --root-pub "$ROOT_PUB"
  assert_equals registry-key-id-mismatch "$(json failed_check)" "a key id must be the hash of the key it is bound to"

  # Another root, given as PEM and again as one line of unpadded base64url, so both
  # accepted root-key formats are proved to be read rather than rejected as garbage.
  openssl pkey -in "$PRIV1" -pubout -out "$dir/other-root.pem" 2>/dev/null
  printf '%s\n' "$PUB1" > "$dir/other-root.b64u"
  run 4 "another root (PEM)" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/vp-owner-trust.json" --root-pub "$dir/other-root.pem"
  assert_equals registry-signature "$(json failed_check)" "a registry signed by another root does not verify"
  run 4 "another root (base64url)" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/vp-owner-trust.json" --root-pub "$dir/other-root.b64u"
  assert_equals registry-signature "$(json failed_check)" "a base64url root key is read, and the wrong root still fails"
  run 2 "a root public key that is not a key" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/vp-owner-trust.json" --root-pub "$dir/vp-owner-trust.json"
  assert_contains "$OUT" "not a PEM, DER, or base64url" "a file that is not a public key is refused"
  pass "a registry is trusted only when the named root signs its exact canonical bytes, it is unexpired, and every binding is unique and self-consistent"
}

test_registry_install_is_atomic_and_a_rollback_leaves_the_installed_file_untouched() {
  local dir into installed_sha
  dir=$(new_dir install)
  into="$dir/installed"
  good_registry "$dir/rev3.json" 3
  good_registry "$dir/rev4.json" 4
  run 0 "positive control: first install" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev3.json" --root-pub "$ROOT_PUB" --into "$into"
  assert_equals True "$(json installed)" "the first install succeeds"
  assert_equals absent "$(json previous_state)" "the first install reports no previous registry"
  assert_present "$into/vp-owner-trust.json" "the registry is installed under its canonical name"
  assert_present "$into/vp-owner-trust.json.sig" "the detached signature is installed beside it"
  assert_equals 3 "$(file_json "$into/vp-owner-trust.json" registry_revision)" "revision 3 is installed"

  run 0 "ordinary newer revision installs" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev4.json" --root-pub "$ROOT_PUB" --into "$into"
  assert_equals 3 "$(json previous_registry_revision)" "the install names the revision it replaced"
  assert_equals verified "$(json previous_state)" "the replaced registry had itself verified"
  assert_equals 4 "$(file_json "$into/vp-owner-trust.json" registry_revision)" "revision 4 is installed"
  installed_sha=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$into/vp-owner-trust.json")

  run 3 "rollback to revision 3" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev3.json" --root-pub "$ROOT_PUB" --into "$into"
  assert_equals registry-rolled-back "$(json failed_check)" "the rollback is named"
  assert_equals 4 "$(file_json "$into/vp-owner-trust.json" registry_revision)" "a refused rollback leaves revision 4 installed"
  assert_equals "$installed_sha" "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$into/vp-owner-trust.json")" "the installed bytes are unchanged"

  run 3 "re-installing the same revision" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev4.json" --root-pub "$ROOT_PUB" --into "$into"
  assert_equals registry-rolled-back "$(json failed_check)" "the revision must strictly increase"

  mutate "$dir/rev4.json" "$dir/rev5-edited.json" 'doc["registry_revision"] = 5'
  cp "$dir/rev4.json.sig" "$dir/rev5-edited.json.sig"
  run 4 "edited higher revision" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev5-edited.json" --root-pub "$ROOT_PUB" --into "$into"
  assert_equals registry-signature "$(json failed_check)" "bumping the revision without the root signature is refused"
  assert_equals "$installed_sha" "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$into/vp-owner-trust.json")" "the unsigned candidate changed nothing"

  run 2 "install under /etc" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-install \
    --registry "$dir/rev4.json" --root-pub "$ROOT_PUB" --into /etc/ai-harness/trust
  assert_contains "$OUT" "never writes there" "an install into /etc is refused"
  run 2 "registry-install without a named root" python3 "$TOOL" registry-install \
    --registry "$dir/rev4.json" --into "$into"
  assert_contains "$OUT" "--root-pub" "registry-install cannot run without an explicit root public key"
  # Where --registry is optional, naming it without a root is refused rather than
  # silently trusted: there is no default root path and /etc is never read.
  run 2 "a registry with no root at all" python3 "$TOOL" route-resolve --routes "$dir/rev4.json" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1 --registry "$dir/rev4.json"
  assert_contains "$OUT" "no default root path" "the root public key is always explicit"
  pass "installation is atomic and refuses a rolled-back, unsigned or privileged target while leaving the installed registry byte-identical"
}

# --- owner records -------------------------------------------------------------------------------

test_a_validly_signed_owner_record_verifies_against_the_installed_registry() {
  local dir recomputed
  dir=$(new_dir verify)
  good_registry "$dir/vp-owner-trust.json" 3
  run 0 "sign" sign_record "$dir/owner.json" 3 4 2026-09-26T10:00:00Z
  assert_equals "$KEY1" "$(json key_id)" "the record is signed by this machine's key"
  run 0 "positive control: verify" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "a validly signed record verifies"
  assert_equals active "$(json ownership_state)" "the ownership state is projected"
  assert_equals 4 "$(json owner_epoch)" "the owner epoch is projected"
  assert_equals mk-1 "$(json owner_machine_key)" "the owner machine key is projected"
  assert_contains "$OUT" "is not a current record" "verification does not claim to be a CAS read"
  # Positive control on the envelope: recompute the signed bytes and verify with openssl.
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
pub = json.load(open(work + "/vp-owner-trust.json"))["signers"][0]["public_key"]
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
  pass "a record signed by a bound, active, in-window signer verifies, and its envelope matches the specified signed bytes exactly"
}

test_a_flipped_signature_or_payload_byte_fails_verification() {
  local dir
  dir=$(new_dir tamper)
  good_registry "$dir/vp-owner-trust.json" 3
  run 0 "sign" sign_record "$dir/owner.json" 3 4 2026-09-26T10:00:00Z
  mutate "$dir/owner.json" "$dir/flipped-sig.json" \
    'sig = doc["signature"]; doc["signature"] = ("B" if sig[0] != "B" else "C") + sig[1:]'
  run 4 "one flipped signature byte" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/flipped-sig.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals signature "$(json failed_check)" "a flipped signature byte fails the signature check"
  mutate "$dir/owner.json" "$dir/flipped-payload.json" 'doc["payload"]["owner_epoch"] = 5'
  run 4 "one flipped payload byte" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/flipped-payload.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals signature "$(json failed_check)" "an edited payload fails the signature check"
  mutate "$dir/owner.json" "$dir/other-alg.json" 'doc["protected"]["alg"] = "RSA"'
  run 4 "another algorithm" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/other-alg.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals alg "$(json failed_check)" "another algorithm is rejected before any signature work"
  mutate "$dir/owner.json" "$dir/missing.json" 'del doc["payload"]["chief_instance_key"]'
  run 4 "missing field" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/missing.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals structure "$(json failed_check)" "a missing payload field is rejected"
  assert_contains "$OUT" "chief_instance_key" "the missing field is named"
  mutate "$dir/owner.json" "$dir/padded.json" 'doc["signature"] = doc["signature"] + "=="'
  run 4 "padded base64" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/padded.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals base64 "$(json failed_check)" "a padded signature is not canonical unpadded base64url"
  mutate "$dir/owner.json" "$dir/bad-ts.json" 'doc["payload"]["signed_at"] = "2026-09-26 10:00:00"'
  run 4 "non-canonical timestamp" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/bad-ts.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals timestamp "$(json failed_check)" "a non-RFC-3339 signed_at is rejected"
  pass "a flipped signature or payload byte, another algorithm, a missing field, padded base64, and a non-canonical timestamp each fail a named check"
}

test_a_non_canonical_serialization_is_refused_even_with_a_valid_signature() {
  local dir
  dir=$(new_dir canonical)
  good_registry "$dir/vp-owner-trust.json" 3
  run 0 "sign" sign_record "$dir/owner.json" 3 4 2026-09-26T10:00:00Z
  mutate "$dir/owner.json" "$dir/reordered.json" \
    'raw = (__import__("json").dumps({k: doc[k] for k in ("signature", "schema_version", "protected", "payload")}, sort_keys=False, separators=(",", ":")) + "\n").encode()'
  run 4 "reordered keys" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/reordered.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals canonical-serialization "$(json failed_check)" "a reordered blob is not the canonical serialization"
  mutate "$dir/owner.json" "$dir/spaced.json" \
    'raw = (__import__("json").dumps(doc, sort_keys=True, separators=(", ", ": ")) + "\n").encode()'
  run 4 "inserted whitespace" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/spaced.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals canonical-serialization "$(json failed_check)" "inserted whitespace is not canonical"
  python3 -c 'import sys; raw = open(sys.argv[1], "rb").read(); open(sys.argv[2], "wb").write(raw.rstrip(b"\n"))' \
    "$dir/owner.json" "$dir/no-lf.json"
  run 4 "missing trailing LF" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/no-lf.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals canonical-serialization "$(json failed_check)" "the one trailing LF is part of the stored blob"
  run 0 "positive control: the untouched blob still verifies" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  pass "a blob that is not byte-for-byte the canonical serialization is refused before its signature is even consulted"
}

test_the_registry_binding_lifecycle_decides_every_record() {
  local dir
  dir=$(new_dir lifecycle)
  good_registry "$dir/vp-owner-trust.json" 3
  run 0 "sign" sign_record "$dir/owner.json" 3 4 2026-09-26T10:00:00Z
  run 0 "positive control: verify under the active binding" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"

  # Revoked after signing: the record still fails closed, regardless of signed time.
  registry "$dir/revoked.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 revoked 2026-09-01T00:00:00Z - 2026-09-26T10:30:00Z)"
  run 0 "sign the revoking revision" python3 "$TOOL" registry-sign --registry "$dir/revoked.json" --root-key "$ROOT_KEY"
  run 4 "revoked signer" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/revoked.json" --root-pub "$ROOT_PUB"
  assert_equals revoked-binding "$(json failed_check)" "a revoked binding rejects a record it signed before revocation"

  # A binding for another machine: the signature is good but the identity is not.
  registry "$dir/wrong-machine.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-9 firstmate-chief/mk-9 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the wrong-machine revision" python3 "$TOOL" registry-sign --registry "$dir/wrong-machine.json" --root-key "$ROOT_KEY"
  run 4 "wrong-machine binding" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/wrong-machine.json" --root-pub "$ROOT_PUB"
  assert_equals machine-binding "$(json failed_check)" "the binding's machine_key must match the record"
  assert_contains "$OUT" "mk-9" "the disagreeing machine key is named"

  # A binding for the right machine but another chief instance.
  registry "$dir/wrong-chief.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/other active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the wrong-chief revision" python3 "$TOOL" registry-sign --registry "$dir/wrong-chief.json" --root-key "$ROOT_KEY"
  run 4 "wrong chief instance" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/wrong-chief.json" --root-pub "$ROOT_PUB"
  assert_equals chief-binding "$(json failed_check)" "the binding's chief_instance_key must match the record"

  # Signed outside the binding's signing-time window, both directions.
  registry "$dir/retired.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 retired 2026-09-01T00:00:00Z 2026-09-26T09:00:00Z -)"
  run 0 "sign the retiring revision" python3 "$TOOL" registry-sign --registry "$dir/retired.json" --root-key "$ROOT_KEY"
  run 4 "signed after not_after" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/retired.json" --root-pub "$ROOT_PUB"
  assert_equals signing-window "$(json failed_check)" "a record signed after not_after is rejected"
  registry "$dir/future.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-27T00:00:00Z - -)"
  run 0 "sign the not-yet-valid revision" python3 "$TOOL" registry-sign --registry "$dir/future.json" --root-key "$ROOT_KEY"
  run 4 "signed before not_before" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/future.json" --root-pub "$ROOT_PUB"
  assert_equals signing-window "$(json failed_check)" "a record signed before not_before is rejected"

  # A registry that does not know this key at all.
  registry "$dir/other-signer.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY2" "$PUB2" mk-2 firstmate-chief/mk-2 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the other-signer revision" python3 "$TOOL" registry-sign --registry "$dir/other-signer.json" --root-key "$ROOT_KEY"
  run 4 "unknown key id" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/other-signer.json" --root-pub "$ROOT_PUB"
  assert_equals unknown-key-id "$(json failed_check)" "an unbound key id is rejected"

  # An installed registry that fails its own verification rejects every record.
  # A structurally valid but locally edited installed registry: the record itself is
  # untouched and correctly signed, and it is still rejected.
  mutate "$dir/vp-owner-trust.json" "$dir/tampered.json" 'doc["signers"][0]["machine_key"] = "mk-9"'
  cp "$dir/vp-owner-trust.json.sig" "$dir/tampered.json.sig"
  run 4 "installed registry that does not verify" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/tampered.json" --root-pub "$ROOT_PUB"
  assert_equals registry-signature "$(json failed_check)" "a record is never verified against an unverifiable registry"
  # A registry whose own structure contradicts itself is refused before any crypto.
  mutate "$dir/vp-owner-trust.json" "$dir/malformed.json" 'doc["signers"][0]["status"] = "revoked"'
  cp "$dir/vp-owner-trust.json.sig" "$dir/malformed.json.sig"
  run 4 "installed registry that contradicts itself" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/malformed.json" --root-pub "$ROOT_PUB"
  assert_equals registry-structure "$(json failed_check)" "a revoked binding with no revoked_at is malformed"
  pass "revocation, a wrong machine or chief binding, either edge of the signing window, an unknown key, and an unverifiable registry each reject with their own named check"
}

test_a_future_provenance_revision_is_refused_until_the_installed_registry_catches_up() {
  local dir
  dir=$(new_dir revision)
  good_registry "$dir/rev3.json" 3
  run 0 "sign with provenance revision 4" sign_record "$dir/owner4.json" 4 5 2026-09-26T10:00:00Z
  run 4 "stale reader" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner4.json" --registry "$dir/rev3.json" --root-pub "$ROOT_PUB"
  assert_equals future-registry-revision "$(json failed_check)" "a record from a future revision refuses dispatch"
  assert_equals 4 "$(json record_trust_registry_revision)" "the record revision is reported"
  assert_equals 3 "$(json installed_registry_revision)" "the installed revision is reported"
  good_registry "$dir/rev4.json" 4
  run 0 "after the registry catches up" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner4.json" --registry "$dir/rev4.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "verification resumes once the installed revision reaches the record's"
  pass "a stale reader refuses a future-revision record by name and verifies it only after the installed registry reaches that revision"
}

test_an_unrelated_enrollment_revision_still_verifies_an_existing_record_without_re_signing() {
  local dir before
  dir=$(new_dir unrelated)
  good_registry "$dir/rev3.json" 3
  run 0 "sign at revision 3" sign_record "$dir/owner.json" 3 4 2026-09-26T10:00:00Z
  before=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$dir/owner.json")
  # Revision 4 enrolls an unrelated machine and renews the expiry; mk-1 stays bound.
  registry "$dir/rev4.json" 4 2026-09-20T00:00:00Z 2028-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)" \
    "$(signer "$KEY2" "$PUB2" mk-2 firstmate-chief/mk-2 active 2026-09-20T00:00:00Z - -)"
  run 0 "sign revision 4" python3 "$TOOL" registry-sign --registry "$dir/rev4.json" --root-key "$ROOT_KEY"
  run 0 "the revision-3 record still verifies" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/owner.json" --registry "$dir/rev4.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "an unrelated enrollment or expiry renewal does not invalidate the record"
  assert_equals 3 "$(json record_trust_registry_revision)" "the record keeps its own provenance revision"
  assert_equals 4 "$(json installed_registry_revision)" "the installed revision moved on"
  assert_equals "$before" "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$dir/owner.json")" "the record was not re-signed"
  pass "an ordinary newer registry revision preserves an existing record whose signer remains bound and in window, with no re-signing"
}

test_sign_owner_refuses_a_key_the_installed_registry_does_not_authorize() {
  local dir
  dir=$(new_dir signing)
  good_registry "$dir/rev3.json" 3
  run 0 "positive control: an active signer may sign" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state active \
    --registry "$dir/rev3.json" --root-pub "$ROOT_PUB" --out "$dir/owner.json"
  assert_equals 3 "$(json trust_registry_revision)" "the provenance revision is the verified installed one"
  assert_contains "$OUT" "signing does not publish" "signing does not claim to have published the record"
  run 2 "an unenrolled key may not sign" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV2" --vp-id vp/ai-harness/primary --owner-machine-key mk-2 --owner-epoch 1 \
    --chief-instance-key firstmate-chief/mk-2 --ownership-state active \
    --registry "$dir/rev3.json" --root-pub "$ROOT_PUB" --out "$dir/nope.json"
  assert_contains "$OUT" "non-dispatching until a human" "an unenrolled machine stays non-dispatching"
  assert_absent "$dir/nope.json" "a refused signing wrote no record"
  registry "$dir/revoked.json" 4 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 revoked 2026-09-01T00:00:00Z - 2026-09-25T00:00:00Z)"
  run 0 "sign the revoking revision" python3 "$TOOL" registry-sign --registry "$dir/revoked.json" --root-key "$ROOT_KEY"
  run 2 "a revoked signer may not sign" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 5 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state active \
    --registry "$dir/revoked.json" --root-pub "$ROOT_PUB" --out "$dir/revoked-record.json"
  assert_contains "$OUT" "revoked" "the revoked status is named"
  assert_absent "$dir/revoked-record.json" "a revoked signer wrote no record"
  run 2 "no provenance revision at all" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state active --out "$dir/no-rev.json"
  assert_contains "$OUT" "trust_registry_revision" "the provenance revision is never invented"
  run 2 "a prepared handoff must name its handoff" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --trust-registry-revision 3 --out "$dir/bad-handoff.json"
  assert_contains "$OUT" "must name its handoff" "a prepared record without a handoff object is refused"
  pass "only a bound, active or retiring signer may sign, and a refused signing writes nothing"
}

test_a_prepared_handoff_record_round_trips_with_its_destination_and_nonce() {
  local dir
  dir=$(new_dir handoff)
  good_registry "$dir/rev3.json" 3
  cat > "$dir/handoff.json" <<'JSON'
{"handoff_id": "ho-1", "destination_machine_key": "mk-2", "next_owner_epoch": 5,
 "nonce": "nonce-abc", "prepared_at": "2026-09-26T10:00:00Z"}
JSON
  run 0 "sign the prepared handoff" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 4 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --predecessor-object-id 1111111111111111111111111111111111111111 \
    --handoff-file "$dir/handoff.json" --trust-registry-revision 3 --out "$dir/prepared.json"
  run 0 "verify the prepared handoff" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/prepared.json" --registry "$dir/rev3.json" --root-pub "$ROOT_PUB"
  assert_equals handoff-prepared "$(json ownership_state)" "the prepared state is projected"
  assert_equals mk-2 "$(json handoff.destination_machine_key)" "the destination machine is projected"
  assert_equals 5 "$(json handoff.next_owner_epoch)" "the next epoch is projected"
  assert_equals nonce-abc "$(json handoff.nonce)" "the single-use nonce is projected"
  mutate "$dir/prepared.json" "$dir/retargeted.json" 'doc["payload"]["handoff"]["destination_machine_key"] = "mk-9"'
  run 4 "a retargeted handoff" python3 "$TOOL" --now 2026-09-26T11:00:00Z verify-owner \
    --record "$dir/retargeted.json" --registry "$dir/rev3.json" --root-pub "$ROOT_PUB"
  assert_equals signature "$(json failed_check)" "changing the destination invalidates the signature"
  run 2 "a next epoch that does not advance" python3 "$TOOL" --now 2026-09-26T10:00:00Z sign-owner \
    --private-key "$PRIV1" --vp-id vp/ai-harness/primary --owner-machine-key mk-1 --owner-epoch 9 \
    --chief-instance-key firstmate-chief/mk-1 --ownership-state handoff-prepared \
    --handoff-file "$dir/handoff.json" --trust-registry-revision 3 --out "$dir/stale-epoch.json"
  assert_contains "$OUT" "must be greater than the current" "a prepared handoff must advance the epoch"
  pass "a prepared handoff carries its destination, next epoch and nonce inside the signed payload, so none of them can be changed"
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

  run 2 "a routes file of the wrong shape" python3 "$TOOL" route-resolve --routes "$ROOT_PUB" \
    --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1
  assert_contains "$OUT" "refused" "a non-routes file is refused"
  pass "a missing, duplicate, or incomplete route row blocks forwarding, names the invalid field, and never yields a direct VP target"
}

test_route_resolve_refuses_a_chief_instance_key_the_registry_contradicts() {
  local dir
  dir=$(new_dir route-registry)
  routes_file "$dir/chief-routes.json" "{\"schema_version\":1,\"routes\":[$ROUTE_ROW_MK2]}"
  registry "$dir/agree.json" 5 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY2" "$PUB2" mk-2 firstmate-chief/mk-2 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the agreeing registry" python3 "$TOOL" registry-sign --registry "$dir/agree.json" --root-key "$ROOT_KEY"
  run 0 "positive control: route and registry agree" python3 "$TOOL" --now 2026-09-26T10:00:00Z route-resolve \
    --routes "$dir/chief-routes.json" --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1 \
    --registry "$dir/agree.json" --root-pub "$ROOT_PUB"
  assert_equals resolved "$(json owner_route_status)" "an agreeing registry resolves the route"
  assert_equals 5 "$(json installed_registry_revision)" "the registry revision is reported"

  registry "$dir/disagree.json" 5 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY2" "$PUB2" mk-2 firstmate-chief/other-chief active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the disagreeing registry" python3 "$TOOL" registry-sign --registry "$dir/disagree.json" --root-key "$ROOT_KEY"
  run 2 "the registry contradicts the route" python3 "$TOOL" --now 2026-09-26T10:00:00Z route-resolve \
    --routes "$dir/chief-routes.json" --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1 \
    --registry "$dir/disagree.json" --root-pub "$ROOT_PUB"
  assert_equals chief_instance_key "$(json invalid_field)" "the contradicting field is named"
  assert_equals forwarding-blocked "$(json dispatch_authority)" "a contradiction blocks forwarding"
  assert_contains "$OUT" other-chief "the registry's binding is named"

  registry "$dir/unbound.json" 5 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)"
  run 0 "sign the unbound registry" python3 "$TOOL" registry-sign --registry "$dir/unbound.json" --root-key "$ROOT_KEY"
  run 2 "no binding for the owner machine" python3 "$TOOL" --now 2026-09-26T10:00:00Z route-resolve \
    --routes "$dir/chief-routes.json" --owner-machine-key mk-2 --owner-epoch 4 --local-machine-key mk-1 \
    --registry "$dir/unbound.json" --root-pub "$ROOT_PUB"
  assert_equals chief_instance_key "$(json invalid_field)" "an owner machine with no binding blocks forwarding"
  pass "a chief_instance_key the installed registry contradicts, or an owner machine it does not bind, blocks forwarding instead of guessing a target"
}

test_registry_sign_canonicalizes_a_human_readable_registry_before_signing() {
  local dir
  dir=$(new_dir canonicalize)
  registry "$dir/canonical.json" 3 2026-09-01T00:00:00Z 2027-09-01T00:00:00Z \
    "$(signer "$KEY1" "$PUB1" mk-1 firstmate-chief/mk-1 active 2026-09-01T00:00:00Z - -)"
  python3 -c '
import json, sys
json.dump(json.load(open(sys.argv[1])), open(sys.argv[2], "w"), indent=2)
open(sys.argv[2], "a").write("\n")' "$dir/canonical.json" "$dir/readable.json"
  run 4 "a readable registry is not signed as it stands" python3 "$TOOL" registry-sign \
    --registry "$dir/readable.json" --root-key "$ROOT_KEY"
  assert_equals registry-canonical-serialization "$(json failed_check)" "signing refuses a non-canonical registry"
  assert_absent "$dir/readable.json.sig" "the refused signing wrote no signature"
  run 0 "canonicalize then sign" python3 "$TOOL" registry-sign --registry "$dir/readable.json" \
    --root-key "$ROOT_KEY" --canonicalize
  assert_equals 3 "$(json registry_revision)" "the canonicalized registry is signed"
  run 0 "the canonicalized registry verifies" python3 "$TOOL" --now 2026-09-26T10:00:00Z registry-verify \
    --registry "$dir/readable.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "what was rewritten is exactly what was signed"
  pass "--canonicalize makes the reviewed registry and the signed bytes one object, and signing refuses a non-canonical registry otherwise"
}

test_the_shipped_documentation_examples_are_real() {
  local dir
  dir=$(new_dir examples)
  cp "$ROOT/docs/examples/vp-owner-trust.json" "$dir/vp-owner-trust.json"
  run 0 "sign the shipped registry example with a test root" python3 "$TOOL" registry-sign \
    --registry "$dir/vp-owner-trust.json" --root-key "$ROOT_KEY" --canonicalize
  run 0 "the shipped registry example verifies" python3 "$TOOL" --now 2026-10-01T00:00:00Z registry-verify \
    --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals True "$(json verified)" "every key id in the example is the hash of its own public key"
  assert_equals 4 "$(json registry_revision)" "the example's revision is read"
  run 0 "the shipped routes example resolves" python3 "$TOOL" route-resolve \
    --routes "$ROOT/docs/examples/chief-routes.json" \
    --owner-machine-key e2a94c17-8b06-4d3f-a571-0c9e4b18d6f2 --owner-epoch 4 \
    --local-machine-key b7c1f0d2-3e45-4a89-9f10-6d2b8c4e7a51
  assert_equals resolved "$(json owner_route_status)" "the shipped routes example resolves a remote owner"
  assert_equals cos-hetzner "$(json endpoints.0.native_agent_name)" "the example's native agent name is resolved"
  run 0 "the shipped examples agree with each other" python3 "$TOOL" --now 2026-10-01T00:00:00Z route-resolve \
    --routes "$ROOT/docs/examples/chief-routes.json" \
    --owner-machine-key e2a94c17-8b06-4d3f-a571-0c9e4b18d6f2 --owner-epoch 4 \
    --local-machine-key b7c1f0d2-3e45-4a89-9f10-6d2b8c4e7a51 \
    --registry "$dir/vp-owner-trust.json" --root-pub "$ROOT_PUB"
  assert_equals resolved "$(json owner_route_status)" "the example routes and registry bind the same chief instance keys"
  pass "the shipped registry and routes examples are internally consistent and accepted by the tool, not illustrative pseudo-JSON"
}

test_keygen_creates_a_private_key_whose_id_is_the_hash_of_its_own_public_key
test_keygen_refuses_a_privileged_or_unowned_directory_without_writing
test_enroll_request_is_canonical_and_its_proof_of_possession_verifies
test_a_root_signed_registry_verifies_and_any_local_edit_does_not
test_registry_install_is_atomic_and_a_rollback_leaves_the_installed_file_untouched
test_a_validly_signed_owner_record_verifies_against_the_installed_registry
test_a_flipped_signature_or_payload_byte_fails_verification
test_a_non_canonical_serialization_is_refused_even_with_a_valid_signature
test_the_registry_binding_lifecycle_decides_every_record
test_a_future_provenance_revision_is_refused_until_the_installed_registry_catches_up
test_an_unrelated_enrollment_revision_still_verifies_an_existing_record_without_re_signing
test_sign_owner_refuses_a_key_the_installed_registry_does_not_authorize
test_a_prepared_handoff_record_round_trips_with_its_destination_and_nonce
test_route_resolve_projects_local_ownership_without_a_routes_lookup
test_route_resolve_returns_exactly_one_row_and_the_ordered_endpoints
test_route_resolve_blocks_forwarding_on_a_missing_duplicate_or_incomplete_row
test_route_resolve_refuses_a_chief_instance_key_the_registry_contradicts
test_registry_sign_canonicalizes_a_human_readable_registry_before_signing
test_the_shipped_documentation_examples_are_real
