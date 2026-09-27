#!/usr/bin/env python3
# fm-vp-owner.py - the VP-owner authority layer: one Ed25519 signer identity per
# machine, self-verifying owner records, and owner-route resolution for the
# chief-of-staff dispatch path.
#
#   self-provision    create or heal this machine's signer identity in a
#                     caller-owned 0700 state directory, unattended and
#                     idempotent; this is what install.sh runs on every machine
#   keygen            generate one Ed25519 signer keypair in a caller-owned 0700
#                     directory (private key 0600) and print its key id and
#                     public key, never the private key
#   sign-owner        sign one owner record (the canonical Ed25519 envelope)
#   verify-owner      verify one owner record against the public key the record
#                     itself carries; every rejection names the failed check
#   route-resolve     resolve a VP owner machine key to exactly one chief-routes
#                     row and the ordered forwarding endpoints, or refuse
#
# Exit codes, in the style of bin/fm-dispatch-body.py:
#   0 ok; 2 refused (invalid input, path/ownership guard, unresolved route) -
#   nothing changed; 3 conflict (a key id that contradicts its key file);
#   4 verification failed - the JSON object names failed_check.
# Every command prints exactly one JSON object on stdout. A private key is never
# printed, copied, or included in any output. Warnings go to stderr and never
# change an exit code.
#
# ---------------------------------------------------------------------------
# What this tool does not do
# ---------------------------------------------------------------------------
# It performs no remote ref write, no network I/O, and no privileged write: the
# compare-and-swap writes to refs/ai-harness/vp-owners/<escaped-vp-id> are
# outside it, and it writes only into a directory the caller names and owns.
#
# Ownership is self-asserted. Any process that can write this ref namespace or a
# local file under a caller-owned state directory can assert a VP identity, and
# nothing here detects a forged or hand-edited record beyond the record's own
# internal consistency. There is no fleet root key, no signer registry, no
# expiry, no signing window and no revocation. That is a trade Sergei made
# (AIH-62xkr, ask entry A002): every machine in scope is his own, there is no
# adversary in the threat model, and an authority layer that can block a machine
# or need a human step is worth less here than one that always provisions
# itself. What the document checks still buy is that a record cannot
# accidentally name one key id while carrying another key's material, or claim a
# chief instance that does not follow from its own owner machine key.
#
# Cryptography is the openssl CLI (Ed25519: `openssl genpkey -algorithm ed25519`,
# `openssl pkey -pubout -outform DER`, `openssl pkeyutl -sign/-verify -rawin`);
# everything else is the Python standard library. No third-party module and no
# sqlite3 CLI are needed.
#
# Canonical JSON is RFC 8785 for the value shapes these records use: objects,
# arrays, strings, null, and non-negative integers. Keys are sorted, there is no
# insignificant whitespace, and non-ASCII is emitted as UTF-8 rather than escaped.
# RFC 8785 orders keys by UTF-16 code unit; Python sorts by code point, which is
# the same ordering for the ASCII key names this schema defines.
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

OWNER_SCHEMA_VERSION = 1
SELF_SCHEMA_VERSION = 1
ROUTES_SCHEMA_VERSION = 1
OWNER_SIG_DOMAIN = b"ai-harness/vp-owner/v1\0"
KEY_ID_PREFIX = "ed25519-sha256:"
CHIEF_KEY_PREFIX = "firstmate-chief/"
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")
SELF_FILENAME = "self.json"
KEYS_DIRNAME = "keys"
KEY_SUFFIX = ".key"

EXIT_OK, EXIT_REFUSED, EXIT_CONFLICT, EXIT_VERIFY_FAILED = 0, 2, 3, 4

OWNERSHIP_STATES = ("active", "handoff-prepared", "transferred")
PREPARED_STATES = ("handoff-prepared",)

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
B64U = re.compile(r"^[A-Za-z0-9_-]+$")
KEY_ID_BODY = re.compile(r"^[0-9a-f]{64}$")

PROTECTED_FIELDS = ("alg", "key_id", "public_key")
PAYLOAD_FIELDS = ("chief_instance_key", "handoff", "owner_epoch", "owner_machine_key",
                  "ownership_state", "predecessor_object_id", "signed_at", "vp_id")
HANDOFF_FIELDS = ("accepted_at", "destination_machine_key", "handoff_id", "next_owner_epoch",
                  "nonce", "prepared_at")
HANDOFF_REQUIRED = ("destination_machine_key", "handoff_id", "next_owner_epoch", "nonce", "prepared_at")
SELF_FIELDS = ("chief_instance_key", "key_id", "machine_key", "provisioned_at",
               "public_key", "schema_version")
ROUTE_REQUIRED = ("chief_instance_key", "machine_key", "native_agent_name", "route_revision")

# The installer-owned trust and state roots this tool must never write into. It is
# deliberately a list of the reserved roots rather than the bare "/var" prefix:
# macOS hands every user a per-user temporary directory under /var/folders, and
# /var/tmp is a user-writable scratch area on every Unix, so refusing all of /var
# would refuse ordinary caller-owned scratch directories while adding no safety.
SYSTEM_ROOTS = ("/etc", "/usr", "/boot", "/sys", "/proc", "/dev",
                "/var/lib", "/var/lock", "/var/run", "/var/db", "/var/spool", "/var/root")


class Refusal(Exception):
    def __init__(self, code, reason, **extra):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.extra = extra


class TrustFailure(Exception):
    """A document check said no: this is not an owner record. Always exit 4 and
    always name the check. Nothing here is a trust or authorization decision."""

    def __init__(self, check, reason, **extra):
        super().__init__(reason)
        self.check = check
        self.reason = reason
        self.extra = extra


def emit(obj, code=EXIT_OK):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()
    return code


def warn(name, reason):
    sys.stderr.write(f"warning: {name}: {reason}\n")
    sys.stderr.flush()


# --- canonical JSON and encodings ----------------------------------------------------------------

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(field, value, expected_len=None):
    """Unpadded base64url only. Padding, whitespace, standard-alphabet characters,
    and any encoding that does not re-encode to the same string are refused, so a
    non-canonical base64 value can never verify."""
    if not isinstance(value, str) or not value or not B64U.match(value):
        raise TrustFailure("base64", f"{field}: must be unpadded base64url ([A-Za-z0-9_-]), got {value!r}")
    pad = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + pad)
    except (ValueError, binascii.Error):
        raise TrustFailure("base64", f"{field}: is not decodable base64url") from None
    if b64u_encode(raw) != value:
        raise TrustFailure("base64", f"{field}: is not the canonical base64url encoding of its own bytes")
    if expected_len is not None and len(raw) != expected_len:
        raise TrustFailure("base64", f"{field}: decodes to {len(raw)} bytes, expected {expected_len}")
    return raw


def parse_ts(field, value, failure=None):
    if not isinstance(value, str) or not RFC3339.match(value):
        exc = (failure or "timestamp")
        raise TrustFailure(exc, f"{field}: must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ), got {value!r}")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise TrustFailure(failure or "timestamp", f"{field}: not a real timestamp: {value!r}") from None


def valid_ts(value):
    return isinstance(value, str) and RFC3339.match(value) is not None


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_ts(explicit):
    if explicit is not None:
        parse_ts("now", explicit)
        return explicit
    return fmt_ts(datetime.now(timezone.utc).replace(microsecond=0))


def check_ident(field, value, failure=None):
    if not isinstance(value, str) or not IDENT.match(value):
        raise TrustFailure(failure or "structure",
                           f"{field}: must be 1-200 chars of [A-Za-z0-9._:/-] starting alphanumeric, got {value!r}")
    return value


def check_uint(field, value, failure=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TrustFailure(failure or "structure", f"{field}: must be a non-negative integer, got {value!r}")
    return value


def check_exact_fields(where, obj, allowed, required, failure="structure"):
    if not isinstance(obj, dict):
        raise TrustFailure(failure, f"{where}: must be a JSON object, got {type(obj).__name__}")
    missing = [k for k in required if k not in obj]
    if missing:
        raise TrustFailure(failure, f"{where}: missing required field(s) {', '.join(sorted(missing))}")
    unknown = [k for k in obj if k not in allowed]
    if unknown:
        raise TrustFailure(failure, f"{where}: unknown field(s) {', '.join(sorted(unknown))}")


def arg_check(fn, *a):
    """A bad command-line argument is a refusal (exit 2), never a document failure
    (exit 4): exit 4 is reserved for a document that failed a named check."""
    try:
        return fn(*a)
    except TrustFailure as exc:
        raise Refusal(EXIT_REFUSED, exc.reason) from None


def read_bytes(field, path):
    if not path:
        raise Refusal(EXIT_REFUSED, f"{field}: a path is required; this tool never guesses one")
    if not os.path.isfile(path):
        raise Refusal(EXIT_REFUSED, f"{field}: {path} is not a readable file")
    with open(path, "rb") as fh:
        return fh.read()


def parse_canonical_document(field, raw, failure):
    """Parse a document that MUST be byte-for-byte canonical JSON plus one trailing LF."""
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise TrustFailure(failure, f"{field}: not valid UTF-8 at byte {exc.start}") from None
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise TrustFailure(failure, f"{field}: not parseable JSON ({exc})") from None
    if not isinstance(obj, dict):
        raise TrustFailure(failure, f"{field}: the top level must be a JSON object")
    expected = canonical_json(obj) + b"\n"
    if raw != expected:
        raise TrustFailure(failure, f"{field}: is not byte-for-byte RFC 8785 canonical JSON plus one trailing LF"
                                    " (key order, whitespace, escaping, or the trailing newline differs)")
    return obj


# --- path and ownership guards -------------------------------------------------------------------

def refuse_system_path(field, path):
    """Refuse an installer-owned trust or state root. Checked on the given path and,
    when it exists, on its resolved path, so a symlink cannot smuggle one in."""
    # realpath resolves symlinks in the leading components even when the final
    # component does not exist, so a symlink pointing at a reserved root cannot
    # smuggle one in under a caller-owned name.
    candidates = {os.path.normpath(os.path.abspath(path)), os.path.normpath(os.path.realpath(path))}
    for candidate in sorted(candidates):
        if candidate == "/":
            raise Refusal(EXIT_REFUSED, f"{field}: / is never a key or state directory")
        for root in SYSTEM_ROOTS:
            if candidate == root or candidate.startswith(root + "/"):
                raise Refusal(EXIT_REFUSED,
                              f"{field}: {candidate} is under the installer-owned root {root};"
                              " this tool never writes there (see \"What this tool does not do\" in its header)")


def refuse_unless_caller_owned_dir(field, path, mode_limit=0o077):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise Refusal(EXIT_REFUSED, f"{field}: {path} is a symlink; this tool opens only a real directory")
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(EXIT_REFUSED, f"{field}: {path} is not a directory")
    if os.name == "posix":
        if st.st_uid != os.geteuid():
            raise Refusal(EXIT_REFUSED,
                          f"{field}: {path} is owned by uid {st.st_uid}, not this OS identity"
                          f" (uid {os.geteuid()}); nothing was written")
        if st.st_mode & mode_limit:
            raise Refusal(EXIT_REFUSED,
                          f"{field}: {path} is accessible to other users (mode"
                          f" {stat.S_IMODE(st.st_mode):04o}); require 0700")


def ensure_private_dir(field, path, mode_limit=0o077):
    """Guard first, then create. A refused directory is never created."""
    refuse_system_path(field, path)
    if os.path.lexists(path):
        refuse_unless_caller_owned_dir(field, path, mode_limit)
        return path
    parent = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(parent):
        raise Refusal(EXIT_REFUSED, f"{field}: parent directory {parent} does not exist; it is never created for you")
    refuse_unless_caller_owned_dir(f"{field} parent", parent, 0o002)
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    return path


def ensure_state_dir(field, path, healer):
    """The self-provision variant of ensure_private_dir: the write-safety guards are
    identical, but a directory that merely drifted - a loosened mode, a parent that
    is not there yet - is healed rather than refused, because this runs unattended
    from install.sh. Only what the filesystem genuinely refuses is a refusal."""
    refuse_system_path(field, path)
    path = os.path.normpath(os.path.abspath(path))
    if os.path.lexists(path):
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise Refusal(EXIT_REFUSED, f"{field}: {path} is a symlink; this tool opens only a real directory")
        if not stat.S_ISDIR(st.st_mode):
            raise Refusal(EXIT_REFUSED, f"{field}: {path} is not a directory")
        if os.name == "posix":
            if st.st_uid != os.geteuid():
                raise Refusal(EXIT_REFUSED,
                              f"{field}: {path} is owned by uid {st.st_uid}, not this OS identity"
                              f" (uid {os.geteuid()}); nothing was written")
            if st.st_mode & 0o077:
                os.chmod(path, 0o700)
                healer.heal("state-dir-mode",
                            f"{path} was mode {stat.S_IMODE(st.st_mode):04o}, readable by other users,"
                            " and is now 0700")
        return path
    missing = []
    probe = path
    while not os.path.lexists(probe):
        missing.append(probe)
        parent = os.path.dirname(probe)
        if parent == probe:
            raise Refusal(EXIT_REFUSED, f"{field}: {path} has no existing ancestor to create it under")
        probe = parent
    refuse_unless_caller_owned_dir(f"{field} ancestor", probe, 0o002)
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o700)
    return path


def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".fm-vp-owner.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(directory)


# --- openssl ------------------------------------------------------------------------------------

def openssl(args, stdin=None, what="openssl"):
    try:
        proc = subprocess.run(["openssl"] + args, input=stdin, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        raise Refusal(EXIT_REFUSED, "openssl: the openssl CLI is required for Ed25519 and was not found on PATH") from None
    return proc


def openssl_or_refuse(args, what):
    proc = openssl(args)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().replace("\n", "; ")
        raise Refusal(EXIT_REFUSED, f"{what}: openssl {' '.join(args)} exited {proc.returncode}: {detail}")
    return proc.stdout


def raw_public_key_of_private(key_path):
    if not os.path.isfile(key_path):
        raise Refusal(EXIT_REFUSED, f"private key: {key_path} is not a readable file")
    der = openssl_or_refuse(["pkey", "-in", key_path, "-pubout", "-outform", "DER"], "private key")
    return raw_from_spki(der, f"private key {key_path}")


def raw_from_spki(der, what):
    if len(der) == 44 and der.startswith(SPKI_ED25519_PREFIX):
        return der[12:]
    raise Refusal(EXIT_REFUSED, f"{what}: does not hold a 32-byte Ed25519 public key (got {len(der)} DER bytes)")


def spki_of_raw(raw):
    return SPKI_ED25519_PREFIX + raw


def key_id_of(raw_pub):
    return KEY_ID_PREFIX + hashlib.sha256(raw_pub).hexdigest()


def valid_key_id(value):
    return isinstance(value, str) and value.startswith(KEY_ID_PREFIX) \
        and KEY_ID_BODY.match(value[len(KEY_ID_PREFIX):]) is not None


def sign_raw(key_path, data):
    directory = tempfile.mkdtemp(prefix="fm-vp-owner-sign.")
    try:
        msg = os.path.join(directory, "m")
        with open(msg, "wb") as fh:
            fh.write(data)
        sig = openssl_or_refuse(["pkeyutl", "-sign", "-inkey", key_path, "-rawin", "-in", msg], "sign")
    finally:
        _rmtree(directory)
    if len(sig) != 64:
        raise Refusal(EXIT_REFUSED, f"sign: openssl produced a {len(sig)}-byte signature, expected 64")
    return sig


def verify_raw(raw_pub, data, sig):
    """True only when openssl verifies the raw Ed25519 signature over exactly `data`."""
    if len(sig) != 64:
        return False
    directory = tempfile.mkdtemp(prefix="fm-vp-owner-verify.")
    try:
        pub = os.path.join(directory, "p.der")
        msg = os.path.join(directory, "m")
        sigf = os.path.join(directory, "s")
        with open(pub, "wb") as fh:
            fh.write(spki_of_raw(raw_pub))
        with open(msg, "wb") as fh:
            fh.write(data)
        with open(sigf, "wb") as fh:
            fh.write(sig)
        proc = openssl(["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-keyform", "DER",
                        "-rawin", "-in", msg, "-sigfile", sigf])
    finally:
        _rmtree(directory)
    return proc.returncode == 0


def _rmtree(directory):
    for name in os.listdir(directory):
        try:
            os.unlink(os.path.join(directory, name))
        except OSError:
            pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


# --- signer keys ---------------------------------------------------------------------------------

def generate_key(key_dir):
    """Generate one Ed25519 private key 0600, named by its own key id.
    Returns (raw public key, key id, key path)."""
    fd, tmp = tempfile.mkstemp(prefix=".fm-vp-owner-key.", dir=key_dir)
    os.close(fd)
    os.chmod(tmp, 0o600)
    try:
        openssl_or_refuse(["genpkey", "-algorithm", "ed25519", "-out", tmp], "keygen")
        os.chmod(tmp, 0o600)
        raw_pub = raw_public_key_of_private(tmp)
        key_id = key_id_of(raw_pub)
        final = os.path.join(key_dir, key_id + KEY_SUFFIX)
        if os.path.lexists(final):
            raise Refusal(EXIT_CONFLICT, f"keygen: {final} already exists; an existing signer key is never replaced")
        os.rename(tmp, final)
        tmp = None
    finally:
        if tmp is not None and os.path.lexists(tmp):
            os.unlink(tmp)
    os.chmod(final, 0o600)
    fsync_dir(key_dir)
    return raw_pub, key_id, final


def existing_keys(key_dir):
    """Every readable-looking signer key in the directory, newest first."""
    entries = []
    try:
        names = os.listdir(key_dir)
    except OSError:
        return []
    for name in names:
        if not name.endswith(KEY_SUFFIX):
            continue
        key_id = name[: -len(KEY_SUFFIX)]
        if not valid_key_id(key_id):
            continue
        full = os.path.join(key_dir, name)
        if not os.path.isfile(full):
            continue
        entries.append((os.lstat(full).st_mtime, key_id, full))
    entries.sort(key=lambda entry: (-entry[0], entry[1]))
    return [(key_id, full) for _, key_id, full in entries]


def readable_identity(key_path):
    """(raw public key, key id) of a private key file, or None when openssl cannot
    read it. A key file that is not a key is skipped rather than fatal, so one bad
    file in the key directory cannot stop a machine provisioning itself."""
    try:
        raw_pub = raw_public_key_of_private(key_path)
    except Refusal:
        return None
    return raw_pub, key_id_of(raw_pub)


class Healer:
    """Whatever self-provision had to repair. Every entry is reported in the JSON
    object and as one stderr warning, and none of them changes the exit code."""

    def __init__(self):
        self.names = []
        self._pending = []

    def heal(self, name, reason):
        if name not in self.names:
            self.names.append(name)
            self._pending.append((name, reason))

    def flush(self):
        for name, reason in self._pending:
            warn(name, reason)
        self._pending = []


# --- owner record -------------------------------------------------------------------------------

def signing_input(protected, payload):
    return OWNER_SIG_DOMAIN + canonical_json({"protected": protected, "payload": payload})


def validate_owner_shape(record):
    """Every document-validity check, in the order a reader can apply them.
    Returns (protected, payload, raw public key). Raises TrustFailure naming the
    failed check. Nothing here consults any external state."""
    check_exact_fields("record", record, ("payload", "protected", "schema_version", "signature"),
                       ("payload", "protected", "schema_version", "signature"))
    if record["schema_version"] != OWNER_SCHEMA_VERSION:
        raise TrustFailure("schema-version",
                           f"record: schema_version must be {OWNER_SCHEMA_VERSION}, got {record['schema_version']!r}")
    protected, payload = record["protected"], record["payload"]
    check_exact_fields("record.protected", protected, PROTECTED_FIELDS, PROTECTED_FIELDS)
    if protected["alg"] != "Ed25519":
        raise TrustFailure("alg", f"record.protected.alg: must be \"Ed25519\", got {protected['alg']!r}")
    check_ident("record.protected.key_id", protected["key_id"])
    if not valid_key_id(protected["key_id"]):
        raise TrustFailure("structure",
                           f"record.protected.key_id: must be {KEY_ID_PREFIX}<64 lowercase hex>,"
                           f" got {protected['key_id']!r}")
    raw_pub = b64u_decode("record.protected.public_key", protected["public_key"], 32)
    if key_id_of(raw_pub) != protected["key_id"]:
        raise TrustFailure("key-id-mismatch",
                           f"record.protected.key_id {protected['key_id']} is not the SHA-256 of the public key"
                           f" the record carries ({key_id_of(raw_pub)}); the record names one key and"
                           " carries another")
    check_exact_fields("record.payload", payload, PAYLOAD_FIELDS, PAYLOAD_FIELDS)
    check_ident("record.payload.vp_id", payload["vp_id"])
    check_ident("record.payload.owner_machine_key", payload["owner_machine_key"])
    check_ident("record.payload.chief_instance_key", payload["chief_instance_key"])
    expected_chief = CHIEF_KEY_PREFIX + payload["owner_machine_key"]
    if payload["chief_instance_key"] != expected_chief:
        raise TrustFailure("chief-binding",
                           f"record.payload.chief_instance_key {payload['chief_instance_key']} does not derive"
                           f" from owner_machine_key {payload['owner_machine_key']}; it must be {expected_chief}")
    check_uint("record.payload.owner_epoch", payload["owner_epoch"])
    if payload["ownership_state"] not in OWNERSHIP_STATES:
        raise TrustFailure("structure", f"record.payload.ownership_state: must be one of"
                                        f" {', '.join(OWNERSHIP_STATES)}, got {payload['ownership_state']!r}")
    if not isinstance(payload["predecessor_object_id"], str) or not OBJECT_ID.match(payload["predecessor_object_id"]):
        raise TrustFailure("structure", "record.payload.predecessor_object_id: must be 40 lowercase hex characters"
                                        " (the zero id for a first claim)")
    parse_ts("record.payload.signed_at", payload["signed_at"])
    handoff = payload["handoff"]
    if handoff is None:
        if payload["ownership_state"] in PREPARED_STATES:
            raise TrustFailure("structure",
                               f"record.payload.handoff: a {payload['ownership_state']} record must name its handoff")
    else:
        check_exact_fields("record.payload.handoff", handoff, HANDOFF_FIELDS, HANDOFF_REQUIRED)
        check_ident("handoff.handoff_id", handoff["handoff_id"])
        check_ident("handoff.destination_machine_key", handoff["destination_machine_key"])
        check_ident("handoff.nonce", handoff["nonce"])
        next_epoch = check_uint("handoff.next_owner_epoch", handoff["next_owner_epoch"])
        if next_epoch <= payload["owner_epoch"] and payload["ownership_state"] in PREPARED_STATES:
            raise TrustFailure("structure", f"handoff.next_owner_epoch {next_epoch} must be greater than the current"
                                            f" owner_epoch {payload['owner_epoch']}")
        parse_ts("handoff.prepared_at", handoff["prepared_at"])
        if handoff.get("accepted_at") is not None:
            parse_ts("handoff.accepted_at", handoff["accepted_at"])
    return protected, payload, raw_pub


# --- commands -----------------------------------------------------------------------------------

def cmd_keygen(args):
    key_dir = ensure_private_dir("key-dir", args.key_dir)
    raw_pub, key_id, final = generate_key(key_dir)
    return emit({
        "key_id": key_id,
        "public_key": b64u_encode(raw_pub),
        "private_key_path": final,
        "private_key_mode": "0600",
        "key_dir": key_dir,
        "key_dir_mode": "0700",
        "note": "the private key is never printed; self-provision is the unattended path that also"
                " writes the self record naming this identity",
    }, EXIT_OK)


def read_self_record(state_dir, failure="self-structure"):
    """The self record in a state directory, parsed. Raises TrustFailure when the
    file is not byte-for-byte canonical JSON."""
    self_path = os.path.join(state_dir, SELF_FILENAME)
    return self_path, parse_canonical_document("self", read_bytes("self", self_path), failure)


def cmd_self_provision(args):
    healer = Healer()
    machine_key = arg_check(check_ident, "machine-key", args.machine_key)
    chief_key = CHIEF_KEY_PREFIX + machine_key
    arg_check(check_ident, "chief_instance_key", chief_key)
    state_dir = ensure_state_dir("state-dir", args.state_dir, healer)
    key_dir = ensure_state_dir("state-dir keys", os.path.join(state_dir, KEYS_DIRNAME), healer)
    self_path = os.path.join(state_dir, SELF_FILENAME)

    current = None
    if os.path.lexists(self_path):
        try:
            _, current = read_self_record(state_dir)
        except (TrustFailure, Refusal):
            healer.heal("self-unparseable",
                        f"{self_path} is not a readable canonical self record; it is rewritten from the key on disk")

    named = current.get("key_id") if isinstance(current, dict) else None
    raw_pub = key_id = key_path = None
    if valid_key_id(named):
        candidate = os.path.join(key_dir, named + KEY_SUFFIX)
        identity = readable_identity(candidate) if os.path.isfile(candidate) else None
        if identity is not None:
            raw_pub, key_id, key_path = identity[0], identity[1], candidate
        else:
            healer.heal("self-key-missing",
                        f"{self_path} names key {named}, which is not a readable key file in {key_dir};"
                        " the key that is there is adopted instead")
    if key_path is None:
        for _, candidate in existing_keys(key_dir):
            identity = readable_identity(candidate)
            if identity is not None:
                raw_pub, key_id, key_path = identity[0], identity[1], candidate
                break
    if key_path is None:
        raw_pub, key_id, key_path = generate_key(key_dir)
        healer.heal("key-generated", f"no signer key was present in {key_dir}; one Ed25519 key was generated")
    elif current is None and "self-unparseable" not in healer.names:
        healer.heal("self-missing", f"{self_path} was absent; it is rewritten from the key already in {key_dir}")

    public_key = b64u_encode(raw_pub)
    if isinstance(current, dict):
        if current.get("machine_key") != machine_key:
            healer.heal("self-machine-key",
                        f"{self_path} recorded machine_key {current.get('machine_key')!r};"
                        f" the argument {machine_key} wins and the chief key is re-derived")
        elif current.get("chief_instance_key") != chief_key:
            healer.heal("self-machine-key",
                        f"{self_path} recorded chief_instance_key {current.get('chief_instance_key')!r};"
                        f" it is re-derived as {chief_key}")
        if "self-key-missing" not in healer.names \
                and (current.get("key_id") != key_id or current.get("public_key") != public_key):
            healer.heal("self-key-id",
                        f"{self_path} recorded key_id {current.get('key_id')!r} with public_key"
                        f" {current.get('public_key')!r}; both are rewritten from the key in {key_dir}")

    provisioned_at = now_ts(args.now)
    if isinstance(current, dict) and valid_ts(current.get("provisioned_at")):
        provisioned_at = current["provisioned_at"]
    document = {
        "schema_version": SELF_SCHEMA_VERSION,
        "machine_key": machine_key,
        "chief_instance_key": chief_key,
        "key_id": key_id,
        "public_key": public_key,
        "provisioned_at": provisioned_at,
    }
    desired = canonical_json(document) + b"\n"
    on_disk = None
    if os.path.isfile(self_path):
        try:
            with open(self_path, "rb") as fh:
                on_disk = fh.read()
        except OSError:
            on_disk = None
    if on_disk != desired:
        atomic_write(self_path, desired, 0o600)
    elif stat.S_IMODE(os.lstat(self_path).st_mode) != 0o600:
        os.chmod(self_path, 0o600)

    healer.flush()
    return emit({
        "provisioned": True,
        "machine_key": machine_key,
        "chief_instance_key": chief_key,
        "key_id": key_id,
        "public_key": public_key,
        "key_path": key_path,
        "self_path": self_path,
        "healed": healer.names,
    }, EXIT_OK)


def resolve_private_key(args):
    if args.private_key and args.state_dir:
        raise Refusal(EXIT_REFUSED, "key: name either --private-key or --state-dir, not both")
    if args.private_key:
        return args.private_key
    if args.state_dir:
        try:
            self_path, document = read_self_record(args.state_dir)
        except TrustFailure as exc:
            raise Refusal(EXIT_REFUSED, f"self: {exc.reason}; run self-provision to heal it") from None
        key_id = document.get("key_id")
        if not valid_key_id(key_id):
            raise Refusal(EXIT_REFUSED, f"self: {self_path} names no usable key_id;"
                                        " run self-provision to heal it")
        return os.path.join(args.state_dir, KEYS_DIRNAME, key_id + KEY_SUFFIX)
    raise Refusal(EXIT_REFUSED, "key: name the signer with --state-dir (the self-provisioned identity)"
                                " or --private-key")


def cmd_sign_owner(args):
    key_path = resolve_private_key(args)
    raw_pub = raw_public_key_of_private(key_path)
    key_id = key_id_of(raw_pub)

    handoff = None
    if args.handoff_file:
        raw = read_bytes("handoff", args.handoff_file)
        try:
            handoff = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise Refusal(EXIT_REFUSED, f"handoff: {args.handoff_file} is not parseable JSON ({exc})") from None
        for key in HANDOFF_FIELDS:
            handoff.setdefault(key, None)
    payload = {
        "chief_instance_key": arg_check(check_ident, "chief_instance_key", args.chief_instance_key),
        "handoff": handoff,
        "owner_epoch": arg_check(check_uint, "owner_epoch", args.owner_epoch),
        "owner_machine_key": arg_check(check_ident, "owner_machine_key", args.owner_machine_key),
        "ownership_state": args.ownership_state,
        "predecessor_object_id": args.predecessor_object_id,
        "signed_at": now_ts(args.signed_at if args.signed_at else args.now),
        "vp_id": arg_check(check_ident, "vp_id", args.vp_id),
    }
    protected = {"alg": "Ed25519", "key_id": key_id, "public_key": b64u_encode(raw_pub)}
    record = {"schema_version": OWNER_SCHEMA_VERSION, "protected": protected, "payload": payload}
    # Refuse to sign a record this tool would not verify: the shape gate runs first,
    # so a malformed payload never reaches the private key. Signing consults nothing
    # else - there is no state in which a key is allowed or forbidden to sign.
    arg_check(validate_owner_shape, dict(record, signature=b64u_encode(b"\0" * 64)))
    signature = sign_raw(key_path, signing_input(protected, payload))
    record["signature"] = b64u_encode(signature)
    raw = canonical_json(record) + b"\n"
    if args.out:
        atomic_write(args.out, raw, 0o600)
        return emit({"signed": True, "record_path": args.out, "key_id": key_id,
                     "vp_id": payload["vp_id"], "owner_epoch": payload["owner_epoch"],
                     "ownership_state": payload["ownership_state"], "signed_at": payload["signed_at"],
                     "note": "signing does not publish: the compare-and-swap write to"
                             " refs/ai-harness/vp-owners/<escaped-vp-id> is outside this tool"}, EXIT_OK)
    sys.stdout.write(raw.decode("utf-8"))
    sys.stdout.flush()
    return EXIT_OK


def cmd_verify_owner(args):
    raw = read_bytes("record", args.record)
    record = parse_canonical_document("record", raw, "canonical-serialization")
    protected, payload, raw_pub = validate_owner_shape(record)
    signature = b64u_decode("record.signature", record["signature"], 64)
    if not verify_raw(raw_pub, signing_input(protected, payload), signature):
        raise TrustFailure("signature",
                           f"the Ed25519 signature does not verify under key_id {protected['key_id']};"
                           " the record was altered or signed by another key")
    # The one identity expectation a caller can express is a soft warning, not a
    # refusal: a record that is internally valid always verifies.
    warnings = []
    if args.expected_owner_machine_key and args.expected_owner_machine_key != payload["owner_machine_key"]:
        warnings.append(f"machine-binding: owner_machine_key {payload['owner_machine_key']} is not the expected"
                        f" {args.expected_owner_machine_key}")
    for warning in warnings:
        name, _, reason = warning.partition(": ")
        warn(name, reason)
    return emit({
        "verified": True,
        "key_id": protected["key_id"],
        "public_key": protected["public_key"],
        "vp_id": payload["vp_id"],
        "owner_machine_key": payload["owner_machine_key"],
        "owner_epoch": payload["owner_epoch"],
        "ownership_state": payload["ownership_state"],
        "chief_instance_key": payload["chief_instance_key"],
        "signed_at": payload["signed_at"],
        "handoff": payload["handoff"],
        "warnings": warnings,
        "note": "a verified record is not a current record: the compare-and-swap read of"
                " refs/ai-harness/vp-owners/<escaped-vp-id> is outside this tool, and ownership"
                " is self-asserted (see this tool's header)",
    }, EXIT_OK)


def _route_refusal(field, reason, args, **extra):
    out = {
        "owner_route_status": "unresolved",
        "dispatch_authority": "forwarding-blocked",
        "direct_vp_delivery": False,
        "invalid_field": field,
        "reason": reason,
        "owner_machine_key": args.owner_machine_key,
        "owner_epoch": args.owner_epoch,
    }
    out.update(extra)
    return emit(out, EXIT_REFUSED)


def cmd_route_resolve(args):
    arg_check(check_ident, "owner_machine_key", args.owner_machine_key)
    arg_check(check_ident, "local_machine_key", args.local_machine_key)
    arg_check(check_uint, "owner_epoch", args.owner_epoch)
    if args.owner_machine_key == args.local_machine_key:
        return emit({
            "owner_route_status": "local",
            "dispatch_authority": "local-owner",
            "direct_vp_delivery": True,
            "owner_machine_key": args.owner_machine_key,
            "owner_epoch": args.owner_epoch,
            "note": "local dispatch still needs this machine's chief lock and the current"
                    " signature-verified active authority record, neither of which this tool holds",
        }, EXIT_OK)

    raw = read_bytes("routes", args.routes)
    try:
        routes_doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refusal(EXIT_REFUSED, f"routes: {args.routes} is not parseable JSON ({exc})") from None
    if not isinstance(routes_doc, dict) or routes_doc.get("schema_version") != ROUTES_SCHEMA_VERSION \
            or not isinstance(routes_doc.get("routes"), list):
        raise Refusal(EXIT_REFUSED, f"routes: {args.routes} must be an object with schema_version"
                                    f" {ROUTES_SCHEMA_VERSION} and a routes array")
    rows = [r for r in routes_doc["routes"] if isinstance(r, dict) and r.get("machine_key") == args.owner_machine_key]
    # An unresolved route is a routing answer - there is no address for this owner -
    # rather than an authority decision, so it stays a refusal.
    if not rows:
        return _route_refusal("machine_key", f"no chief-routes row is keyed by machine_key"
                                             f" {args.owner_machine_key}; a target is never guessed", args)
    if len(rows) > 1:
        return _route_refusal("machine_key", f"{len(rows)} chief-routes rows are keyed by machine_key"
                                             f" {args.owner_machine_key}; a duplicate row resolves nothing", args)
    row = rows[0]
    for field in ROUTE_REQUIRED:
        if not row.get(field):
            return _route_refusal(field, f"the chief-routes row for {args.owner_machine_key} has no {field}", args)
    if not isinstance(row["route_revision"], int) or isinstance(row["route_revision"], bool) \
            or row["route_revision"] < 1:
        return _route_refusal("route_revision", "route_revision must be a positive integer", args)
    for group, fields in (("agent_mail", ("project_key", "agent_name")),
                          ("fm_send", ("ssh_host", "firstmate_task_id"))):
        block = row.get(group)
        if not isinstance(block, dict):
            return _route_refusal(group, f"the chief-routes row for {args.owner_machine_key} has no {group} block", args)
        for field in fields:
            if not block.get(field):
                return _route_refusal(f"{group}.{field}",
                                      f"the chief-routes row for {args.owner_machine_key} has no {group}.{field}", args)

    return emit({
        "owner_route_status": "resolved",
        "dispatch_authority": "forward-to-owner",
        "direct_vp_delivery": False,
        "owner_machine_key": args.owner_machine_key,
        "owner_epoch": args.owner_epoch,
        "route_revision": row["route_revision"],
        "chief_instance_key": row["chief_instance_key"],
        "endpoints": [
            {"transport": "native", "native_agent_name": row["native_agent_name"]},
            {"transport": "agent-mail", "project_key": row["agent_mail"]["project_key"],
             "agent_name": row["agent_mail"]["agent_name"]},
            {"transport": "fm-send", "ssh_host": row["fm_send"]["ssh_host"],
             "firstmate_task_id": row["fm_send"]["firstmate_task_id"]},
        ],
        "note": "forward the same dispatch id and owner epoch to the owning chief; never address the VP directly",
    }, EXIT_OK)


# --- argument parsing ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="fm-vp-owner.py", description="VP-owner authority layer (see header)")
    p.add_argument("--now", default=None, help="RFC 3339 UTC override of the clock (tests, replay)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("self-provision",
                        description="create or heal this machine's signer identity, unattended and idempotent")
    sp.add_argument("--state-dir", required=True)
    sp.add_argument("--machine-key", required=True)
    sp.set_defaults(fn=cmd_self_provision)

    g = sub.add_parser("keygen")
    g.add_argument("--key-dir", required=True)
    g.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("sign-owner")
    s.add_argument("--private-key", default=None)
    s.add_argument("--state-dir", default=None)
    s.add_argument("--vp-id", required=True)
    s.add_argument("--owner-machine-key", required=True)
    s.add_argument("--owner-epoch", required=True, type=int)
    s.add_argument("--chief-instance-key", required=True)
    s.add_argument("--ownership-state", required=True, choices=list(OWNERSHIP_STATES))
    s.add_argument("--predecessor-object-id", default="0" * 40)
    s.add_argument("--handoff-file", default=None)
    s.add_argument("--signed-at", default=None)
    s.add_argument("--out", default=None)
    s.set_defaults(fn=cmd_sign_owner)

    v = sub.add_parser("verify-owner")
    v.add_argument("--record", required=True)
    v.add_argument("--expected-owner-machine-key", default=None)
    v.set_defaults(fn=cmd_verify_owner)

    r = sub.add_parser("route-resolve")
    r.add_argument("--routes", required=True)
    r.add_argument("--owner-machine-key", required=True)
    r.add_argument("--owner-epoch", required=True, type=int)
    r.add_argument("--local-machine-key", required=True)
    r.set_defaults(fn=cmd_route_resolve)
    return p


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse already printed its message; keep the exit-code contract.
        return EXIT_REFUSED if exc.code else 0
    try:
        return args.fn(args)
    except TrustFailure as exc:
        out = {"verified": False, "code": EXIT_VERIFY_FAILED, "failed_check": exc.check, "reason": exc.reason}
        out.update(exc.extra)
        return emit(out, EXIT_VERIFY_FAILED)
    except Refusal as exc:
        out = {"refused": True, "code": exc.code, "reason": exc.reason}
        out.update(exc.extra)
        return emit(out, exc.code)
    except OSError as exc:
        return emit({"refused": True, "code": EXIT_REFUSED, "reason": f"os: {exc}"}, EXIT_REFUSED)


if __name__ == "__main__":
    sys.exit(main())
