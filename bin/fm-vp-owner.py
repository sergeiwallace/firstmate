#!/usr/bin/env python3
# fm-vp-owner.py - the VP-owner authority layer: Ed25519 signer identity, the
# root-signed signer trust registry, signed owner records, and owner-route
# resolution for the chief-of-staff dispatch path.
#
# This tool owns everything about VP ownership authority that needs NO privileged
# write and NO remote ref write. It is deliberately stopped at that boundary; the
# "Privileged boundary" section below names what is missing and why.
#
#   keygen            generate this machine's Ed25519 signer keypair in a
#                     caller-owned 0700 directory (private key 0600) and print
#                     its key id and public key, never the private key
#   enroll-request    the canonical enrollment request a human verifies out of
#                     band: identities, public key, key id, one-use nonce, and
#                     proof of possession signed by the new private key
#   sign-owner        sign one owner record (the canonical Ed25519 envelope)
#   verify-owner      verify one owner record against an installed, root-verified
#                     registry; every rejection names the failed trust check
#   registry-verify   verify a trust registry and its detached root signature
#   registry-install  atomically install a verified registry into a caller-owned
#                     directory; refuses expired, unsigned, locally edited, or
#                     rolled-back registries and leaves the installed file alone
#   registry-sign     OFFLINE ROOT ONLY (see that subcommand's banner): sign a
#                     registry revision with the fleet root private key
#                     (--canonicalize first rewrites a human-readable edit into
#                     the canonical serialization that is actually signed)
#   route-resolve     resolve a VP owner machine key to exactly one chief-routes
#                     row and the ordered forwarding endpoints, or refuse
#
# Exit codes, in the style of bin/fm-dispatch-body.py:
#   0 ok; 2 refused (invalid input, path/ownership guard, unresolved route) -
#   nothing changed; 3 conflict (a rolled-back registry install, a key id that
#   contradicts its key) - nothing changed; 4 verification failed - the JSON
#   object names failed_check.
# Every command prints exactly one JSON object on stdout. A private key is never
# printed, copied, or included in any output.
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
#
# ---------------------------------------------------------------------------
# Privileged boundary (NOT implemented here, and not implementable by this tool)
# ---------------------------------------------------------------------------
# Each of the following needs a privileged write, a remote ref write, or a human
# decision. This tool never attempts them, never defaults to them, and never
# writes under /etc or the installer-owned /var trust and state roots.
#
#   * /etc/ai-harness/trust/vp-owner-root.pub - provisioning the offline fleet
#     root public key, and pinning its SHA-256 fingerprint in the human-reviewed
#     installer release manifest. This tool accepts only an explicit --root-pub
#     and has no default path, so it cannot silently trust an unpinned root.
#   * /var/lib/ai-harness/keys/vp-owner/<key-id>.key - placing the machine
#     signer private key in the installer-owned 0700 directory owned by the
#     designated chief OS identity. `keygen` writes only to a caller-owned
#     directory the caller names.
#   * /var/lock/ai-harness/firstmate-chief/<machine-key>.owner.lock and
#     /var/lib/ai-harness/firstmate-chief/<machine-key>/owner.json - the machine
#     singleton lock and machine-global owner record.
#   * /etc/ai-harness/machine-id - the installer-generated machine identity that
#     makes machine_key non-caller-controlled. Here machine_key is an argument,
#     so this tool proves signature and binding consistency, never that the
#     asserted machine key is this machine's.
#   * refs/ai-harness/vp-owners/<escaped-vp-id> on the canonical ai-harness
#     remote - every compare-and-swap write: first claim, active update,
#     prepare-handoff, and activate-successor. This tool signs and verifies the
#     objects those writes carry; it performs no ref write and no network I/O.
#   * offline-root signing of a registry revision (`registry-sign` exists for the
#     human at signing time and for tests; the root private key is never
#     installed on a chief machine).
#   * lost-key recovery authorization - the short-lived, single-use, root-signed
#     authorization bound to vp_id, current object id/epoch, revoked key id,
#     destination machine/key id, next epoch, nonce, and expiry.
#   * any system service, launchd/systemd unit, or sudo operation.
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

OWNER_SCHEMA_VERSION = 1
REGISTRY_SCHEMA_VERSION = 1
ROUTES_SCHEMA_VERSION = 1
OWNER_SIG_DOMAIN = b"ai-harness/vp-owner/v1\0"
ENROLL_SIG_DOMAIN = b"ai-harness/vp-owner-enroll/v1\0"
KEY_ID_PREFIX = "ed25519-sha256:"
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")
REGISTRY_FILENAME = "vp-owner-trust.json"
SIG_SUFFIX = ".sig"

EXIT_OK, EXIT_REFUSED, EXIT_CONFLICT, EXIT_VERIFY_FAILED = 0, 2, 3, 4

OWNERSHIP_STATES = ("active", "handoff-prepared", "handoff-prepared-recovery", "transferred")
PREPARED_STATES = ("handoff-prepared", "handoff-prepared-recovery")
LIFECYCLE_STATUSES = ("active", "retiring", "retired", "revoked")
SIGNING_STATUSES = ("active", "retiring")

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
B64U = re.compile(r"^[A-Za-z0-9_-]+$")

PROTECTED_FIELDS = ("alg", "key_id", "trust_registry_revision")
PAYLOAD_FIELDS = ("chief_instance_key", "handoff", "owner_epoch", "owner_machine_key",
                  "ownership_state", "predecessor_object_id", "signed_at", "vp_id")
HANDOFF_FIELDS = ("accepted_at", "destination_machine_key", "handoff_id", "next_owner_epoch",
                  "nonce", "prepared_at")
HANDOFF_REQUIRED = ("destination_machine_key", "handoff_id", "next_owner_epoch", "nonce", "prepared_at")
SIGNER_FIELDS = ("chief_instance_key", "key_id", "machine_key", "not_after", "not_before",
                 "public_key", "revoked_at", "status", "supersedes")
SIGNER_REQUIRED = ("chief_instance_key", "key_id", "machine_key", "not_before", "public_key", "status")
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
    """A trust check said no. Always exit 4 and always name the check."""

    def __init__(self, check, reason, **extra):
        super().__init__(reason)
        self.check = check
        self.reason = reason
        self.extra = extra


def emit(obj, code=EXIT_OK):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()
    return code


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
    """A bad command-line argument is a refusal (exit 2), never a trust failure (exit 4):
    exit 4 is reserved for a document that failed a named trust check."""
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
            raise Refusal(EXIT_REFUSED, f"{field}: / is never a key or trust directory")
        for root in SYSTEM_ROOTS:
            if candidate == root or candidate.startswith(root + "/"):
                raise Refusal(EXIT_REFUSED,
                              f"{field}: {candidate} is under the installer-owned root {root};"
                              " this tool never writes there (see the Privileged boundary in its header)")


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


def read_public_key_file(field, path):
    """Accept the three shapes a root public key is distributed in: PEM
    (openssl pkey -pubout), DER SPKI, or one line of unpadded base64url raw key."""
    raw = read_bytes(field, path)
    if raw.startswith(b"-----BEGIN"):
        body = b"".join(line for line in raw.splitlines() if not line.startswith(b"-----"))
        try:
            der = base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error):
            raise Refusal(EXIT_REFUSED, f"{field}: {path} is not a decodable PEM public key") from None
        return raw_from_spki(der, f"{field} {path}")
    if len(raw) == 44 and raw.startswith(SPKI_ED25519_PREFIX):
        return raw[12:]
    if len(raw) == 32:
        return raw
    text = raw.decode("utf-8", "replace").strip()
    if text and B64U.match(text):
        try:
            return b64u_decode(field, text, 32)
        except TrustFailure as exc:
            raise Refusal(EXIT_REFUSED, f"{field}: {path}: {exc.reason}") from None
    raise Refusal(EXIT_REFUSED, f"{field}: {path} is not a PEM, DER, or base64url Ed25519 public key")


# --- trust registry -----------------------------------------------------------------------------

def sig_path_for(registry_path, explicit):
    return explicit if explicit else registry_path + SIG_SUFFIX


def verify_registry(registry_path, root_pub_path, sig_path, now, installed_revision=None):
    """Full registry verification. Raises TrustFailure naming the failed check.
    Returns (registry object, raw bytes, root key id)."""
    raw = read_bytes("registry", registry_path)
    registry = parse_canonical_document("registry", raw, "registry-canonical-serialization")
    check_exact_fields("registry", registry,
                       ("expires_at", "issued_at", "registry_revision", "schema_version", "signers"),
                       ("expires_at", "issued_at", "registry_revision", "schema_version", "signers"),
                       "registry-structure")
    if registry["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise TrustFailure("registry-schema-version",
                           f"registry: schema_version must be {REGISTRY_SCHEMA_VERSION},"
                           f" got {registry['schema_version']!r}")
    revision = check_uint("registry.registry_revision", registry["registry_revision"], "registry-structure")
    if revision < 1:
        raise TrustFailure("registry-structure", "registry: registry_revision must be 1 or greater")
    issued = parse_ts("registry.issued_at", registry["issued_at"], "registry-structure")
    expires = parse_ts("registry.expires_at", registry["expires_at"], "registry-structure")
    if expires <= issued:
        raise TrustFailure("registry-structure",
                           f"registry: expires_at {registry['expires_at']} is not after issued_at {registry['issued_at']}")
    if parse_ts("now", now) > expires:
        raise TrustFailure("registry-expired",
                           f"registry: revision {revision} expired at {registry['expires_at']}; refusing to trust it")
    if installed_revision is not None and revision <= installed_revision:
        raise Refusal(EXIT_CONFLICT,
                      f"registry-rolled-back: revision {revision} is not newer than the installed revision"
                      f" {installed_revision}; a rollback is refused and nothing was changed",
                      failed_check="registry-rolled-back", registry_revision=revision,
                      installed_registry_revision=installed_revision)
    signers = registry["signers"]
    if not isinstance(signers, list) or not signers:
        raise TrustFailure("registry-structure", "registry.signers: must be a non-empty array")
    seen_ids, seen_keys, active_machines = set(), set(), set()
    for index, signer in enumerate(signers):
        where = f"registry.signers[{index}]"
        check_exact_fields(where, signer, SIGNER_FIELDS, SIGNER_REQUIRED, "registry-structure")
        key_id = check_ident(f"{where}.key_id", signer["key_id"], "registry-structure")
        raw_pub = b64u_decode(f"{where}.public_key", signer["public_key"], 32)
        if key_id_of(raw_pub) != key_id:
            raise TrustFailure("registry-key-id-mismatch",
                               f"{where}: key_id {key_id} is not the SHA-256 of its own public key"
                               f" ({key_id_of(raw_pub)})")
        check_ident(f"{where}.machine_key", signer["machine_key"], "registry-structure")
        check_ident(f"{where}.chief_instance_key", signer["chief_instance_key"], "registry-structure")
        status = signer["status"]
        if status not in LIFECYCLE_STATUSES:
            raise TrustFailure("registry-structure",
                               f"{where}.status: must be one of {', '.join(LIFECYCLE_STATUSES)}, got {status!r}")
        not_before = parse_ts(f"{where}.not_before", signer["not_before"], "registry-structure")
        if signer.get("not_after") is not None:
            not_after = parse_ts(f"{where}.not_after", signer["not_after"], "registry-structure")
            if not_after <= not_before:
                raise TrustFailure("registry-structure",
                                   f"{where}: not_after {signer['not_after']} is not after not_before"
                                   f" {signer['not_before']}")
        elif status == "retired":
            raise TrustFailure("registry-structure", f"{where}: a retired binding must carry not_after")
        if signer.get("revoked_at") is not None:
            parse_ts(f"{where}.revoked_at", signer["revoked_at"], "registry-structure")
        elif status == "revoked":
            raise TrustFailure("registry-structure", f"{where}: a revoked binding must carry revoked_at")
        if signer.get("supersedes") is not None:
            check_ident(f"{where}.supersedes", signer["supersedes"], "registry-structure")
        if key_id in seen_ids:
            raise TrustFailure("registry-duplicate-binding", f"{where}: key_id {key_id} is bound more than once")
        seen_ids.add(key_id)
        if signer["public_key"] in seen_keys:
            raise TrustFailure("registry-duplicate-binding",
                               f"{where}: the same public key is bound under two key ids")
        seen_keys.add(signer["public_key"])
        if status == "active":
            if signer["machine_key"] in active_machines:
                raise TrustFailure("registry-duplicate-binding",
                                   f"{where}: machine {signer['machine_key']} already has an active binding;"
                                   " a rotation marks the outgoing key retiring, never active")
            active_machines.add(signer["machine_key"])
    for index, signer in enumerate(signers):
        if signer.get("supersedes") is not None and signer["supersedes"] not in seen_ids:
            raise TrustFailure("registry-structure",
                               f"registry.signers[{index}].supersedes: {signer['supersedes']} is not in this registry")

    root_pub = read_public_key_file("root-pub", root_pub_path)
    sig_raw = read_bytes("registry signature", sig_path)
    sig_text = sig_raw.decode("utf-8", "replace").strip()
    signature = b64u_decode("registry signature", sig_text, 64)
    if not verify_raw(root_pub, raw, signature):
        raise TrustFailure("registry-signature",
                           f"registry: the detached signature in {sig_path} does not verify against the root key"
                           f" {key_id_of(root_pub)}; an unsigned or locally edited registry is refused")
    return registry, raw, key_id_of(root_pub)


def binding_for(registry, key_id):
    for signer in registry["signers"]:
        if signer["key_id"] == key_id:
            return signer
    return None


# --- owner record -------------------------------------------------------------------------------

def signing_input(protected, payload):
    return OWNER_SIG_DOMAIN + canonical_json({"protected": protected, "payload": payload})


def validate_owner_shape(record):
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
    if not protected["key_id"].startswith(KEY_ID_PREFIX) or \
            not re.fullmatch(r"[0-9a-f]{64}", protected["key_id"][len(KEY_ID_PREFIX):]):
        raise TrustFailure("structure",
                           f"record.protected.key_id: must be {KEY_ID_PREFIX}<64 lowercase hex>,"
                           f" got {protected['key_id']!r}")
    check_uint("record.protected.trust_registry_revision", protected["trust_registry_revision"])
    check_exact_fields("record.payload", payload, PAYLOAD_FIELDS, PAYLOAD_FIELDS)
    check_ident("record.payload.vp_id", payload["vp_id"])
    check_ident("record.payload.owner_machine_key", payload["owner_machine_key"])
    check_ident("record.payload.chief_instance_key", payload["chief_instance_key"])
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
    return protected, payload


def check_owner_trust(protected, payload, registry, now):
    """The trust checks that need the installed registry. Raises TrustFailure."""
    record_revision = protected["trust_registry_revision"]
    installed_revision = registry["registry_revision"]
    if record_revision > installed_revision:
        raise TrustFailure("future-registry-revision",
                           f"record provenance revision {record_revision} is newer than the installed registry"
                           f" revision {installed_revision}; refresh the root-verified registry and stay"
                           " non-dispatching until the installed revision reaches it",
                           record_trust_registry_revision=record_revision,
                           installed_registry_revision=installed_revision)
    binding = binding_for(registry, protected["key_id"])
    if binding is None:
        raise TrustFailure("unknown-key-id",
                           f"key_id {protected['key_id']} is not bound in installed registry revision"
                           f" {installed_revision}")
    if binding["status"] == "revoked":
        raise TrustFailure("revoked-binding",
                           f"key_id {binding['key_id']} was revoked at {binding['revoked_at']};"
                           " every record it signed fails closed regardless of signing time")
    signed_at = parse_ts("record.payload.signed_at", payload["signed_at"])
    not_before = parse_ts("binding.not_before", binding["not_before"])
    if signed_at < not_before:
        raise TrustFailure("signing-window",
                           f"signed_at {payload['signed_at']} is before the binding's not_before"
                           f" {binding['not_before']}")
    if binding.get("not_after") is not None and signed_at > parse_ts("binding.not_after", binding["not_after"]):
        raise TrustFailure("signing-window",
                           f"signed_at {payload['signed_at']} is after the binding's not_after"
                           f" {binding['not_after']}")
    if binding["machine_key"] != payload["owner_machine_key"]:
        raise TrustFailure("machine-binding",
                           f"owner_machine_key {payload['owner_machine_key']} does not match the binding's"
                           f" machine_key {binding['machine_key']} for key_id {binding['key_id']}")
    if binding["chief_instance_key"] != payload["chief_instance_key"]:
        raise TrustFailure("chief-binding",
                           f"chief_instance_key {payload['chief_instance_key']} does not match the binding's"
                           f" chief_instance_key {binding['chief_instance_key']} for key_id {binding['key_id']}")
    return binding


# --- commands -----------------------------------------------------------------------------------

def cmd_keygen(args):
    key_dir = ensure_private_dir("key-dir", args.key_dir)
    fd, tmp = tempfile.mkstemp(prefix=".fm-vp-owner-key.", dir=key_dir)
    os.close(fd)
    os.chmod(tmp, 0o600)
    try:
        openssl_or_refuse(["genpkey", "-algorithm", "ed25519", "-out", tmp], "keygen")
        os.chmod(tmp, 0o600)
        raw_pub = raw_public_key_of_private(tmp)
        key_id = key_id_of(raw_pub)
        final = os.path.join(key_dir, key_id + ".key")
        if os.path.lexists(final):
            raise Refusal(EXIT_CONFLICT, f"keygen: {final} already exists; an existing signer key is never replaced")
        os.rename(tmp, final)
        tmp = None
    finally:
        if tmp is not None and os.path.lexists(tmp):
            os.unlink(tmp)
    os.chmod(final, 0o600)
    fsync_dir(key_dir)
    return emit({
        "key_id": key_id,
        "public_key": b64u_encode(raw_pub),
        "private_key_path": final,
        "private_key_mode": "0600",
        "key_dir": key_dir,
        "key_dir_mode": "0700",
        "note": "the private key is never printed; the fleet-root enrollment of this key id is human-gated",
    }, EXIT_OK)


def resolve_private_key(args):
    if args.private_key:
        return args.private_key
    if args.key_dir and args.key_id:
        return os.path.join(args.key_dir, args.key_id + ".key")
    raise Refusal(EXIT_REFUSED, "key: name the signer private key with --private-key, or --key-dir plus --key-id")


def cmd_enroll_request(args):
    key_path = resolve_private_key(args)
    raw_pub = raw_public_key_of_private(key_path)
    key_id = key_id_of(raw_pub)
    if args.key_id and args.key_id != key_id:
        raise Refusal(EXIT_CONFLICT, f"key_id: --key-id {args.key_id} is not the key id of {key_path} ({key_id})")
    request = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "chief_instance_key": arg_check(check_ident, "chief_instance_key", args.chief_instance_key),
        "key_id": key_id,
        "machine_key": arg_check(check_ident, "machine_key", args.machine_key),
        "nonce": args.nonce if args.nonce else secrets.token_urlsafe(24),
        "public_key": b64u_encode(raw_pub),
        "requested_at": now_ts(args.now),
    }
    arg_check(check_ident, "nonce", request["nonce"])
    proof = sign_raw(key_path, ENROLL_SIG_DOMAIN + canonical_json(request))
    document = dict(request)
    document["proof_of_possession"] = b64u_encode(proof)
    raw = canonical_json(document) + b"\n"
    if args.out:
        atomic_write(args.out, raw, 0o600)
        return emit({"enrolled": False, "request_path": args.out, "key_id": key_id,
                     "machine_key": request["machine_key"], "nonce": request["nonce"],
                     "note": "non-dispatching until a human verifies this request, root-signs a registry revision"
                             " naming this key active, and that revision is installed"}, EXIT_OK)
    sys.stdout.write(raw.decode("utf-8"))
    sys.stdout.flush()
    return EXIT_OK


def cmd_sign_owner(args):
    key_path = resolve_private_key(args)
    raw_pub = raw_public_key_of_private(key_path)
    key_id = key_id_of(raw_pub)
    if args.key_id and args.key_id != key_id:
        raise Refusal(EXIT_CONFLICT, f"key_id: --key-id {args.key_id} is not the key id of {key_path} ({key_id})")

    revision = args.trust_registry_revision
    if args.registry:
        registry, _, _ = verify_registry(args.registry, args.root_pub, sig_path_for(args.registry, args.sig),
                                         now_ts(args.now))
        if revision is None:
            revision = registry["registry_revision"]
        binding = binding_for(registry, key_id)
        if binding is None:
            raise Refusal(EXIT_REFUSED, f"key_id {key_id} is not bound in installed registry revision"
                                        f" {registry['registry_revision']}; this machine is non-dispatching until"
                                        " a human root-signs its enrollment")
        if binding["status"] not in SIGNING_STATUSES:
            raise Refusal(EXIT_REFUSED, f"key_id {key_id} is {binding['status']} in the installed registry;"
                                        f" only {' or '.join(SIGNING_STATUSES)} bindings may sign")
    if revision is None:
        raise Refusal(EXIT_REFUSED, "trust_registry_revision: give --trust-registry-revision, or --registry plus"
                                    " --root-pub so the signing provenance revision is the verified installed one")

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
    protected = {"alg": "Ed25519", "key_id": key_id,
                 "trust_registry_revision": arg_check(check_uint, "trust_registry_revision", revision)}
    record = {"schema_version": OWNER_SCHEMA_VERSION, "protected": protected, "payload": payload}
    # Refuse to sign a record this tool would not verify: the shape gate runs first,
    # so a malformed payload never reaches the private key.
    arg_check(validate_owner_shape, dict(record, signature=b64u_encode(b"\0" * 64)))
    signature = sign_raw(key_path, signing_input(protected, payload))
    record["signature"] = b64u_encode(signature)
    raw = canonical_json(record) + b"\n"
    if args.out:
        atomic_write(args.out, raw, 0o600)
        return emit({"signed": True, "record_path": args.out, "key_id": key_id,
                     "trust_registry_revision": protected["trust_registry_revision"],
                     "vp_id": payload["vp_id"], "owner_epoch": payload["owner_epoch"],
                     "ownership_state": payload["ownership_state"], "signed_at": payload["signed_at"],
                     "note": "signing does not publish: the compare-and-swap write to"
                             " refs/ai-harness/vp-owners/<escaped-vp-id> is outside this tool"}, EXIT_OK)
    sys.stdout.write(raw.decode("utf-8"))
    sys.stdout.flush()
    return EXIT_OK


def cmd_verify_owner(args):
    raw = read_bytes("record", args.record)
    registry, _, root_key_id = verify_registry(args.registry, args.root_pub,
                                               sig_path_for(args.registry, args.sig), now_ts(args.now))
    record = parse_canonical_document("record", raw, "canonical-serialization")
    protected, payload = validate_owner_shape(record)
    signature = b64u_decode("record.signature", record["signature"], 64)
    binding = check_owner_trust(protected, payload, registry, now_ts(args.now))
    raw_pub = b64u_decode("binding.public_key", binding["public_key"], 32)
    if not verify_raw(raw_pub, signing_input(protected, payload), signature):
        raise TrustFailure("signature",
                           f"the Ed25519 signature does not verify under key_id {binding['key_id']};"
                           " the record was altered or signed by another key")
    if args.expected_owner_machine_key and args.expected_owner_machine_key != payload["owner_machine_key"]:
        raise TrustFailure("machine-binding",
                           f"owner_machine_key {payload['owner_machine_key']} is not the expected"
                           f" {args.expected_owner_machine_key}")
    return emit({
        "verified": True,
        "key_id": protected["key_id"],
        "binding_status": binding["status"],
        "installed_registry_revision": registry["registry_revision"],
        "record_trust_registry_revision": protected["trust_registry_revision"],
        "root_key_id": root_key_id,
        "vp_id": payload["vp_id"],
        "owner_machine_key": payload["owner_machine_key"],
        "owner_epoch": payload["owner_epoch"],
        "ownership_state": payload["ownership_state"],
        "chief_instance_key": payload["chief_instance_key"],
        "signed_at": payload["signed_at"],
        "handoff": payload["handoff"],
        "note": "a verified record is not a current record: the compare-and-swap read of"
                " refs/ai-harness/vp-owners/<escaped-vp-id> is outside this tool",
    }, EXIT_OK)


def cmd_registry_verify(args):
    registry, raw, root_key_id = verify_registry(args.registry, args.root_pub,
                                                 sig_path_for(args.registry, args.sig), now_ts(args.now),
                                                 args.installed_revision)
    return emit({
        "verified": True,
        "registry": args.registry,
        "registry_revision": registry["registry_revision"],
        "issued_at": registry["issued_at"],
        "expires_at": registry["expires_at"],
        "root_key_id": root_key_id,
        "signers": [{"key_id": s["key_id"], "machine_key": s["machine_key"],
                     "chief_instance_key": s["chief_instance_key"], "status": s["status"]}
                    for s in registry["signers"]],
        "sha256": hashlib.sha256(raw).hexdigest(),
    }, EXIT_OK)


def installed_registry_state(path, root_pub_path, now):
    """The installed registry's revision, and whether it still verifies. A file that
    cannot even be parsed reports revision None, so a first install proceeds; the
    directory is caller-owned and 0700, so a corrupt installed file is not a
    privilege boundary, but it is always reported rather than passed over."""
    if not os.path.isfile(path):
        return None, "absent"
    try:
        obj = json.loads(read_bytes("installed registry", path).decode("utf-8"))
        revision = obj["registry_revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            return None, "unparseable"
    except (ValueError, UnicodeDecodeError, KeyError, TypeError):
        return None, "unparseable"
    try:
        verify_registry(path, root_pub_path, path + SIG_SUFFIX, now)
        return revision, "verified"
    except (TrustFailure, Refusal):
        return revision, "unverifiable"


def cmd_registry_install(args):
    into = ensure_private_dir("into", args.into)
    installed_path = os.path.join(into, REGISTRY_FILENAME)
    installed_revision, installed_state = installed_registry_state(installed_path, args.root_pub, now_ts(args.now))
    registry, raw, root_key_id = verify_registry(args.registry, args.root_pub,
                                                 sig_path_for(args.registry, args.sig), now_ts(args.now),
                                                 installed_revision)
    sig_raw = read_bytes("registry signature", sig_path_for(args.registry, args.sig))
    # The signature lands first: a reader that sees a new signature against the old
    # registry fails its own verification, which is the safe direction.
    atomic_write(installed_path + SIG_SUFFIX, sig_raw, 0o600)
    atomic_write(installed_path, raw, 0o600)
    return emit({
        "installed": True,
        "path": installed_path,
        "signature_path": installed_path + SIG_SUFFIX,
        "registry_revision": registry["registry_revision"],
        "previous_registry_revision": installed_revision,
        "previous_state": installed_state,
        "root_key_id": root_key_id,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "note": "the root public key at --root-pub and its release-manifest fingerprint pin are"
                " human-gated; this tool has no default root path and never reads /etc",
    }, EXIT_OK)


def cmd_registry_sign(args):
    # OFFLINE ROOT ONLY. The fleet root private key is never installed on a chief
    # machine: this subcommand exists for the human at signing time on the offline
    # root host, and for tests that need a root of their own. Running it on a chief
    # machine would mean the root key is there, which the design forbids.
    raw = read_bytes("registry", args.registry)
    if args.canonicalize:
        # A human edits a readable registry; only its canonical serialization is ever
        # signed. Rewriting it here (atomically, in place, on the offline root host)
        # is what makes the reviewed file and the signed bytes the same object.
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise Refusal(EXIT_REFUSED, f"registry: {args.registry} is not parseable JSON ({exc})") from None
        if not isinstance(parsed, dict):
            raise Refusal(EXIT_REFUSED, "registry: the top level must be a JSON object")
        canonical = canonical_json(parsed) + b"\n"
        if canonical != raw:
            atomic_write(args.registry, canonical, 0o644)
            raw = canonical
    registry = parse_canonical_document("registry", raw, "registry-canonical-serialization")
    if registry.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise Refusal(EXIT_REFUSED, f"registry: schema_version must be {REGISTRY_SCHEMA_VERSION}")
    raw_pub = raw_public_key_of_private(args.root_key)
    signature = sign_raw(args.root_key, raw)
    out = args.out if args.out else sig_path_for(args.registry, None)
    atomic_write(out, (b64u_encode(signature) + "\n").encode("ascii"), 0o644)
    return emit({
        "signed": True,
        "signature_path": out,
        "registry_revision": registry["registry_revision"],
        "root_key_id": key_id_of(raw_pub),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "warning": "offline root only: this command is never run on a chief machine in production",
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

    registry_revision = None
    if args.registry:
        registry, _, _ = verify_registry(args.registry, args.root_pub, sig_path_for(args.registry, args.sig),
                                         now_ts(args.now))
        registry_revision = registry["registry_revision"]
        bound = [s for s in registry["signers"]
                 if s["machine_key"] == args.owner_machine_key and s["status"] in SIGNING_STATUSES]
        if not bound:
            return _route_refusal("chief_instance_key",
                                  f"installed registry revision {registry_revision} has no active or retiring"
                                  f" binding for machine_key {args.owner_machine_key}", args,
                                  installed_registry_revision=registry_revision)
        if all(s["chief_instance_key"] != row["chief_instance_key"] for s in bound):
            return _route_refusal("chief_instance_key",
                                  f"the chief-routes row names chief_instance_key {row['chief_instance_key']}"
                                  f" but the registry binds machine_key {args.owner_machine_key} to"
                                  f" {bound[0]['chief_instance_key']}", args,
                                  installed_registry_revision=registry_revision)

    return emit({
        "owner_route_status": "resolved",
        "dispatch_authority": "forward-to-owner",
        "direct_vp_delivery": False,
        "owner_machine_key": args.owner_machine_key,
        "owner_epoch": args.owner_epoch,
        "route_revision": row["route_revision"],
        "chief_instance_key": row["chief_instance_key"],
        "installed_registry_revision": registry_revision,
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

    g = sub.add_parser("keygen")
    g.add_argument("--key-dir", required=True)
    g.set_defaults(fn=cmd_keygen)

    def add_key_args(parser):
        parser.add_argument("--private-key", default=None)
        parser.add_argument("--key-dir", default=None)
        parser.add_argument("--key-id", default=None)

    e = sub.add_parser("enroll-request")
    add_key_args(e)
    e.add_argument("--machine-key", required=True)
    e.add_argument("--chief-instance-key", required=True)
    e.add_argument("--nonce", default=None)
    e.add_argument("--out", default=None)
    e.set_defaults(fn=cmd_enroll_request)

    s = sub.add_parser("sign-owner")
    add_key_args(s)
    s.add_argument("--vp-id", required=True)
    s.add_argument("--owner-machine-key", required=True)
    s.add_argument("--owner-epoch", required=True, type=int)
    s.add_argument("--chief-instance-key", required=True)
    s.add_argument("--ownership-state", required=True, choices=list(OWNERSHIP_STATES))
    s.add_argument("--predecessor-object-id", default="0" * 40)
    s.add_argument("--handoff-file", default=None)
    s.add_argument("--trust-registry-revision", default=None, type=int)
    s.add_argument("--registry", default=None)
    s.add_argument("--root-pub", default=None)
    s.add_argument("--sig", default=None)
    s.add_argument("--signed-at", default=None)
    s.add_argument("--out", default=None)
    s.set_defaults(fn=cmd_sign_owner)

    v = sub.add_parser("verify-owner")
    v.add_argument("--record", required=True)
    v.add_argument("--registry", required=True)
    v.add_argument("--root-pub", required=True)
    v.add_argument("--sig", default=None)
    v.add_argument("--expected-owner-machine-key", default=None)
    v.set_defaults(fn=cmd_verify_owner)

    rv = sub.add_parser("registry-verify")
    rv.add_argument("--registry", required=True)
    rv.add_argument("--root-pub", required=True)
    rv.add_argument("--sig", default=None)
    rv.add_argument("--installed-revision", default=None, type=int)
    rv.set_defaults(fn=cmd_registry_verify)

    ri = sub.add_parser("registry-install")
    ri.add_argument("--registry", required=True)
    ri.add_argument("--root-pub", required=True)
    ri.add_argument("--into", required=True)
    ri.add_argument("--sig", default=None)
    ri.set_defaults(fn=cmd_registry_install)

    rs = sub.add_parser("registry-sign", description="OFFLINE ROOT ONLY: never run on a chief machine")
    rs.add_argument("--registry", required=True)
    rs.add_argument("--root-key", required=True)
    rs.add_argument("--out", default=None)
    rs.add_argument("--canonicalize", action="store_true",
                    help="rewrite the registry to its canonical serialization before signing,"
                         " so a human-readable edit and the signed bytes are the same object")
    rs.set_defaults(fn=cmd_registry_sign)

    r = sub.add_parser("route-resolve")
    r.add_argument("--routes", required=True)
    r.add_argument("--owner-machine-key", required=True)
    r.add_argument("--owner-epoch", required=True, type=int)
    r.add_argument("--local-machine-key", required=True)
    r.add_argument("--registry", default=None)
    r.add_argument("--root-pub", default=None)
    r.add_argument("--sig", default=None)
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
        # Only for the subcommands that take a root: registry-sign names the offline
        # root private key instead and has no --root-pub at all.
        if hasattr(args, "root_pub") and getattr(args, "registry", None) and not args.root_pub:
            raise Refusal(EXIT_REFUSED, "root-pub: --registry is only trusted with its explicit --root-pub;"
                                        " there is no default root path and /etc is never read")
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
