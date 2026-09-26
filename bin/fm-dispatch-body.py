#!/usr/bin/env python3
# fm-dispatch-body.py - the durable dispatch-body broker behind the chief-of-staff
# dispatch path (bin/fm-receive.sh and bin/fm-forward-receive.sh are its faces).
#
# One SQLite database per owning chief home, dispatch-bodies.sqlite3, is the SOLE
# authority for the operational text of a dispatch. A transport carries only a
# dispatch id (native SendMessage's non-operational doorbell) or an envelope copy
# whose hash must match the staged object (Agent Mail, fm-send). Nothing a
# transport carries can create, recover, or alter a body here.
#
#   init                      create or verify the database (schema 1)
#   stage                     commit one canonical body before any transport runs
#   claim                     fm-receive: atomically claim staged -> claimed and
#                             return the body to exactly one winner; every other
#                             caller gets the stored receipt and never the body
#   resume                    re-read a claimed body with its own claim token
#   inject | terminal         finish a claimed row; the body is set to NULL in the
#                             same transaction (secure_delete=ON)
#   reconcile-required        a claimed row whose token or enqueue outcome cannot
#                             be proven; body NULL, surfaced, never re-staged
#   receipt                   the stored receipt for one id, never the body
#   forward-receive           metadata for the owning chief's local delivery;
#                             refuses a stale owner epoch, never exposes the body
#   expire-due                unclaimed rows past expires_at become expired
#   cleanup                   drop old receipts only after the append-only journal
#                             holds the same id, hash and terminal state
#
# Exit codes: 0 done; 2 refused (invalid input, authentication, missing home) -
#             nothing changed; 3 conflict (same id, different content/target/epoch;
#             stale owner) - nothing changed; 4 receipt only (loser, expired,
#             unknown) - no body was or will be returned.
# Every command prints exactly one JSON object on stdout. Only a winning `claim`
# or a token-authenticated `resume` ever includes body_utf8.
#
# Authentication is by OS identity: the database and its directory must be owned
# by the calling user and unreadable by anyone else (mode 0600/0700), or every
# command refuses before opening it. The design's peer-credential socket and the
# per-VP process check need the machine registry that has not landed; until it
# does, a caller must also name the target vp_id and it must match the staged
# row, so a dispatch id alone still obtains nothing.
#
# Standard library only (sqlite3, hashlib, json, secrets). No sqlite3 CLI needed.
import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone

SCHEMA_VERSION = 1
HASH_DOMAIN = b"firstmate-dispatch-body/v1\0"
DEFAULT_TTL_SECONDS = 24 * 3600
TTL_MIN_SECONDS = 60
RETENTION_DAYS = 7
BUSY_TIMEOUT_MS = 5000
ROUTES = ("native", "agent-mail", "fm-send")
STATES = ("staged", "claimed", "reconcile-required", "injected", "terminal", "expired")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")

EXIT_OK, EXIT_REFUSED, EXIT_CONFLICT, EXIT_RECEIPT = 0, 2, 3, 4

RECEIPT_COLUMNS = (
    "dispatch_id", "vp_id", "owner_machine_key", "owner_epoch", "chief_generation",
    "staged_by_machine_key", "message_hash", "state", "winner_route", "created_at",
    "expires_at", "claimed_at", "injected_at", "terminal_at", "failure_reason",
)


class Refusal(Exception):
    def __init__(self, code, reason, **extra):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.extra = extra


def emit(obj, code=EXIT_OK):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()
    return code


def canonical_json(obj):
    # RFC 8785 for the value shapes this record uses (strings and non-negative
    # integers): sorted keys, no whitespace, UTF-8, no escaping of non-ASCII.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def message_hash(record):
    payload = {k: record[k] for k in (
        "schema_version", "dispatch_id", "vp_id", "owner_machine_key", "owner_epoch",
        "chief_generation", "staged_by_machine_key", "body_utf8", "created_at", "expires_at",
    )}
    return hashlib.sha256(HASH_DOMAIN + canonical_json(payload)).hexdigest()


def parse_ts(field, value):
    if not isinstance(value, str) or not RFC3339.match(value):
        raise Refusal(EXIT_REFUSED, f"{field}: must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ), got {value!r}")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal(EXIT_REFUSED, f"{field}: not a real timestamp: {value!r}") from None


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_ts(explicit):
    if explicit is not None:
        parse_ts("now", explicit)
        return explicit
    return fmt_ts(datetime.now(timezone.utc).replace(microsecond=0))


def check_ident(field, value):
    if not isinstance(value, str) or not IDENT.match(value):
        raise Refusal(EXIT_REFUSED, f"{field}: must be 1-200 chars of [A-Za-z0-9._:/-] starting alphanumeric, got {value!r}")
    return value


def check_uint(field, value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Refusal(EXIT_REFUSED, f"{field}: must be a non-negative integer, got {value!r}")
    return value


def check_route(value):
    if value not in ROUTES:
        raise Refusal(EXIT_REFUSED, f"route: must be one of {', '.join(ROUTES)}, got {value!r}")
    return value


def check_hash(field, value):
    if value is None:
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Refusal(EXIT_REFUSED, f"{field}: must be 64 lowercase hex chars, got {value!r}")
    return value


# --- database ------------------------------------------------------------------------------------

def _refuse_unless_private(path, what, is_dir):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise Refusal(EXIT_REFUSED, f"authentication: {what} {path} is a symlink; the broker opens only a real {'directory' if is_dir else 'file'}")
    if is_dir and not stat.S_ISDIR(st.st_mode):
        raise Refusal(EXIT_REFUSED, f"authentication: {path} is not a directory")
    if not is_dir and not stat.S_ISREG(st.st_mode):
        raise Refusal(EXIT_REFUSED, f"authentication: {path} is not a regular file")
    if os.name == "posix":
        if st.st_uid != os.geteuid():
            raise Refusal(EXIT_REFUSED, f"authentication: {what} {path} is owned by uid {st.st_uid}, not this OS identity (uid {os.geteuid()})")
        # The database file must be private (0600). Its directory is the chief home, which
        # the installer creates with the ordinary umask (often group-writable); it must be
        # owned by this identity and never world-writable, or the file could be replaced.
        limit = 0o002 if is_dir else 0o077
        if st.st_mode & limit:
            raise Refusal(EXIT_REFUSED, f"authentication: {what} {path} is {'world-writable' if is_dir else 'accessible to other users'} (mode {stat.S_IMODE(st.st_mode):04o}); require {'no world write' if is_dir else '0600'}")


def open_db(path, create):
    if not path:
        raise Refusal(EXIT_REFUSED, "db: name the broker database (--db, FM_DISPATCH_BODY_DB, or FM_HOME); it is never guessed")
    parent = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(parent):
        raise Refusal(EXIT_REFUSED, f"db: parent directory {parent} does not exist; the chief home must be seeded first")
    if os.name == "posix":
        _refuse_unless_private(parent, "database directory", is_dir=True)
    if os.path.lexists(path):
        _refuse_unless_private(path, "database", is_dir=False)
    elif create:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    else:
        raise Refusal(EXIT_RECEIPT, f"db: {path} does not exist; nothing has been staged here", state="unknown")
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dispatch_bodies ("
        " dispatch_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, vp_id TEXT NOT NULL,"
        " owner_machine_key TEXT NOT NULL, owner_epoch INTEGER NOT NULL, chief_generation INTEGER NOT NULL,"
        " staged_by_machine_key TEXT NOT NULL, body_utf8 TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,"
        " message_hash TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN"
        " ('staged','claimed','reconcile-required','injected','terminal','expired')),"
        " winner_route TEXT, claim_token TEXT, claimed_at TEXT, injected_at TEXT, terminal_at TEXT, failure_reason TEXT)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS broker_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = conn.execute("SELECT value FROM broker_meta WHERE key='schema_version'").fetchone()
    if row is None:
        conn.execute("INSERT INTO broker_meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    elif row["value"] != str(SCHEMA_VERSION):
        conn.execute("ROLLBACK")
        conn.close()
        raise Refusal(EXIT_REFUSED, f"db: schema version {row['value']} is not {SCHEMA_VERSION}; refusing to read a foreign database")
    conn.execute("COMMIT")
    return conn


def fsync_parent(path):
    parent = os.path.dirname(os.path.abspath(path)) or "."
    try:
        fd = os.open(parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def receipt_of(row):
    return {k: row[k] for k in RECEIPT_COLUMNS}


def fetch(conn, dispatch_id):
    return conn.execute("SELECT * FROM dispatch_bodies WHERE dispatch_id=?", (dispatch_id,)).fetchone()


def expire_if_due(conn, row, now):
    """Inside an open write transaction: an unclaimed row past its deadline becomes expired."""
    if row["state"] == "staged" and row["expires_at"] <= now:
        conn.execute(
            "UPDATE dispatch_bodies SET state='expired', body_utf8=NULL, terminal_at=?, failure_reason='expired'"
            " WHERE dispatch_id=? AND state='staged'", (now, row["dispatch_id"]))
        return fetch(conn, row["dispatch_id"])
    return row


# --- commands ------------------------------------------------------------------------------------

def read_body(args):
    if args.body_file is not None and args.body_stdin:
        raise Refusal(EXIT_REFUSED, "body: give --body-file or --body-stdin, not both")
    if args.body_file is not None:
        with open(args.body_file, "rb") as fh:
            raw = fh.read()
    elif args.body_stdin:
        raw = sys.stdin.buffer.read()
    else:
        raise Refusal(EXIT_REFUSED, "body: a staged dispatch needs --body-file or --body-stdin")
    try:
        body = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise Refusal(EXIT_REFUSED, f"body: not valid UTF-8 at byte {exc.start}; the exact rendered prompt must be UTF-8") from None
    if not body.strip():
        raise Refusal(EXIT_REFUSED, "body: empty; a dispatch with no operational text is never staged")
    return body


def cmd_stage(args):
    record = {
        "schema_version": SCHEMA_VERSION,
        "dispatch_id": check_ident("dispatch_id", args.dispatch_id),
        "vp_id": check_ident("vp_id", args.vp_id),
        "owner_machine_key": check_ident("owner_machine_key", args.owner_machine_key),
        "owner_epoch": check_uint("owner_epoch", args.owner_epoch),
        "chief_generation": check_uint("chief_generation", args.chief_generation),
        "staged_by_machine_key": check_ident("staged_by_machine_key", args.staged_by_machine_key),
        "body_utf8": read_body(args),
    }
    created = args.created_at if args.created_at is not None else now_ts(args.now)
    created_dt = parse_ts("created_at", created)
    if args.expires_at is not None and args.ttl_seconds is not None:
        raise Refusal(EXIT_REFUSED, "expiry: give --expires-at or --ttl-seconds, not both")
    if args.expires_at is not None:
        expires_dt = parse_ts("expires_at", args.expires_at)
    else:
        ttl = DEFAULT_TTL_SECONDS if args.ttl_seconds is None else args.ttl_seconds
        if ttl < TTL_MIN_SECONDS or ttl > DEFAULT_TTL_SECONDS:
            raise Refusal(EXIT_REFUSED, f"ttl_seconds: must be within {TTL_MIN_SECONDS}-{DEFAULT_TTL_SECONDS} (the default 24h may only be shortened), got {ttl}")
        expires_dt = created_dt + timedelta(seconds=ttl)
    if expires_dt <= created_dt:
        raise Refusal(EXIT_REFUSED, f"expires_at: {fmt_ts(expires_dt)} is not after created_at {created}")
    record["created_at"] = created
    record["expires_at"] = fmt_ts(expires_dt)
    record["message_hash"] = message_hash(record)

    conn = open_db(args.db, create=True)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = fetch(conn, record["dispatch_id"])
        if existing is not None:
            conn.execute("ROLLBACK")
            if existing["message_hash"] == record["message_hash"]:
                out = {"idempotent": True, "receipt": receipt_of(existing)}
                return emit(out, EXIT_OK)
            differing = [k for k in ("vp_id", "owner_machine_key", "owner_epoch", "chief_generation",
                                     "staged_by_machine_key", "created_at", "expires_at")
                         if existing[k] != record[k]]
            body_differs = existing["body_utf8"] is not None and existing["body_utf8"] != record["body_utf8"]
            if body_differs:
                differing.append("body_utf8")
            if not differing:
                differing.append("body_utf8 (already cleared)")
            raise Refusal(EXIT_CONFLICT,
                          f"conflict: dispatch id {record['dispatch_id']} is already staged with hash"
                          f" {existing['message_hash']}; this request hashes {record['message_hash']}"
                          f" (differs in {', '.join(differing)}); nothing was sent or changed",
                          receipt=receipt_of(existing))
        conn.execute(
            "INSERT INTO dispatch_bodies(dispatch_id, schema_version, vp_id, owner_machine_key, owner_epoch,"
            " chief_generation, staged_by_machine_key, body_utf8, created_at, expires_at, message_hash, state)"
            " VALUES (:dispatch_id, :schema_version, :vp_id, :owner_machine_key, :owner_epoch, :chief_generation,"
            " :staged_by_machine_key, :body_utf8, :created_at, :expires_at, :message_hash, 'staged')", record)
        conn.execute("COMMIT")
        row = fetch(conn, record["dispatch_id"])
    finally:
        conn.close()
    fsync_parent(args.db)
    return emit({"idempotent": False, "receipt": receipt_of(row)}, EXIT_OK)


def _write_inbox_projection(inbox_dir, receipt):
    """The winner's O_CREAT|O_EXCL receipt projection: audit state, never a second body authority."""
    if not inbox_dir:
        return None
    os.makedirs(inbox_dir, mode=0o700, exist_ok=True)
    path = os.path.join(inbox_dir, f"{receipt['dispatch_id']}.json")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return {"path": path, "created": False}
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    return {"path": path, "created": True}


def cmd_claim(args):
    dispatch_id = check_ident("dispatch_id", args.dispatch_id)
    vp_id = check_ident("vp_id", args.vp_id)
    route = check_route(args.route)
    expected = check_hash("expected_hash", args.expected_hash)
    now = now_ts(args.now)
    conn = open_db(args.db, create=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = fetch(conn, dispatch_id)
        if row is None:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_RECEIPT, f"expired/unknown: no dispatch {dispatch_id} is staged here", state="unknown")
        if row["vp_id"] != vp_id:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_REFUSED, f"target-mismatch: dispatch {dispatch_id} is addressed to another VP, not {vp_id}; no body is returned")
        if expected is not None and expected != row["message_hash"]:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_CONFLICT, f"hash-conflict: the envelope hash {expected} does not match the staged object {row['message_hash']}; the transport copy is not authority")
        row = expire_if_due(conn, row, now)
        if row["state"] != "staged":
            conn.execute("COMMIT")
            fsync_parent(args.db)
            raise Refusal(EXIT_RECEIPT, f"receipt-only: dispatch {dispatch_id} is {row['state']}"
                          + (f" (winner {row['winner_route']})" if row["winner_route"] else ""),
                          receipt=receipt_of(row))
        token = secrets.token_urlsafe(32)
        cur = conn.execute(
            "UPDATE dispatch_bodies SET state='claimed', winner_route=?, claim_token=?, claimed_at=?"
            " WHERE dispatch_id=? AND state='staged'", (route, token, now, dispatch_id))
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_CONFLICT, f"claim of {dispatch_id} changed no row; reconcile")
        conn.execute("COMMIT")
        row = fetch(conn, dispatch_id)
    finally:
        conn.close()
    fsync_parent(args.db)
    receipt = receipt_of(row)
    out = {"winner": True, "claim_token": token, "receipt": receipt, "body_utf8": row["body_utf8"]}
    projection = _write_inbox_projection(args.inbox_dir, receipt)
    if projection is not None:
        out["inbox_projection"] = projection
    return emit(out, EXIT_OK)


def _finish(args, new_state, needs_token=True):
    dispatch_id = check_ident("dispatch_id", args.dispatch_id)
    now = now_ts(args.now)
    reason = getattr(args, "reason", None)
    conn = open_db(args.db, create=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = fetch(conn, dispatch_id)
        if row is None:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_RECEIPT, f"expired/unknown: no dispatch {dispatch_id} is staged here", state="unknown")
        if row["state"] != "claimed":
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_RECEIPT, f"receipt-only: dispatch {dispatch_id} is {row['state']}, not claimed", receipt=receipt_of(row))
        if needs_token and not secrets.compare_digest(row["claim_token"] or "", args.claim_token or ""):
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_REFUSED, f"claim-token-mismatch: only the winner of {dispatch_id} may finish it; nothing changed")
        if new_state == "injected":
            conn.execute("UPDATE dispatch_bodies SET state='injected', body_utf8=NULL, injected_at=? WHERE dispatch_id=? AND state='claimed'",
                         (now, dispatch_id))
        else:
            conn.execute("UPDATE dispatch_bodies SET state=?, body_utf8=NULL, terminal_at=?, failure_reason=? WHERE dispatch_id=? AND state='claimed'",
                         (new_state, now, reason, dispatch_id))
        conn.execute("COMMIT")
        row = fetch(conn, dispatch_id)
    finally:
        conn.close()
    fsync_parent(args.db)
    return emit({"receipt": receipt_of(row)}, EXIT_OK)


def cmd_inject(args):
    return _finish(args, "injected")


def cmd_terminal(args):
    if not args.reason:
        raise Refusal(EXIT_REFUSED, "reason: a terminal outcome must name its failure reason")
    return _finish(args, "terminal")


def cmd_reconcile_required(args):
    if not args.reason:
        raise Refusal(EXIT_REFUSED, "reason: say what could not be proven (token, enqueue outcome)")
    return _finish(args, "reconcile-required", needs_token=False)


def cmd_resume(args):
    dispatch_id = check_ident("dispatch_id", args.dispatch_id)
    conn = open_db(args.db, create=False)
    try:
        row = fetch(conn, dispatch_id)
    finally:
        conn.close()
    if row is None:
        raise Refusal(EXIT_RECEIPT, f"expired/unknown: no dispatch {dispatch_id} is staged here", state="unknown")
    if row["state"] != "claimed" or row["body_utf8"] is None:
        raise Refusal(EXIT_RECEIPT, f"receipt-only: dispatch {dispatch_id} is {row['state']}; its body is no longer held", receipt=receipt_of(row))
    if not secrets.compare_digest(row["claim_token"] or "", args.claim_token or ""):
        raise Refusal(EXIT_REFUSED, f"claim-token-mismatch: only the durable winner token of {dispatch_id} may resume it; no body is returned")
    return emit({"winner": True, "resumed": True, "receipt": receipt_of(row), "body_utf8": row["body_utf8"]}, EXIT_OK)


def cmd_receipt(args):
    dispatch_id = check_ident("dispatch_id", args.dispatch_id)
    conn = open_db(args.db, create=False)
    try:
        row = fetch(conn, dispatch_id)
    finally:
        conn.close()
    if row is None:
        raise Refusal(EXIT_RECEIPT, f"expired/unknown: no dispatch {dispatch_id} is staged here", state="unknown")
    return emit({"receipt": receipt_of(row)}, EXIT_OK)


def cmd_forward_receive(args):
    dispatch_id = check_ident("dispatch_id", args.dispatch_id)
    epoch = check_uint("expected_owner_epoch", args.expected_owner_epoch)
    expected = check_hash("expected_hash", args.expected_hash)
    now = now_ts(args.now)
    conn = open_db(args.db, create=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = fetch(conn, dispatch_id)
        if row is None:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_RECEIPT, f"expired/unknown: no dispatch {dispatch_id} is staged here; a forward cannot create one", state="unknown")
        if row["owner_epoch"] != epoch:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_CONFLICT, f"stale-owner: the forward names owner epoch {epoch} but the staged object is epoch {row['owner_epoch']}; refresh and forward once more",
                          current_owner_epoch=row["owner_epoch"], owner_machine_key=row["owner_machine_key"])
        if expected is not None and expected != row["message_hash"]:
            conn.execute("ROLLBACK")
            raise Refusal(EXIT_CONFLICT, f"hash-conflict: the forward envelope hash {expected} does not match the staged object {row['message_hash']}")
        row = expire_if_due(conn, row, now)
        conn.execute("COMMIT")
    finally:
        conn.close()
    if row["state"] != "staged":
        raise Refusal(EXIT_RECEIPT, f"receipt-only: dispatch {dispatch_id} is {row['state']}; nothing is left to deliver locally", receipt=receipt_of(row))
    # Metadata only. The owning chief begins local transport selection from this;
    # the body is obtained solely by the target VP's own claim.
    return emit({"deliverable": True, "receipt": receipt_of(row), "next": "select a local transport for vp_id with bin/fm-message-transport.sh; the VP claims the body via fm-receive"}, EXIT_OK)


def cmd_expire_due(args):
    now = now_ts(args.now)
    conn = open_db(args.db, create=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        due = [r["dispatch_id"] for r in conn.execute("SELECT dispatch_id FROM dispatch_bodies WHERE state='staged' AND expires_at<=? ORDER BY dispatch_id", (now,))]
        for dispatch_id in due:
            conn.execute("UPDATE dispatch_bodies SET state='expired', body_utf8=NULL, terminal_at=?, failure_reason='expired' WHERE dispatch_id=? AND state='staged'", (now, dispatch_id))
        conn.execute("COMMIT")
    finally:
        conn.close()
    fsync_parent(args.db)
    return emit({"expired": due, "count": len(due)}, EXIT_OK)


def _journal_terminal_ids(path):
    """(dispatch_id, message_hash, state) triples the append-only dispatch journal records as terminal."""
    seen = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            did = rec.get("dispatch_id", rec.get("id"))
            state = rec.get("state", rec.get("transport_state"))
            if did and state in ("injected", "terminal", "expired") and rec.get("message_hash"):
                seen.add((did, rec["message_hash"], state))
    return seen


def cmd_cleanup(args):
    now = now_ts(args.now)
    cutoff = fmt_ts(parse_ts("now", now) - timedelta(days=args.retention_days))
    if not os.path.isfile(args.journal):
        raise Refusal(EXIT_REFUSED, f"journal: {args.journal} is missing; receipts are removed only after the journal holds them")
    journaled = _journal_terminal_ids(args.journal)
    conn = open_db(args.db, create=False)
    try:
        conn.execute("BEGIN IMMEDIATE")
        candidates = conn.execute(
            "SELECT dispatch_id, message_hash, state, injected_at, terminal_at FROM dispatch_bodies"
            " WHERE state IN ('injected','terminal','expired') ORDER BY dispatch_id").fetchall()
        removed, kept = [], []
        for r in candidates:
            finished = r["injected_at"] if r["state"] == "injected" else r["terminal_at"]
            if finished is None or finished > cutoff:
                continue
            if (r["dispatch_id"], r["message_hash"], r["state"]) in journaled:
                conn.execute("DELETE FROM dispatch_bodies WHERE dispatch_id=?", (r["dispatch_id"],))
                removed.append(r["dispatch_id"])
            else:
                kept.append(r["dispatch_id"])
        conn.execute("COMMIT")
    finally:
        conn.close()
    fsync_parent(args.db)
    return emit({"removed": removed, "kept_unjournaled": kept, "cutoff": cutoff}, EXIT_OK)


def cmd_init(args):
    conn = open_db(args.db, create=True)
    try:
        count = conn.execute("SELECT count(*) AS n FROM dispatch_bodies").fetchone()["n"]
    finally:
        conn.close()
    fsync_parent(args.db)
    return emit({"db": args.db, "schema_version": SCHEMA_VERSION, "rows": count}, EXIT_OK)


# --- argument parsing ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="fm-dispatch-body.py", description="durable dispatch-body broker (see header)")
    p.add_argument("--db", default=os.environ.get("FM_DISPATCH_BODY_DB") or (
        os.path.join(os.environ["FM_HOME"], "dispatch-bodies.sqlite3") if os.environ.get("FM_HOME") else None))
    p.add_argument("--now", default=None, help="RFC 3339 UTC override of the clock (tests, replay)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    s = sub.add_parser("stage")
    s.add_argument("--dispatch-id", required=True)
    s.add_argument("--vp-id", required=True)
    s.add_argument("--owner-machine-key", required=True)
    s.add_argument("--owner-epoch", required=True, type=int)
    s.add_argument("--chief-generation", required=True, type=int)
    s.add_argument("--staged-by-machine-key", required=True)
    s.add_argument("--created-at", default=None)
    s.add_argument("--expires-at", default=None)
    s.add_argument("--ttl-seconds", default=None, type=int)
    s.add_argument("--body-file", default=None)
    s.add_argument("--body-stdin", action="store_true")
    s.set_defaults(fn=cmd_stage)

    c = sub.add_parser("claim")
    c.add_argument("--dispatch-id", required=True)
    c.add_argument("--vp-id", required=True)
    c.add_argument("--route", required=True)
    c.add_argument("--expected-hash", default=None)
    c.add_argument("--inbox-dir", default=None)
    c.set_defaults(fn=cmd_claim)

    r = sub.add_parser("resume")
    r.add_argument("--dispatch-id", required=True)
    r.add_argument("--claim-token", required=True)
    r.set_defaults(fn=cmd_resume)

    for name, fn, needs_reason in (("inject", cmd_inject, False), ("terminal", cmd_terminal, True)):
        f = sub.add_parser(name)
        f.add_argument("--dispatch-id", required=True)
        f.add_argument("--claim-token", required=True)
        if needs_reason:
            f.add_argument("--reason", required=True)
        f.set_defaults(fn=fn)

    q = sub.add_parser("reconcile-required")
    q.add_argument("--dispatch-id", required=True)
    q.add_argument("--reason", required=True)
    q.set_defaults(fn=cmd_reconcile_required)

    g = sub.add_parser("receipt")
    g.add_argument("--dispatch-id", required=True)
    g.set_defaults(fn=cmd_receipt)

    w = sub.add_parser("forward-receive")
    w.add_argument("--dispatch-id", required=True)
    w.add_argument("--expected-owner-epoch", required=True, type=int)
    w.add_argument("--expected-hash", default=None)
    w.set_defaults(fn=cmd_forward_receive)

    sub.add_parser("expire-due").set_defaults(fn=cmd_expire_due)

    k = sub.add_parser("cleanup")
    k.add_argument("--journal", required=True)
    k.add_argument("--retention-days", default=RETENTION_DAYS, type=int)
    k.set_defaults(fn=cmd_cleanup)
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
    except Refusal as exc:
        out = {"refused": True, "code": exc.code, "reason": exc.reason}
        out.update(exc.extra)
        return emit(out, exc.code)
    except sqlite3.Error as exc:
        return emit({"refused": True, "code": EXIT_REFUSED, "reason": f"sqlite: {exc}"}, EXIT_REFUSED)


if __name__ == "__main__":
    sys.exit(main())
