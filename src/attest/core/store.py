"""Append-only storage.

Two things here are load-bearing and easy to get wrong.

**Append-only is enforced by the database, not by the application.** SQLite
triggers abort any UPDATE or DELETE on the entries table. Application-level
immutability is one careless ORM call away from being untrue, and the whole
value of an audit trail is that "we don't modify it" is a property rather than
a policy.

That is defence in depth, not a security boundary, and the difference matters
enough to state plainly: anyone with write access to the database *file* can
drop the triggers and rewrite rows. What stops that from succeeding is the
signature chain, not the triggers - which is exactly what ``attest verify``
demonstrates by tampering at the file level and being caught anyway.

**Appends are serialised.** Two concurrent writers that both read the same head
would build two entries claiming the same ``seq`` and the same ``prev_hash`` —
a fork. ``BEGIN IMMEDIATE`` takes the write lock before reading the head, and a
UNIQUE constraint on ``seq`` is the backstop if that ever fails.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .chain import GENESIS_HASH, Entry, build

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq         INTEGER PRIMARY KEY,
    timestamp   TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    prev_hash   TEXT    NOT NULL,
    entry_hash  TEXT    NOT NULL UNIQUE,
    signature   TEXT    NOT NULL,
    key_id      TEXT    NOT NULL,
    version     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_actor    ON entries(actor);
CREATE INDEX IF NOT EXISTS idx_entries_action   ON entries(action);
CREATE INDEX IF NOT EXISTS idx_entries_resource ON entries(resource);
CREATE INDEX IF NOT EXISTS idx_entries_ts       ON entries(timestamp);

-- Immutability as a database property rather than an application convention.
CREATE TRIGGER IF NOT EXISTS entries_no_update
BEFORE UPDATE ON entries
BEGIN
    SELECT RAISE(ABORT, 'audit entries are append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS entries_no_delete
BEFORE DELETE ON entries
BEGIN
    SELECT RAISE(ABORT, 'audit entries are append-only: DELETE is not permitted');
END;

CREATE TABLE IF NOT EXISTS checkpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    covers_to_seq INTEGER NOT NULL,
    head_hash     TEXT NOT NULL,
    merkle_root   TEXT NOT NULL,
    signature     TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    tsa_token     TEXT,
    tsa_time      TEXT,
    tsa_authority TEXT
);

CREATE TABLE IF NOT EXISTS keys (
    key_id     TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    retired_at TEXT
);
"""


class StoreError(RuntimeError):
    pass


class AppendOnlyViolation(StoreError):
    """Raised when something tries to mutate or remove an entry."""


class Store:
    """SQLite-backed append-only entry store."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(
            self.path,
            isolation_level=None,
            check_same_thread=False,
            uri=self.path.startswith("file:"),
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # Cross-process contention: wait rather than failing the write outright.
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)
        # The connection is shared across threads (check_same_thread=False), so
        # BEGIN IMMEDIATE alone is not enough: two threads issuing it on the
        # *same* connection collide with "cannot start a transaction within a
        # transaction". IMMEDIATE serialises writers across processes; this lock
        # serialises them inside one.
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """A serialised write transaction.

        IMMEDIATE takes the write lock before the head is read, so two
        concurrent appends cannot both build on the same predecessor.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # -- reads --------------------------------------------------------------

    def head(self) -> tuple[int, str]:
        """``(last seq, head hash)``; ``(0, GENESIS_HASH)`` on an empty trail."""
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row["seq"], row["entry_hash"]) if row else (0, GENESIS_HASH)

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) AS n FROM entries").fetchone()["n"]

    def get(self, seq: int) -> Entry | None:
        row = self._conn.execute("SELECT * FROM entries WHERE seq = ?", (seq,)).fetchone()
        return _row_to_entry(row) if row else None

    def entries(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Entry]:
        sql = "SELECT * FROM entries WHERE 1=1"
        args: list[Any] = []
        for column, value in (
            ("actor", actor), ("action", action), ("resource", resource),
        ):
            if value:
                sql += f" AND {column} = ?"
                args.append(value)
        if since:
            sql += " AND timestamp >= ?"
            args.append(since)
        if until:
            sql += " AND timestamp <= ?"
            args.append(until)
        sql += " ORDER BY seq"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            args += [limit, offset]
        return [_row_to_entry(r) for r in self._conn.execute(sql, args)]

    # -- writes -------------------------------------------------------------

    def append(
        self,
        actor: str,
        action: str,
        resource: str,
        outcome: str = "success",
        payload: dict[str, Any] | None = None,
        signer: Any = None,
        timestamp: str | None = None,
    ) -> Entry:
        """Append one entry, hashed and signed, under the write lock."""
        with self._write() as conn:
            row = conn.execute(
                "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            last_seq, prev_hash = (row["seq"], row["entry_hash"]) if row else (0, GENESIS_HASH)

            entry = build(
                seq=last_seq + 1,
                prev_hash=prev_hash,
                actor=actor,
                action=action,
                resource=resource,
                outcome=outcome,
                payload=payload,
                timestamp=timestamp,
            )
            if signer is not None:
                from dataclasses import replace

                entry = replace(
                    entry,
                    signature=signer.sign(bytes.fromhex(entry.entry_hash)),
                    key_id=signer.key_id,
                )

            conn.execute(
                "INSERT INTO entries (seq, timestamp, actor, action, resource, outcome, "
                "payload, prev_hash, entry_hash, signature, key_id, version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    entry.seq, entry.timestamp, entry.actor, entry.action, entry.resource,
                    entry.outcome, json.dumps(entry.payload, sort_keys=True), entry.prev_hash,
                    entry.entry_hash, entry.signature, entry.key_id, entry.version,
                ),
            )
            return entry

    def register_key(self, key_id: str, public_key: str, added_at: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO keys (key_id, public_key, added_at) VALUES (?,?,?)",
            (key_id, public_key, added_at),
        )

    def registered_keys(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM keys ORDER BY added_at")]

    # -- checkpoints --------------------------------------------------------

    def add_checkpoint(self, checkpoint: dict[str, Any]) -> int:
        cur = self._conn.execute(
            "INSERT INTO checkpoints (created_at, covers_to_seq, head_hash, merkle_root, "
            "signature, key_id, tsa_token, tsa_time, tsa_authority) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                checkpoint["created_at"], checkpoint["covers_to_seq"], checkpoint["head_hash"],
                checkpoint["merkle_root"], checkpoint["signature"], checkpoint["key_id"],
                checkpoint.get("tsa_token"), checkpoint.get("tsa_time"),
                checkpoint.get("tsa_authority"),
            ),
        )
        return int(cur.lastrowid)

    def checkpoints(self) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._conn.execute("SELECT * FROM checkpoints ORDER BY covers_to_seq")
        ]

    def latest_checkpoint(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM checkpoints ORDER BY covers_to_seq DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    # -- test/demo support --------------------------------------------------

    def force_mutate(self, seq: int, **columns: Any) -> None:
        """Rewrite a row with the append-only triggers dropped.

        This is what an attacker with filesystem access does, and it is here so
        the demo and the tests can prove the chain catches it. It is the only
        code path in the package that can modify an entry, it is never reachable
        from the API, and it exists to be caught.
        """
        if not columns:
            raise StoreError("nothing to mutate")
        self._conn.execute("DROP TRIGGER IF EXISTS entries_no_update")
        try:
            assignments = ", ".join(f"{k} = ?" for k in columns)
            self._conn.execute(
                f"UPDATE entries SET {assignments} WHERE seq = ?", [*columns.values(), seq]
            )
        finally:
            self._conn.executescript(
                "CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries "
                "BEGIN SELECT RAISE(ABORT, 'audit entries are append-only: "
                "UPDATE is not permitted'); END;"
            )

    def force_delete(self, seq: int) -> None:
        """Delete a row with the triggers dropped. Same rationale as above."""
        self._conn.execute("DROP TRIGGER IF EXISTS entries_no_delete")
        try:
            self._conn.execute("DELETE FROM entries WHERE seq = ?", (seq,))
        finally:
            self._conn.executescript(
                "CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries "
                "BEGIN SELECT RAISE(ABORT, 'audit entries are append-only: "
                "DELETE is not permitted'); END;"
            )


def _row_to_entry(row: sqlite3.Row) -> Entry:
    return Entry(
        seq=row["seq"],
        timestamp=row["timestamp"],
        actor=row["actor"],
        action=row["action"],
        resource=row["resource"],
        outcome=row["outcome"],
        payload=json.loads(row["payload"]),
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
        signature=row["signature"],
        key_id=row["key_id"],
        version=row["version"],
    )
