"""Checkpoints: committing the chain head somewhere the operator cannot reach.

A checkpoint records `(sequence, head hash, Merkle root)`, signs it, and gets it
timestamped by an external authority. It is the only mechanism in this system
that survives an operator who controls both the database and the signing key,
because the TSA's signature is not theirs to forge.

Cadence is a trade. Checkpoint every entry and you pay a network round trip per
write; checkpoint daily and an attacker can delete anything written since the
last one. `every_n_entries` and `max_age` exist so the window is a decision
someone made on purpose rather than whatever the default happened to be.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from . import canonical, rfc3161
from .chain import merkle_root
from .signing import KeyPair
from .store import Store

UTC = timezone.utc


@dataclass
class AnchorPolicy:
    """When to cut a checkpoint.

    The gap between checkpoints is the window in which entries can be silently
    deleted from the end of the trail. Pick it against how much loss is
    tolerable, not against how chatty the TSA is.
    """

    every_n_entries: int = 100
    max_age: timedelta = timedelta(hours=24)

    def due(
        self, entries_since: int, last_at: datetime | None, now: datetime | None = None
    ) -> bool:
        if entries_since <= 0:
            return False
        if entries_since >= self.every_n_entries:
            return True
        if last_at is None:
            return True
        return (now or datetime.now(UTC)) - last_at >= self.max_age


def create_checkpoint(
    store: Store,
    signer: KeyPair,
    *,
    tsa_url: str | None = None,
    local_fallback: bool = True,
) -> dict[str, Any]:
    """Cut, sign and (where possible) externally timestamp a checkpoint."""
    head_seq, head_hash = store.head()
    if head_seq == 0:
        raise ValueError("nothing to checkpoint: the trail is empty")

    hashes = [entry.entry_hash for entry in store.entries()]
    root = merkle_root(hashes)
    created_at = datetime.now(UTC).isoformat(timespec="seconds")

    # Signed over the canonical encoding of exactly these four fields, so a
    # verifier reconstructs the same bytes from the stored row.
    body = {
        "covers_to_seq": head_seq,
        "created_at": created_at,
        "head_hash": head_hash,
        "merkle_root": root,
    }
    signature = signer.sign(canonical.encode(body))

    checkpoint: dict[str, Any] = {
        **body,
        "signature": signature,
        "key_id": signer.key_id,
        "tsa_token": None,
        "tsa_time": None,
        "tsa_authority": None,
    }

    # The digest handed to the TSA covers the whole signed body, not just the
    # head hash - otherwise the timestamp would cover a hash without covering
    # which sequence number it claims to be.
    digest = bytes.fromhex(canonical.digest(body))

    stamped = None
    if tsa_url:
        try:
            stamped = rfc3161.request_timestamp(digest, tsa_url)
        except rfc3161.TimestampError as exc:
            # A failed anchor is recorded, never silently skipped: an
            # un-anchored checkpoint proves nothing to a third party, and the
            # operator needs to know the window is still open.
            checkpoint["tsa_authority"] = f"failed: {exc}"

    if stamped is None and local_fallback:
        stamped = rfc3161.LocalAuthority().stamp(digest)

    if stamped:
        checkpoint["tsa_token"] = stamped["token"]
        checkpoint["tsa_time"] = stamped["gen_time"]
        checkpoint["tsa_authority"] = stamped["authority"]

    store.add_checkpoint(checkpoint)
    return checkpoint


def is_externally_anchored(checkpoint: dict[str, Any]) -> bool:
    """True only for a checkpoint dated by an actual third party."""
    authority = checkpoint.get("tsa_authority") or ""
    return bool(checkpoint.get("tsa_token")) and not authority.startswith(("local:", "failed:"))


def unanchored_window(store: Store) -> int:
    """Entries written since the last checkpoint — the truncation exposure.

    This is the number to put on a dashboard. It is exactly how many entries an
    attacker with database access could delete right now without any check in
    this system noticing.
    """
    head_seq, _ = store.head()
    latest = store.latest_checkpoint()
    covered = latest["covers_to_seq"] if latest else 0
    # Clamped at zero: a head *behind* its checkpoint is truncation, not a
    # negative window, and the verifier reports it as such. Letting a negative
    # number reach a dashboard would read as "safer than fully anchored".
    return max(0, head_seq - covered)
