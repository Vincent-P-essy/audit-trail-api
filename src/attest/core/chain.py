"""The hash chain: what an entry is, and how each one binds to the one before it.

Every entry commits to its predecessor, so changing entry 40 changes its hash,
which invalidates entry 41's ``prev_hash``, and so on to the head. An attacker
who edits one row has to recompute every row after it — and cannot, without the
signing key.

**What a chain alone cannot detect, stated up front:** truncation. Deleting the
last N entries leaves a chain that verifies perfectly; it is simply shorter. No
amount of hashing fixes this, because the evidence that those entries existed
was in the entries themselves. The only defence is committing the head to
somewhere the operator does not control — which is what :mod:`attest.core.anchor`
does, and the honest reason checkpoints exist rather than being decoration.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import canonical

UTC = timezone.utc

#: Hash of the notional entry before the first one. Any 32-byte constant works;
#: what matters is that it is fixed and documented, so two implementations
#: derive the same chain from the same events.
GENESIS_HASH = "0" * 64

#: Bumped if the hashed field set ever changes. Recorded on every entry so a
#: verifier can refuse a chain it does not know how to re-derive, rather than
#: computing a different hash and reporting tampering.
CHAIN_VERSION = 1


def now_iso() -> str:
    """UTC, second precision, always with an offset.

    Naive timestamps in an audit trail are a defect: they cannot be ordered
    against anything else and cannot be defended to an auditor.
    """
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Entry:
    """One immutable event in the trail."""

    seq: int
    timestamp: str
    actor: str
    action: str
    resource: str
    outcome: str
    payload: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""
    signature: str = ""
    key_id: str = ""
    version: int = CHAIN_VERSION

    def __post_init__(self) -> None:
        if self.seq < 1:
            raise ValueError("sequence numbers start at 1")
        for name in ("actor", "action", "resource", "outcome"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")

    @property
    def payload_hash(self) -> str:
        return canonical.digest(self.payload)

    def hashable(self) -> dict[str, Any]:
        """Exactly the fields the entry hash commits to.

        The signature is excluded (it is computed over the hash), and so is
        anything a later migration might add — a verifier reconstructs this
        dict from stored columns, so adding a field here without bumping
        ``CHAIN_VERSION`` would silently invalidate every historical entry.
        """
        return {
            "version": self.version,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "payload_hash": self.payload_hash,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return canonical.digest(self.hashable())

    def with_hash(self) -> Entry:
        return replace_entry(self, entry_hash=self.compute_hash())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.hashable(),
            "payload": self.payload,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


def replace_entry(entry: Entry, **changes: Any) -> Entry:
    from dataclasses import replace

    return replace(entry, **changes)


def build(
    seq: int,
    prev_hash: str,
    actor: str,
    action: str,
    resource: str,
    outcome: str = "success",
    payload: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> Entry:
    """Build the next entry in a chain, hashed but not yet signed."""
    entry = Entry(
        seq=seq,
        timestamp=timestamp or now_iso(),
        actor=actor,
        action=action,
        resource=resource,
        outcome=outcome,
        payload=payload or {},
        prev_hash=prev_hash,
    )
    return entry.with_hash()


def head_hash(entries: list[Entry]) -> str:
    return entries[-1].entry_hash if entries else GENESIS_HASH


def merkle_root(hashes: list[str]) -> str:
    """Merkle root over entry hashes, for compact checkpoint commitments.

    A checkpoint could just record the head hash, and the chain would still be
    verifiable end to end. The root is recorded as well because it supports
    *inclusion proofs*: proving one entry was covered by a checkpoint without
    handing the verifier the whole log. In a regulated setting that is the
    difference between answering one question and disclosing the entire trail.

    Odd nodes are promoted rather than duplicated - duplicating the last node
    is the classic CVE-2012-2459 shape, where two different trees produce the
    same root.
    """
    if not hashes:
        return GENESIS_HASH

    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2:
            nxt.append(level[-1])  # promote, never duplicate
        level = nxt
    return level[0].hex()
