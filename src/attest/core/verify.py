"""Verification: prove the trail is intact, or say precisely where it isn't.

A verifier that returns a boolean is not much use to an auditor. "The log is
invalid" invites the answer "it must be a bug in your tool"; "entry 41 claims a
predecessor hash that does not match entry 40, and entry 41's own signature is
still valid, so the tampering is at entry 40" does not.

Five independent checks run over every entry, and each failure is reported with
the sequence number, the expected value, the value found, and — critically —
what that combination *implies*, because the pattern of which checks fail is
what localises the attack:

| Symptom | What it means |
| --- | --- |
| hash mismatch on entry N | entry N's own fields were edited |
| link break at N, N's hash valid | entry N-1 was edited, or an entry was removed between them |
| sequence gap | entries were deleted from the middle |
| signature invalid | entry was forged, or signed by a key not in the ring |
| head behind a checkpoint | the tail was truncated |

That last one is the only check that catches truncation, and it only works
because a checkpoint was anchored somewhere the operator does not control.
Without checkpoints, deleting the newest entries is undetectable — the chain
that remains is perfectly valid, just shorter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import canonical
from .chain import GENESIS_HASH, Entry, merkle_root
from .signing import KeyRing, SigningError


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    """One thing wrong with the trail."""

    seq: int | None
    check: str
    severity: Severity
    detail: str
    implication: str
    expected: str = ""
    found: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "check": self.check,
            "severity": self.severity.value,
            "detail": self.detail,
            "implication": self.implication,
            "expected": self.expected,
            "found": self.found,
        }


@dataclass
class VerificationReport:
    entries_checked: int = 0
    signatures_checked: int = 0
    checkpoints_checked: int = 0
    findings: list[Finding] = field(default_factory=list)
    head_seq: int = 0
    head_hash: str = GENESIS_HASH

    @property
    def intact(self) -> bool:
        return not self.findings

    @property
    def first_break(self) -> Finding | None:
        broken = [f for f in self.findings if f.seq is not None]
        return min(broken, key=lambda f: f.seq or 0) if broken else None

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "entries_checked": self.entries_checked,
            "signatures_checked": self.signatures_checked,
            "checkpoints_checked": self.checkpoints_checked,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "findings": [f.to_dict() for f in self.findings],
        }


def verify_chain(
    entries: list[Entry],
    keyring: KeyRing | None = None,
    checkpoints: list[dict[str, Any]] | None = None,
    *,
    expect_signatures: bool = True,
) -> VerificationReport:
    """Verify a whole trail and report every problem found, not just the first."""
    report = VerificationReport(entries_checked=len(entries))
    if not entries:
        return report

    ordered = sorted(entries, key=lambda e: e.seq)
    report.head_seq = ordered[-1].seq
    report.head_hash = ordered[-1].entry_hash

    expected_prev = GENESIS_HASH
    expected_seq = 1

    for entry in ordered:
        # 1. Sequence continuity. A gap means entries were removed from the
        #    middle; the chain link check below will usually also fire, but the
        #    gap is what tells you how many went missing.
        if entry.seq != expected_seq:
            report.findings.append(
                Finding(
                    seq=entry.seq,
                    check="sequence",
                    severity=Severity.CRITICAL,
                    detail=f"expected sequence {expected_seq}, found {entry.seq}",
                    implication=(
                        f"{entry.seq - expected_seq} entr"
                        f"{'y was' if entry.seq - expected_seq == 1 else 'ies were'} "
                        "removed from the middle of the trail"
                    ),
                    expected=str(expected_seq),
                    found=str(entry.seq),
                )
            )
        expected_seq = entry.seq + 1

        # 2. The entry's own integrity: does its hash match its contents?
        recomputed = entry.compute_hash()
        own_hash_ok = recomputed == entry.entry_hash
        if not own_hash_ok:
            report.findings.append(
                Finding(
                    seq=entry.seq,
                    check="entry_hash",
                    severity=Severity.CRITICAL,
                    detail="stored hash does not match the entry's contents",
                    implication="this entry's fields were edited after it was written",
                    expected=recomputed[:16] + "...",
                    found=entry.entry_hash[:16] + "...",
                )
            )

        # 3. The link to the predecessor.
        if entry.prev_hash != expected_prev:
            report.findings.append(
                Finding(
                    seq=entry.seq,
                    check="chain_link",
                    severity=Severity.CRITICAL,
                    detail="prev_hash does not match the previous entry's hash",
                    implication=(
                        "entry "
                        f"{entry.seq - 1} was edited or removed"
                        if own_hash_ok
                        else "the trail was rewritten around this point"
                    ),
                    expected=expected_prev[:16] + "...",
                    found=entry.prev_hash[:16] + "...",
                )
            )
        expected_prev = entry.entry_hash

        # 4. The signature, which is what forces an attacker to hold the key.
        if expect_signatures:
            if not entry.signature or not entry.key_id:
                report.findings.append(
                    Finding(
                        seq=entry.seq,
                        check="signature",
                        severity=Severity.HIGH,
                        detail="entry carries no signature",
                        implication="anyone able to write to the store could have produced it",
                    )
                )
            elif keyring is not None:
                report.signatures_checked += 1
                try:
                    valid = keyring.verify(
                        entry.key_id, bytes.fromhex(entry.entry_hash), entry.signature
                    )
                except SigningError:
                    report.findings.append(
                        Finding(
                            seq=entry.seq,
                            check="signature",
                            severity=Severity.CRITICAL,
                            detail=f"signed by unknown key {entry.key_id!r}",
                            implication=(
                                "the entry was signed outside this system, or a "
                                "retired key was dropped from the keyring"
                            ),
                        )
                    )
                else:
                    if not valid:
                        report.findings.append(
                            Finding(
                                seq=entry.seq,
                                check="signature",
                                severity=Severity.CRITICAL,
                                detail="signature does not verify against the recorded key",
                                implication="the entry was forged or altered after signing",
                            )
                        )

    if checkpoints:
        _verify_checkpoints(ordered, checkpoints, keyring, report)

    return report


def _verify_checkpoints(
    ordered: list[Entry],
    checkpoints: list[dict[str, Any]],
    keyring: KeyRing | None,
    report: VerificationReport,
) -> None:
    """Compare the trail against its external commitments.

    This is the only check that catches truncation, because it is the only one
    with information the operator could not have destroyed by deleting rows.
    """
    by_seq = {entry.seq: entry for entry in ordered}
    head_seq = ordered[-1].seq if ordered else 0

    for checkpoint in sorted(checkpoints, key=lambda c: c["covers_to_seq"]):
        report.checkpoints_checked += 1
        covers = checkpoint["covers_to_seq"]

        if covers > head_seq:
            report.findings.append(
                Finding(
                    seq=covers,
                    check="truncation",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"a checkpoint commits to sequence {covers}, but the trail "
                        f"ends at {head_seq}"
                    ),
                    implication=(
                        f"{covers - head_seq} entries were deleted from the end of the "
                        "trail - a hash chain alone cannot detect this, which is why "
                        "the checkpoint exists"
                    ),
                    expected=f"head >= {covers}",
                    found=f"head = {head_seq}",
                )
            )
            continue

        entry = by_seq.get(covers)
        if entry is None:
            report.findings.append(
                Finding(
                    seq=covers,
                    check="checkpoint",
                    severity=Severity.CRITICAL,
                    detail=f"entry {covers} named by a checkpoint is missing",
                    implication="the entry the checkpoint commits to was deleted",
                )
            )
            continue

        if entry.entry_hash != checkpoint["head_hash"]:
            report.findings.append(
                Finding(
                    seq=covers,
                    check="checkpoint",
                    severity=Severity.CRITICAL,
                    detail="entry hash differs from the hash the checkpoint committed to",
                    implication=(
                        "the trail was rewritten after this checkpoint was anchored; "
                        "the checkpoint is the trustworthy side of this comparison"
                    ),
                    expected=checkpoint["head_hash"][:16] + "...",
                    found=entry.entry_hash[:16] + "...",
                )
            )

        covered = [e.entry_hash for e in ordered if e.seq <= covers]
        root = merkle_root(covered)
        if root != checkpoint["merkle_root"]:
            report.findings.append(
                Finding(
                    seq=covers,
                    check="merkle_root",
                    severity=Severity.CRITICAL,
                    detail="recomputed Merkle root differs from the checkpoint's",
                    implication="at least one entry at or before this point was altered",
                    expected=checkpoint["merkle_root"][:16] + "...",
                    found=root[:16] + "...",
                )
            )

        if keyring is not None and checkpoint.get("signature"):
            message = canonical.encode(
                {
                    "covers_to_seq": covers,
                    "created_at": checkpoint["created_at"],
                    "head_hash": checkpoint["head_hash"],
                    "merkle_root": checkpoint["merkle_root"],
                }
            )
            try:
                if not keyring.verify(checkpoint["key_id"], message, checkpoint["signature"]):
                    report.findings.append(
                        Finding(
                            seq=covers,
                            check="checkpoint_signature",
                            severity=Severity.CRITICAL,
                            detail="checkpoint signature does not verify",
                            implication="the checkpoint itself was forged or altered",
                        )
                    )
            except SigningError:
                report.findings.append(
                    Finding(
                        seq=covers,
                        check="checkpoint_signature",
                        severity=Severity.HIGH,
                        detail=f"checkpoint signed by unknown key {checkpoint['key_id']!r}",
                        implication=(
                            "the signing key is not in the keyring given to the verifier"
                        ),
                    )
                )

        if not checkpoint.get("tsa_token"):
            report.findings.append(
                Finding(
                    seq=covers,
                    check="anchoring",
                    severity=Severity.WARNING,
                    detail="checkpoint has no RFC 3161 timestamp token",
                    implication=(
                        "the checkpoint proves nothing to a third party: it was signed "
                        "with a key the operator controls, so its date rests on the "
                        "operator's word"
                    ),
                )
            )
