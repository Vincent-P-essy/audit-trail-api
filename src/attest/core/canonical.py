"""Canonical serialisation.

A hash chain over JSON is only as trustworthy as the bytes that get hashed. If
``{"a":1,"b":2}`` and ``{"b": 2, "a": 1}`` hash differently, then re-serialising
an event with a different library — or a different Python minor version, or a
different key insertion order — produces a verification failure that looks
exactly like tampering. Teams then learn to ignore verification failures, which
is worse than not having verification.

So the bytes are pinned here, once, and every hash in the system goes through
this module:

- keys sorted, so insertion order cannot matter
- no insignificant whitespace
- UTF-8 with no ASCII escaping, so the same string is the same bytes
- floats and NaN/Infinity rejected outright

The float rule is the one that surprises people. ``0.1 + 0.2`` does not
round-trip through JSON identically on every platform, and IEEE-754 repr rules
have changed between Python versions. A monetary amount stored as a float is a
verification failure waiting for a platform upgrade, so amounts belong in
integer minor units or in strings, and this module refuses to hash anything
else rather than letting the problem surface years later in an audit.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalisationError(ValueError):
    """Raised when a payload cannot be canonically serialised."""


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise CanonicalisationError(
            f"{path}: float values cannot be canonically hashed - their JSON "
            "representation is not stable across platforms. Use an integer in "
            "minor units (cents) or a string."
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(f"{path}: object keys must be strings, got {key!r}")
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


def dumps(payload: Any) -> str:
    """Serialise ``payload`` to the one string this system will ever hash."""
    _reject_floats(payload)
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalisationError(f"payload is not JSON-serialisable: {exc}") from exc


def encode(payload: Any) -> bytes:
    return dumps(payload).encode("utf-8")


def digest(payload: Any) -> str:
    """SHA-256 of the canonical encoding, lowercase hex."""
    return hashlib.sha256(encode(payload)).hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
