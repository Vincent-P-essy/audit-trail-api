"""Signing and key management.

Hashing makes the trail tamper-*evident*: anyone can recompute the chain and see
that it no longer lines up. It does not stop anyone from rewriting history
wholesale, because recomputing a chain is something anybody can do. Signatures
are what force the attacker to hold the key as well as the database.

Ed25519 rather than RSA or ECDSA: deterministic (no per-signature nonce to leak
a key through, which is how PS3 and several Bitcoin wallets lost theirs), small
signatures, no parameter choices to get wrong, and no need for a good random
source at signing time.

**Key rotation is designed in, not bolted on.** An audit trail outlives its
keys. Every entry records the ``key_id`` that signed it, and the keyring keeps
retired public keys forever, so an entry signed in 2026 still verifies in 2031
after two rotations. A system that cannot verify its own history after a key
rotation has an audit trail with an expiry date.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import digest_bytes

UTC = timezone.utc


class SigningError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair with a content-derived identifier."""

    key_id: str
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    created_at: str

    @classmethod
    def generate(cls) -> KeyPair:
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        return cls(
            key_id=derive_key_id(public),
            private=private,
            public=public,
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )

    def sign(self, message: bytes) -> str:
        return _b64(self.private.sign(message))

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def save(self, path: str | Path, passphrase: bytes | None = None) -> Path:
        """Write the private key as PKCS#8 PEM, 0600.

        Encryption is optional and off by default because the common
        deployment puts this behind a KMS or a mounted secret rather than a
        passphrase - but leaving it unencrypted *and* world-readable is the
        failure that actually happens, so the mode is set explicitly.
        """
        enc = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        pem = self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        out = Path(path)
        out.write_bytes(pem)
        out.chmod(0o600)
        return out

    @classmethod
    def load(cls, path: str | Path, passphrase: bytes | None = None) -> KeyPair:
        data = Path(path).read_bytes()
        private = serialization.load_pem_private_key(data, password=passphrase)
        if not isinstance(private, Ed25519PrivateKey):
            raise SigningError(
                f"{path}: expected an Ed25519 private key, got {type(private).__name__}"
            )
        public = private.public_key()
        return cls(
            key_id=derive_key_id(public),
            private=private,
            public=public,
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )


def derive_key_id(public: Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256 over the raw public key.

    Derived rather than assigned so two operators importing the same key
    independently agree on its identifier without coordinating.
    """
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return digest_bytes(raw)[:16]


class KeyRing:
    """Public keys, including retired ones, indexed by key id.

    Retired keys are never removed. Verification of a 2026 entry must still
    work in 2031, and an audit trail you cannot verify after rotating a key is
    an audit trail with an expiry date.
    """

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._meta: dict[str, dict[str, str]] = {}

    def add(self, public: Ed25519PublicKey, *, retired_at: str | None = None) -> str:
        key_id = derive_key_id(public)
        self._keys[key_id] = public
        self._meta[key_id] = {
            "key_id": key_id,
            "public_key": _b64(
                public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            "retired_at": retired_at or "",
        }
        return key_id

    def add_keypair(self, keypair: KeyPair) -> str:
        return self.add(keypair.public)

    def retire(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise SigningError(f"unknown key id {key_id!r}")
        self._meta[key_id]["retired_at"] = datetime.now(UTC).isoformat(timespec="seconds")

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def ids(self) -> list[str]:
        return sorted(self._keys)

    def verify(self, key_id: str, message: bytes, signature: str) -> bool:
        public = self._keys.get(key_id)
        if public is None:
            raise SigningError(f"no public key for key id {key_id!r}")
        try:
            public.verify(_unb64(signature), message)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    def to_json(self) -> str:
        return json.dumps({"keys": list(self._meta.values())}, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> KeyRing:
        ring = cls()
        for record in json.loads(text).get("keys", []):
            public = Ed25519PublicKey.from_public_bytes(_unb64(record["public_key"]))
            ring.add(public, retired_at=record.get("retired_at") or None)
        return ring

    def save(self, path: str | Path) -> Path:
        out = Path(path)
        out.write_text(self.to_json(), encoding="utf-8")
        return out

    @classmethod
    def load(cls, path: str | Path) -> KeyRing:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))
