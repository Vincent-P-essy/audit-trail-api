"""RFC 3161 timestamping: getting a third party to date the chain head.

A signed checkpoint proves the operator committed to a head hash. It does not
prove *when*, because the operator holds the signing key and controls the clock.
An operator who rewrites history and re-signs every checkpoint produces
something internally consistent and completely worthless.

An RFC 3161 Time-Stamp Authority breaks that circularity: it signs
`(hash, its own time)` with a key the operator does not have. Backdating then
requires the TSA's key rather than the operator's.

This module builds the request and parses the response itself, in DER, rather
than shelling out to `openssl ts`. It is about 120 lines and removes a runtime
dependency from the deployment.

**Scope, stated honestly.** The imprint in the returned token is verified
against the digest that was sent — that is the check that catches a token
belonging to different data. Verifying the *TSA's own signature* on the token
requires validating a CMS SignedData structure against the TSA's certificate
chain and a trust store, which is a policy decision (whose TSAs do you trust?)
rather than a coding one. The full token is therefore stored verbatim so an
auditor can validate it with their own trusted roots and `openssl ts -verify`,
and :func:`inspect_token` reports what it did and did not check rather than
returning a bare "valid".
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

UTC = timezone.utc

#: 2.16.840.1.101.3.4.2.1
OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_GENERALIZED_TIME = 0x18

PKI_STATUS = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}


class TimestampError(RuntimeError):
    pass


# -- DER encoding -----------------------------------------------------------


def _length(n: int) -> bytes:
    """DER length: short form under 128, long form above."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def der_integer(value: int) -> bytes:
    if value == 0:
        return _tlv(TAG_INTEGER, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    # DER integers are signed; a leading bit of 1 would read as negative.
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(TAG_INTEGER, body)


def der_octet_string(value: bytes) -> bytes:
    return _tlv(TAG_OCTET_STRING, value)


def der_boolean(value: bool) -> bytes:
    return _tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def der_null() -> bytes:
    return _tlv(TAG_NULL, b"")


def der_oid(arcs: tuple[int, ...]) -> bytes:
    """Encode an OID: first two arcs are packed into one byte, rest base-128."""
    if len(arcs) < 2:
        raise TimestampError("an OID needs at least two arcs")
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        body += chunk
    return _tlv(TAG_OID, bytes(body))


def der_sequence(*parts: bytes) -> bytes:
    return _tlv(TAG_SEQUENCE, b"".join(parts))


def build_request(digest: bytes, *, nonce: int | None = None, cert_req: bool = True) -> bytes:
    """Build a DER-encoded ``TimeStampReq`` for a SHA-256 digest.

        TimeStampReq ::= SEQUENCE {
            version         INTEGER { v1(1) },
            messageImprint  MessageImprint,
            reqPolicy       TSAPolicyId OPTIONAL,
            nonce           INTEGER OPTIONAL,
            certReq         BOOLEAN DEFAULT FALSE }

    The nonce is not optional in practice: without it a network attacker can
    replay an old response, and the timestamp you record is whatever date they
    choose to hand you.
    """
    if len(digest) != 32:
        raise TimestampError(f"expected a 32-byte SHA-256 digest, got {len(digest)} bytes")

    nonce = secrets.randbits(64) if nonce is None else nonce
    message_imprint = der_sequence(
        der_sequence(der_oid(OID_SHA256), der_null()),
        der_octet_string(digest),
    )
    return der_sequence(
        der_integer(1),
        message_imprint,
        der_integer(nonce),
        der_boolean(cert_req),
    )


# -- DER parsing ------------------------------------------------------------


@dataclass
class DerNode:
    tag: int
    value: bytes
    children: list[DerNode]

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def _parse_one(data: bytes, offset: int) -> tuple[DerNode, int]:
    if offset + 2 > len(data):
        raise TimestampError("truncated DER")
    tag = data[offset]
    first = data[offset + 1]
    offset += 2

    if first & 0x80:
        n = first & 0x7F
        if n == 0 or offset + n > len(data):
            raise TimestampError("unsupported or truncated DER length")
        length = int.from_bytes(data[offset : offset + n], "big")
        offset += n
    else:
        length = first

    end = offset + length
    if end > len(data):
        raise TimestampError("DER length runs past the end of the buffer")
    value = data[offset:end]

    children: list[DerNode] = []
    constructed = bool(tag & 0x20)
    if constructed:
        inner = offset
        while inner < end:
            try:
                child, inner = _parse_one(data, inner)
            except TimestampError:
                children = []
                break
            children.append(child)

    return DerNode(tag=tag, value=value, children=children), end


def parse_der(data: bytes) -> DerNode:
    node, _ = _parse_one(data, 0)
    return node


def parse_response(data: bytes) -> tuple[int, str, bytes | None]:
    """Split a ``TimeStampResp`` into ``(status, status name, token DER)``.

        TimeStampResp ::= SEQUENCE {
            status          PKIStatusInfo,
            timeStampToken  TimeStampToken OPTIONAL }
    """
    root = parse_der(data)
    if root.tag != TAG_SEQUENCE or not root.children:
        raise TimestampError("response is not a TimeStampResp SEQUENCE")

    status_info = root.children[0]
    if not status_info.children or status_info.children[0].tag != TAG_INTEGER:
        raise TimestampError("response carries no PKIStatus")
    status = int.from_bytes(status_info.children[0].value, "big")
    name = PKI_STATUS.get(status, f"unknown({status})")

    token = None
    if len(root.children) > 1:
        child = root.children[1]
        token = bytes([child.tag]) + _length(len(child.value)) + child.value
    return status, name, token


def inspect_token(token: bytes, expected_digest: bytes) -> dict[str, Any]:
    """Report what the token says, and what was and was not verified.

    Deliberately does not return a bare boolean: the imprint check is real, the
    TSA signature check is not performed here, and collapsing both into "valid"
    would overstate what this function knows.
    """
    root = parse_der(token)
    times: list[str] = []
    for node in root.walk():
        if node.tag == TAG_GENERALIZED_TIME:
            try:
                times.append(node.value.decode("ascii"))
            except UnicodeDecodeError:
                continue

    imprint_present = expected_digest in token

    gen_time = ""
    if times:
        raw = times[0].rstrip("Z")
        for fmt in ("%Y%m%d%H%M%S.%f", "%Y%m%d%H%M%S"):
            try:
                gen_time = (
                    datetime.strptime(raw, fmt).replace(tzinfo=UTC).isoformat(timespec="seconds")
                )
                break
            except ValueError:
                continue
        else:
            gen_time = times[0]

    return {
        "imprint_matches": imprint_present,
        "gen_time": gen_time,
        "token_bytes": len(token),
        "checked": ["message imprint matches the submitted digest", "genTime extracted"],
        "not_checked": [
            "the TSA's CMS signature over the token (needs the TSA certificate "
            "chain and a trust store — validate with `openssl ts -verify`)"
        ],
    }


# -- authorities ------------------------------------------------------------

#: Public, free, no registration. Used by the CLI's --tsa flag.
FREE_TSA_URL = "https://freetsa.org/tsr"


def request_timestamp(digest: bytes, url: str = FREE_TSA_URL, timeout: float = 20.0) -> dict:
    """Ask a real TSA to date ``digest``. Requires network access."""
    import urllib.error
    import urllib.request

    nonce = secrets.randbits(64)
    body = build_request(digest, nonce=nonce)
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except (urllib.error.URLError, OSError) as exc:
        raise TimestampError(f"could not reach the TSA at {url}: {exc}") from exc

    status, name, token = parse_response(payload)
    if status not in (0, 1) or token is None:
        raise TimestampError(f"the TSA refused to timestamp: {name}")

    info = inspect_token(token, digest)
    if not info["imprint_matches"]:
        # A token for a different digest is worse than no token: it looks like
        # evidence and proves nothing about this chain.
        raise TimestampError("the returned token does not cover the digest that was sent")

    return {
        "authority": url,
        "token": token.hex(),
        "gen_time": info["gen_time"],
        "status": name,
    }


class LocalAuthority:
    """An offline stand-in so tests and demos do not need the network.

    It is **not** a third party. It signs with a key generated in this process,
    so it proves the token was produced by something holding that key and
    nothing about the date. Every checkpoint it produces is labelled
    ``local:offline`` so a reader cannot mistake it for real anchoring, and the
    verifier treats a checkpoint without a real TSA token as a warning.
    """

    authority = "local:offline"

    def __init__(self) -> None:
        from .signing import KeyPair

        self._key = KeyPair.generate()

    def stamp(self, digest: bytes) -> dict:
        import base64

        now = datetime.now(UTC)
        signature = base64.b64decode(self._key.sign(digest))
        token = der_sequence(
            der_integer(1),
            der_octet_string(digest),
            _tlv(TAG_GENERALIZED_TIME, now.strftime("%Y%m%d%H%M%SZ").encode("ascii")),
            der_octet_string(signature),
        )
        return {
            "authority": self.authority,
            "token": token.hex(),
            "gen_time": now.isoformat(timespec="seconds"),
            "status": "granted (local, not a third party)",
        }


def authority_from_env() -> str | None:
    """TSA URL from ``ATTEST_TSA_URL``, if the deployment sets one."""
    return os.environ.get("ATTEST_TSA_URL") or None
