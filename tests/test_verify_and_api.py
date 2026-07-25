"""Detection of every tampering shape, and the HTTP surface."""

from __future__ import annotations

import json

import pytest

from attest.api.app import create_app
from attest.core.anchor import (
    AnchorPolicy,
    create_checkpoint,
    is_externally_anchored,
    unanchored_window,
)
from attest.core.rfc3161 import (
    TimestampError,
    build_request,
    der_integer,
    der_oid,
    inspect_token,
    parse_der,
    parse_response,
)
from attest.core.signing import KeyPair, KeyRing
from attest.core.store import Store
from attest.core.verify import Severity, verify_chain


@pytest.fixture
def trail():
    keypair = KeyPair.generate()
    ring = KeyRing()
    ring.add_keypair(keypair)
    store = Store()
    for i in range(6):
        store.append("m.dubois", "payment.approve", f"PAY-{i}", payload={"n": i}, signer=keypair)
    return store, keypair, ring


class TestDetection:
    def test_clean_trail_verifies(self, trail):
        store, _, ring = trail
        report = verify_chain(store.entries(), ring)
        assert report.intact
        assert report.signatures_checked == 6

    def test_edited_field_is_caught_and_localised(self, trail):
        store, _, ring = trail
        store.force_mutate(3, actor="attacker")
        report = verify_chain(store.entries(), ring)
        assert not report.intact
        assert report.first_break.seq == 3
        assert report.first_break.check == "entry_hash"
        assert "edited" in report.first_break.implication

    def test_a_thorough_attacker_who_rehashes_breaks_the_next_link(self, trail):
        # Recomputing the tampered entry's own hash fixes that check and breaks
        # the following entry's link instead - which is the point of chaining.
        store, _, ring = trail
        entry = store.get(3)
        from dataclasses import replace

        forged = replace(entry, actor="attacker")
        store.force_mutate(3, actor="attacker", entry_hash=forged.compute_hash())
        report = verify_chain(store.entries(), ring)
        checks = {(f.seq, f.check) for f in report.findings}
        assert (4, "chain_link") in checks
        # ...and the signature no longer matches the new hash.
        assert (3, "signature") in checks

    def test_deleted_middle_entry_leaves_a_gap_and_a_broken_link(self, trail):
        store, _, ring = trail
        store.force_delete(3)
        report = verify_chain(store.entries(), ring)
        checks = {f.check for f in report.findings}
        assert "sequence" in checks
        assert "chain_link" in checks

    def test_truncation_is_invisible_without_a_checkpoint(self, trail):
        # The honest limitation: a shorter chain is still a valid chain.
        store, _, ring = trail
        store.force_delete(6)
        store.force_delete(5)
        assert verify_chain(store.entries(), ring).intact

    def test_truncation_is_caught_with_a_checkpoint(self, trail):
        store, keypair, ring = trail
        create_checkpoint(store, keypair)
        store.force_delete(6)
        store.force_delete(5)
        report = verify_chain(store.entries(), ring, store.checkpoints())
        assert not report.intact
        finding = next(f for f in report.findings if f.check == "truncation")
        assert "2 entries were deleted" in finding.implication

    def test_forged_signature_is_caught(self, trail):
        store, _, ring = trail
        other = KeyPair.generate()
        store.force_mutate(2, signature=other.sign(bytes.fromhex(store.get(2).entry_hash)))
        report = verify_chain(store.entries(), ring)
        assert any(f.check == "signature" for f in report.findings)

    def test_signature_from_a_key_outside_the_ring_is_caught(self, trail):
        store, _, ring = trail
        rogue = KeyPair.generate()
        store.force_mutate(2, key_id=rogue.key_id)
        report = verify_chain(store.entries(), ring)
        finding = next(f for f in report.findings if f.check == "signature")
        assert "unknown key" in finding.detail

    def test_unsigned_entries_are_flagged(self):
        store = Store()
        for i in range(3):
            store.append("u", "a", f"r{i}")
        report = verify_chain(store.entries(), KeyRing())
        assert all(f.check == "signature" for f in report.findings)
        assert all(f.severity is Severity.HIGH for f in report.findings)

    def test_altered_entry_before_a_checkpoint_breaks_the_merkle_root(self, trail):
        # The Merkle root commits to entry *hashes*, so it only moves once the
        # attacker recomputes them. A lazy edit is caught by the entry_hash
        # check instead; this covers the thorough attacker.
        store, keypair, ring = trail
        create_checkpoint(store, keypair)
        from dataclasses import replace

        forged = replace(store.get(2), actor="attacker")
        store.force_mutate(2, actor="attacker", entry_hash=forged.compute_hash())
        report = verify_chain(store.entries(), ring, store.checkpoints())
        assert any(f.check == "merkle_root" for f in report.findings)

    def test_a_lazy_edit_before_a_checkpoint_is_caught_by_the_entry_hash(self, trail):
        store, keypair, ring = trail
        create_checkpoint(store, keypair)
        store.force_mutate(2, actor="attacker")
        report = verify_chain(store.entries(), ring, store.checkpoints())
        assert any(f.check == "entry_hash" and f.seq == 2 for f in report.findings)

    def test_forged_checkpoint_is_caught(self, trail):
        store, keypair, ring = trail
        create_checkpoint(store, keypair)
        checkpoints = store.checkpoints()
        checkpoints[0]["head_hash"] = "f" * 64
        report = verify_chain(store.entries(), ring, checkpoints)
        checks = {f.check for f in report.findings}
        assert "checkpoint" in checks or "checkpoint_signature" in checks

    def test_empty_trail_is_vacuously_intact(self):
        assert verify_chain([], KeyRing()).intact

    def test_report_serialises(self, trail):
        store, _, ring = trail
        body = verify_chain(store.entries(), ring).to_dict()
        assert body["intact"] and body["entries_checked"] == 6
        json.dumps(body)


class TestAnchoring:
    def test_checkpoint_covers_the_head(self, trail):
        store, keypair, _ = trail
        checkpoint = create_checkpoint(store, keypair)
        assert checkpoint["covers_to_seq"] == 6
        assert checkpoint["head_hash"] == store.head()[1]

    def test_local_authority_is_not_treated_as_external(self, trail):
        store, keypair, _ = trail
        checkpoint = create_checkpoint(store, keypair)
        assert checkpoint["tsa_token"]
        assert not is_externally_anchored(checkpoint)

    def test_unanchored_checkpoint_raises_a_warning(self, trail):
        store, keypair, ring = trail
        create_checkpoint(store, keypair, local_fallback=False)
        report = verify_chain(store.entries(), ring, store.checkpoints())
        assert any(f.check == "anchoring" and f.severity is Severity.WARNING
                   for f in report.findings)

    def test_unanchored_window(self, trail):
        store, keypair, _ = trail
        create_checkpoint(store, keypair)
        assert unanchored_window(store) == 0
        store.append("u", "a", "r", signer=keypair)
        assert unanchored_window(store) == 1

    def test_window_never_goes_negative(self, trail):
        store, keypair, _ = trail
        create_checkpoint(store, keypair)
        store.force_delete(6)
        assert unanchored_window(store) == 0

    def test_empty_trail_cannot_be_checkpointed(self):
        with pytest.raises(ValueError, match="empty"):
            create_checkpoint(Store(), KeyPair.generate())

    def test_policy_fires_on_count_and_age(self):
        from datetime import datetime, timedelta, timezone

        policy = AnchorPolicy(every_n_entries=10, max_age=timedelta(hours=1))
        now = datetime.now(timezone.utc)
        assert policy.due(10, now)
        assert not policy.due(0, now)
        assert not policy.due(3, now)
        assert policy.due(3, now - timedelta(hours=2), now)
        assert policy.due(1, None)


class TestRfc3161:
    def test_request_is_well_formed_der(self):
        digest = bytes(range(32))
        request = build_request(digest, nonce=12345)
        root = parse_der(request)
        assert root.tag == 0x30
        assert digest in request

    def test_request_rejects_a_wrong_length_digest(self):
        with pytest.raises(TimestampError, match="32-byte"):
            build_request(b"short")

    def test_integer_encoding_avoids_a_negative_reading(self):
        # DER integers are signed; a leading 1 bit needs a 0x00 pad.
        assert der_integer(0x80) == b"\x02\x02\x00\x80"
        assert der_integer(1) == b"\x02\x01\x01"
        assert der_integer(0) == b"\x02\x01\x00"

    def test_oid_encoding_matches_the_known_sha256_value(self):
        assert der_oid((2, 16, 840, 1, 101, 3, 4, 2, 1)).hex() == "0609608648016503040201"

    def test_long_form_lengths(self):
        request = build_request(bytes(32), nonce=2**63 - 1)
        assert parse_der(request).tag == 0x30

    def test_response_parsing_rejects_rubbish(self):
        with pytest.raises(TimestampError):
            parse_response(b"\x30\x82\xff\xff")

    def test_local_token_carries_the_imprint(self):
        from attest.core.rfc3161 import LocalAuthority

        digest = bytes(range(32))
        stamped = LocalAuthority().stamp(digest)
        info = inspect_token(bytes.fromhex(stamped["token"]), digest)
        assert info["imprint_matches"]
        assert info["gen_time"]
        assert info["not_checked"]  # the module never claims more than it verified

    def test_token_for_other_data_does_not_match(self):
        from attest.core.rfc3161 import LocalAuthority

        stamped = LocalAuthority().stamp(bytes(range(32)))
        info = inspect_token(bytes.fromhex(stamped["token"]), b"\xaa" * 32)
        assert not info["imprint_matches"]


class TestApi:
    @pytest.fixture
    def client(self):
        keypair = KeyPair.generate()
        app = create_app(Store(), keypair, write_tokens=set(), read_tokens=set())
        return app.test_client(), app

    def test_append_and_read_back(self, client):
        c, _ = client
        created = c.post(
            "/v1/events",
            json={"actor": "m.dubois", "action": "payment.approve", "resource": "PAY-1"},
        )
        assert created.status_code == 201
        seq = created.get_json()["seq"]
        assert c.get(f"/v1/events/{seq}").get_json()["actor"] == "m.dubois"

    def test_missing_fields(self, client):
        c, _ = client
        response = c.post("/v1/events", json={"actor": "x"})
        assert response.status_code == 400
        assert "action" in response.get_json()["error"]

    def test_float_payload_is_refused_with_an_actionable_hint(self, client):
        c, _ = client
        response = c.post(
            "/v1/events",
            json={"actor": "a", "action": "b", "resource": "c", "payload": {"amount": 1.5}},
        )
        assert response.status_code == 422
        assert "minor units" in response.get_json()["hint"]

    def test_non_object_payload(self, client):
        c, _ = client
        response = c.post(
            "/v1/events", json={"actor": "a", "action": "b", "resource": "c", "payload": [1]}
        )
        assert response.status_code == 400

    def test_there_is_no_delete(self, client):
        c, _ = client
        c.post("/v1/events", json={"actor": "a", "action": "b", "resource": "c"})
        response = c.delete("/v1/events/1")
        assert response.status_code == 405
        assert "append-only" in response.get_json()["detail"]

    def test_verify_returns_409_when_broken(self, client):
        c, app = client
        c.post("/v1/events", json={"actor": "a", "action": "b", "resource": "c"})
        assert c.get("/v1/verify").status_code == 200
        app.config["STORE"].force_mutate(1, actor="attacker")
        broken = c.get("/v1/verify")
        # A monitoring probe that only reads status codes must still notice.
        assert broken.status_code == 409
        assert broken.get_json()["findings"]

    def test_filters(self, client):
        c, _ = client
        for actor in ("alice", "bob", "alice"):
            c.post("/v1/events", json={"actor": actor, "action": "act", "resource": "r"})
        assert c.get("/v1/events?actor=alice").get_json()["count"] == 2

    def test_checkpoint_endpoint(self, client):
        c, _ = client
        c.post("/v1/events", json={"actor": "a", "action": "b", "resource": "c"})
        response = c.post("/v1/checkpoints")
        assert response.status_code == 201
        assert response.get_json()["covers_to_seq"] == 1
        assert c.get("/v1/checkpoints").get_json()["count"] == 1

    def test_checkpoint_on_empty_trail_is_a_conflict(self, client):
        c, _ = client
        assert c.post("/v1/checkpoints").status_code == 409

    def test_health(self, client):
        c, _ = client
        body = c.get("/health").get_json()
        assert body["status"] == "ok"
        assert "signing_key" in body

    def test_pdf_export(self, client):
        c, _ = client
        for i in range(3):
            c.post("/v1/events", json={"actor": "a", "action": "b", "resource": f"r{i}"})
        c.post("/v1/checkpoints")
        response = c.get("/v1/export/evidence.pdf")
        assert response.status_code == 200
        assert response.data.startswith(b"%PDF")
        assert len(response.data) > 3000

    def test_tokens_are_enforced_when_set(self):
        app = create_app(Store(), KeyPair.generate(), write_tokens={"w"}, read_tokens={"r"})
        c = app.test_client()
        assert c.post("/v1/events", json={"actor": "a", "action": "b", "resource": "c"}).status_code == 401
        ok = c.post(
            "/v1/events",
            json={"actor": "a", "action": "b", "resource": "c"},
            headers={"Authorization": "Bearer w"},
        )
        assert ok.status_code == 201
        # A write token must not grant read access.
        assert c.get("/v1/events", headers={"Authorization": "Bearer w"}).status_code == 401
        assert c.get("/v1/events", headers={"Authorization": "Bearer r"}).status_code == 200
