"""Canonical hashing, the chain, signing, and append-only storage."""

from __future__ import annotations

import json
import sqlite3

import pytest

from attest.core import canonical
from attest.core.canonical import CanonicalisationError
from attest.core.chain import GENESIS_HASH, build, merkle_root
from attest.core.signing import KeyPair, KeyRing, SigningError
from attest.core.store import Store


class TestCanonical:
    def test_key_order_does_not_change_the_digest(self):
        assert canonical.digest({"a": 1, "b": 2}) == canonical.digest({"b": 2, "a": 1})

    def test_nested_key_order_does_not_either(self):
        left = {"outer": {"z": 1, "a": {"n": 2, "m": 3}}}
        right = {"outer": {"a": {"m": 3, "n": 2}, "z": 1}}
        assert canonical.digest(left) == canonical.digest(right)

    def test_different_values_change_the_digest(self):
        assert canonical.digest({"a": 1}) != canonical.digest({"a": 2})

    def test_unicode_is_not_escaped(self):
        assert "è" in canonical.dumps({"name": "Lefèvre"})
        assert "\\u" not in canonical.dumps({"name": "Lefèvre"})

    def test_no_insignificant_whitespace(self):
        assert canonical.dumps({"a": 1, "b": [1, 2]}) == '{"a":1,"b":[1,2]}'

    def test_floats_are_rejected_with_the_path(self):
        # A monetary amount stored as a float is a verification failure waiting
        # for a platform upgrade, so it fails now and loudly.
        with pytest.raises(CanonicalisationError, match=r"\$\.amount"):
            canonical.digest({"amount": 42.5})

    def test_nested_floats_are_rejected(self):
        with pytest.raises(CanonicalisationError, match=r"\$\.a\.b\[1\]"):
            canonical.digest({"a": {"b": [1, 2.5]}})

    def test_booleans_are_not_mistaken_for_floats(self):
        assert canonical.digest({"ok": True})

    def test_integers_are_fine(self):
        assert canonical.digest({"amount_cents": 4250})

    def test_non_string_keys_are_rejected(self):
        with pytest.raises(CanonicalisationError, match="keys must be strings"):
            canonical.digest({1: "x"})

    def test_unserialisable_is_rejected(self):
        with pytest.raises(CanonicalisationError):
            canonical.digest({"x": object()})


class TestChain:
    def test_hash_is_stable(self):
        kwargs = dict(
            seq=1, prev_hash=GENESIS_HASH, actor="a", action="b", resource="c",
            timestamp="2026-04-18T09:00:00+00:00", payload={"k": 1},
        )
        assert build(**kwargs).entry_hash == build(**kwargs).entry_hash

    def test_hash_covers_every_field(self):
        base = dict(
            seq=1, prev_hash=GENESIS_HASH, actor="a", action="b", resource="c",
            timestamp="2026-04-18T09:00:00+00:00", outcome="success", payload={"k": 1},
        )
        reference = build(**base).entry_hash
        for field, value in [
            ("actor", "z"), ("action", "z"), ("resource", "z"), ("outcome", "denied"),
            ("timestamp", "2026-04-18T09:00:01+00:00"), ("seq", 2),
            ("prev_hash", "f" * 64), ("payload", {"k": 2}),
        ]:
            assert build(**{**base, field: value}).entry_hash != reference, f"{field} not covered"

    def test_sequence_starts_at_one(self):
        with pytest.raises(ValueError):
            build(seq=0, prev_hash=GENESIS_HASH, actor="a", action="b", resource="c")

    def test_empty_fields_rejected(self):
        with pytest.raises(ValueError, match="actor"):
            build(seq=1, prev_hash=GENESIS_HASH, actor="", action="b", resource="c")


class TestMerkle:
    def test_empty(self):
        assert merkle_root([]) == GENESIS_HASH

    def test_single(self):
        assert merkle_root(["ab" * 32]) == "ab" * 32

    def test_changes_with_any_leaf(self):
        leaves = [f"{i:064x}" for i in range(5)]
        altered = [*leaves[:2], f"{99:064x}", *leaves[3:]]
        assert merkle_root(leaves) != merkle_root(altered)

    def test_order_matters(self):
        leaves = [f"{i:064x}" for i in range(4)]
        assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))

    def test_odd_node_is_promoted_not_duplicated(self):
        # CVE-2012-2459: duplicating the last node lets two different leaf sets
        # produce the same root. Promoting avoids it.
        three = [f"{i:064x}" for i in range(3)]
        four_with_dupe = [*three, three[-1]]
        assert merkle_root(three) != merkle_root(four_with_dupe)


class TestSigning:
    def test_sign_and_verify(self):
        keypair = KeyPair.generate()
        ring = KeyRing()
        ring.add_keypair(keypair)
        message = b"payload"
        assert ring.verify(keypair.key_id, message, keypair.sign(message))

    def test_wrong_message_fails(self):
        keypair = KeyPair.generate()
        ring = KeyRing()
        ring.add_keypair(keypair)
        assert not ring.verify(keypair.key_id, b"other", keypair.sign(b"payload"))

    def test_key_id_is_derived_from_the_key(self):
        keypair = KeyPair.generate()
        assert KeyPair.load(keypair.save("/tmp/attest-test-key.pem")).key_id == keypair.key_id

    def test_saved_key_is_not_world_readable(self):
        import os
        import stat

        keypair = KeyPair.generate()
        path = keypair.save("/tmp/attest-perm-key.pem")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_encrypted_key_needs_the_passphrase(self):
        keypair = KeyPair.generate()
        path = keypair.save("/tmp/attest-enc-key.pem", passphrase=b"hunter2")
        assert KeyPair.load(path, passphrase=b"hunter2").key_id == keypair.key_id
        with pytest.raises((TypeError, ValueError)):
            KeyPair.load(path)

    def test_unknown_key_raises(self):
        with pytest.raises(SigningError, match="no public key"):
            KeyRing().verify("deadbeef", b"m", "sig")

    def test_retired_keys_still_verify(self):
        # An audit trail outlives its keys. A ring that forgets retired keys
        # gives the trail an expiry date.
        old, new = KeyPair.generate(), KeyPair.generate()
        ring = KeyRing()
        ring.add_keypair(old)
        signature = old.sign(b"historic entry")
        ring.add_keypair(new)
        ring.retire(old.key_id)
        assert ring.verify(old.key_id, b"historic entry", signature)

    def test_ring_round_trips_through_json(self):
        keypair = KeyPair.generate()
        ring = KeyRing()
        ring.add_keypair(keypair)
        restored = KeyRing.from_json(ring.to_json())
        assert restored.ids() == ring.ids()
        assert restored.verify(keypair.key_id, b"m", keypair.sign(b"m"))


class TestStore:
    @pytest.fixture
    def signed(self):
        keypair = KeyPair.generate()
        store = Store()
        for i in range(5):
            store.append("u", "act", f"res-{i}", payload={"n": i}, signer=keypair)
        return store, keypair

    def test_head_of_empty_store(self):
        assert Store().head() == (0, GENESIS_HASH)

    def test_entries_link_up(self, signed):
        store, _ = signed
        entries = store.entries()
        assert entries[0].prev_hash == GENESIS_HASH
        for previous, current in zip(entries, entries[1:], strict=False):
            assert current.prev_hash == previous.entry_hash
            assert current.seq == previous.seq + 1

    def test_update_is_refused_by_the_database(self, signed):
        store, _ = signed
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute("UPDATE entries SET actor = 'x' WHERE seq = 1")

    def test_delete_is_refused_by_the_database(self, signed):
        store, _ = signed
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute("DELETE FROM entries WHERE seq = 1")

    def test_triggers_are_restored_after_a_forced_mutation(self, signed):
        # force_mutate exists so tests and the demo can play the attacker. If it
        # left the triggers off, every later write would be unprotected.
        store, _ = signed
        store.force_mutate(1, actor="attacker")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute("UPDATE entries SET actor = 'y' WHERE seq = 2")

    def test_triggers_are_restored_after_a_forced_delete(self, signed):
        store, _ = signed
        store.force_delete(5)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute("DELETE FROM entries WHERE seq = 1")

    def test_filters(self, signed):
        store, keypair = signed
        store.append("auditor", "review", "res-9", signer=keypair)
        assert len(store.entries(actor="auditor")) == 1
        assert len(store.entries(action="act")) == 5
        assert len(store.entries(resource="res-2")) == 1

    def test_pagination(self, signed):
        store, _ = signed
        assert [e.seq for e in store.entries(limit=2, offset=2)] == [3, 4]

    def test_payload_round_trips(self, signed):
        store, keypair = signed
        payload = {"nested": {"list": [1, 2, 3], "text": "Lefèvre"}}
        entry = store.append("u", "a", "r", payload=payload, signer=keypair)
        assert store.get(entry.seq).payload == payload

    def test_float_payload_is_refused_before_it_is_stored(self):
        store = Store()
        with pytest.raises(CanonicalisationError):
            store.append("u", "a", "r", payload={"amount": 1.5}, signer=KeyPair.generate())
        assert store.count() == 0

    def test_concurrent_appends_do_not_fork(self):
        # Two writers reading the same head would both claim the same seq. The
        # UNIQUE constraint is the backstop behind BEGIN IMMEDIATE.
        import threading

        keypair = KeyPair.generate()
        store = Store("file:forktest?mode=memory&cache=shared")
        errors: list[Exception] = []

        def writer(n: int) -> None:
            try:
                for i in range(10):
                    store.append(f"w{n}", "act", f"r{i}", signer=keypair)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, errors
        entries = store.entries()
        assert [e.seq for e in entries] == list(range(1, len(entries) + 1))
        for previous, current in zip(entries, entries[1:], strict=False):
            assert current.prev_hash == previous.entry_hash

    def test_stored_payload_is_sorted_json(self, signed):
        store, keypair = signed
        entry = store.append("u", "a", "r", payload={"z": 1, "a": 2}, signer=keypair)
        raw = store._conn.execute(
            "SELECT payload FROM entries WHERE seq = ?", (entry.seq,)
        ).fetchone()["payload"]
        assert list(json.loads(raw)) == ["a", "z"]
