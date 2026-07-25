"""The HTTP service.

Two API decisions are worth pointing at, because both go against what a REST
generator would produce.

**There is no UPDATE or DELETE, and no soft-delete flag either.** A `deleted`
column would let the trail lie by omission while every hash still verified.
Corrections are appended as new entries that reference the one they correct,
which is how a ledger has always worked.

**Verification is a GET anyone with a read token can call.** An audit trail
whose integrity can only be confirmed by the team that operates it has not
solved the problem it exists to solve.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import Flask, Response, g, jsonify, request

from ..core.anchor import create_checkpoint, is_externally_anchored, unanchored_window
from ..core.canonical import CanonicalisationError
from ..core.signing import KeyPair, KeyRing
from ..core.store import Store
from ..core.verify import verify_chain

MAX_PAYLOAD_BYTES = 64 * 1024


def _tokens(env: str, default: str = "") -> set[str]:
    return {t.strip() for t in os.environ.get(env, default).split(",") if t.strip()}


def create_app(
    store: Store | None = None,
    signer: KeyPair | None = None,
    keyring: KeyRing | None = None,
    *,
    write_tokens: set[str] | None = None,
    read_tokens: set[str] | None = None,
) -> Flask:
    app = Flask(__name__)

    app.config["STORE"] = store or Store(os.environ.get("ATTEST_DB", ":memory:"))
    app.config["SIGNER"] = signer or KeyPair.generate()
    ring = keyring or KeyRing()
    ring.add_keypair(app.config["SIGNER"])
    app.config["KEYRING"] = ring
    app.config["WRITE_TOKENS"] = (
        write_tokens if write_tokens is not None else _tokens("ATTEST_WRITE_TOKENS")
    )
    app.config["READ_TOKENS"] = (
        read_tokens if read_tokens is not None else _tokens("ATTEST_READ_TOKENS")
    )

    app.config["STORE"].register_key(
        app.config["SIGNER"].key_id,
        app.config["SIGNER"].public_bytes().hex(),
        app.config["SIGNER"].created_at,
    )

    def authorised(scope: str) -> Callable:
        """Bearer-token check.

        Write and read tokens are separate sets. The service that emits audit
        events should not be able to read the whole trail back, and the auditor
        reading it should not be able to write to it.
        """

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                allowed = app.config["WRITE_TOKENS" if scope == "write" else "READ_TOKENS"]
                if not allowed:  # unset = open, for local development only
                    return view(*args, **kwargs)
                header = request.headers.get("Authorization", "")
                token = header[7:] if header.startswith("Bearer ") else ""
                if token not in allowed:
                    return jsonify({"error": "unauthorised", "scope": scope}), 401
                g.token = token
                return view(*args, **kwargs)

            return wrapper

        return decorator

    # -- write ---------------------------------------------------------------

    @app.post("/v1/events")
    @authorised("write")
    def append_event():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "a JSON object body is required"}), 400

        missing = [f for f in ("actor", "action", "resource") if not body.get(f)]
        if missing:
            return jsonify({"error": f"missing required field(s): {', '.join(missing)}"}), 400

        payload = body.get("payload") or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "payload must be an object"}), 400
        if len(str(payload)) > MAX_PAYLOAD_BYTES:
            return jsonify({"error": f"payload exceeds {MAX_PAYLOAD_BYTES} bytes"}), 413

        try:
            entry = app.config["STORE"].append(
                actor=str(body["actor"]),
                action=str(body["action"]),
                resource=str(body["resource"]),
                outcome=str(body.get("outcome", "success")),
                payload=payload,
                signer=app.config["SIGNER"],
            )
        except CanonicalisationError as exc:
            # The float rule bites here, and the message has to say why rather
            # than returning a generic 400 the caller cannot act on.
            return jsonify({"error": str(exc), "hint": "use integer minor units or strings"}), 422

        return jsonify(entry.to_dict()), 201

    @app.post("/v1/checkpoints")
    @authorised("write")
    def make_checkpoint():
        try:
            checkpoint = create_checkpoint(
                app.config["STORE"],
                app.config["SIGNER"],
                tsa_url=os.environ.get("ATTEST_TSA_URL"),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        checkpoint["externally_anchored"] = is_externally_anchored(checkpoint)
        return jsonify(checkpoint), 201

    # -- read ----------------------------------------------------------------

    @app.get("/v1/events")
    @authorised("read")
    def list_events():
        try:
            limit = min(int(request.args.get("limit", 100)), 1000)
            offset = max(int(request.args.get("offset", 0)), 0)
        except ValueError:
            return jsonify({"error": "limit and offset must be integers"}), 400

        entries = app.config["STORE"].entries(
            actor=request.args.get("actor"),
            action=request.args.get("action"),
            resource=request.args.get("resource"),
            since=request.args.get("since"),
            until=request.args.get("until"),
            limit=limit,
            offset=offset,
        )
        return jsonify(
            {
                "count": len(entries),
                "total": app.config["STORE"].count(),
                "events": [e.to_dict() for e in entries],
            }
        )

    @app.get("/v1/events/<int:seq>")
    @authorised("read")
    def get_event(seq: int):
        entry = app.config["STORE"].get(seq)
        if entry is None:
            return jsonify({"error": f"no entry with sequence {seq}"}), 404
        return jsonify(entry.to_dict())

    @app.get("/v1/verify")
    @authorised("read")
    def verify():
        store = app.config["STORE"]
        report = verify_chain(store.entries(), app.config["KEYRING"], store.checkpoints())
        body = report.to_dict()
        body["unanchored_entries"] = unanchored_window(store)
        # 409 rather than 200 so a monitoring probe that only looks at the
        # status code still notices a broken trail.
        return jsonify(body), (200 if report.intact else 409)

    @app.get("/v1/checkpoints")
    @authorised("read")
    def list_checkpoints():
        checkpoints = app.config["STORE"].checkpoints()
        for checkpoint in checkpoints:
            checkpoint["externally_anchored"] = is_externally_anchored(checkpoint)
        return jsonify({"count": len(checkpoints), "checkpoints": checkpoints})

    @app.get("/v1/export/evidence.pdf")
    @authorised("read")
    def export_pdf():
        from ..export.pdf import build_evidence_pack

        store = app.config["STORE"]
        pdf = build_evidence_pack(
            entries=store.entries(
                actor=request.args.get("actor"),
                resource=request.args.get("resource"),
                since=request.args.get("since"),
                until=request.args.get("until"),
            ),
            report=verify_chain(store.entries(), app.config["KEYRING"], store.checkpoints()),
            checkpoints=store.checkpoints(),
            keyring=app.config["KEYRING"],
        )
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=evidence-pack.pdf"},
        )

    @app.get("/health")
    def health():
        store = app.config["STORE"]
        head_seq, head_hash = store.head()
        return jsonify(
            {
                "status": "ok",
                "entries": head_seq,
                "head_hash": head_hash,
                "unanchored_entries": unanchored_window(store),
                "signing_key": app.config["SIGNER"].key_id,
            }
        )

    @app.errorhandler(405)
    def method_not_allowed(_):
        # The commonest wrong assumption about this API, answered directly.
        return (
            jsonify(
                {
                    "error": "method not allowed",
                    "detail": (
                        "audit entries are append-only. There is no update or delete, "
                        "and no soft-delete flag either - a correction is a new entry "
                        "that references the one it corrects."
                    ),
                }
            ),
            405,
        )

    return app
