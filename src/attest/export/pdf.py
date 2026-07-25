"""The regulator-facing evidence pack.

What makes this document useful is not that it lists events — a CSV does that.
It is that it carries everything a third party needs to check the claim
*without trusting the system that produced it*: the public keys, the chain
parameters, the checkpoint commitments with their timestamp tokens, and the
exact commands to re-derive the hashes independently.

So the verification section leads, before the events, and it states what was
checked and what was not. A pack that says "VERIFIED" and nothing else is
asking the reader to trust the same system twice.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..core.anchor import is_externally_anchored
from ..core.chain import CHAIN_VERSION, Entry
from ..core.signing import KeyRing
from ..core.verify import Severity, VerificationReport

UTC = timezone.utc

INK = colors.HexColor("#1a1d23")
MUTED = colors.HexColor("#5c6370")
RULE = colors.HexColor("#d5d9e0")
GOOD = colors.HexColor("#1a7f37")
BAD = colors.HexColor("#cf222e")
WARN = colors.HexColor("#9a6700")
BAND = colors.HexColor("#f4f6f9")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=20, leading=24, textColor=INK, spaceAfter=2
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=9.5, textColor=MUTED, spaceAfter=14
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=12.5, textColor=INK,
            spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9, leading=13, textColor=INK
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontSize=8, leading=11, textColor=MUTED
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"], fontName="Courier", fontSize=7.5, leading=10,
            textColor=INK,
        ),
    }


def _table(data: list[list[Any]], widths: list[float], *, header: bool = True) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), BAND),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ]
    table.setStyle(TableStyle(style))
    return table


def build_evidence_pack(
    entries: list[Entry],
    report: VerificationReport,
    checkpoints: list[dict[str, Any]],
    keyring: KeyRing | None = None,
    *,
    title: str = "Audit Trail Evidence Pack",
    organisation: str = "",
) -> bytes:
    """Render the pack and return the PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=title,
        author="attest",
    )
    st = _styles()
    generated = datetime.now(UTC).isoformat(timespec="seconds")
    flow: list[Any] = []

    flow.append(Paragraph(title, st["title"]))
    subtitle = f"Generated {generated}"
    if organisation:
        subtitle = f"{organisation} &middot; {subtitle}"
    flow.append(Paragraph(subtitle, st["subtitle"]))

    # -- integrity, first -----------------------------------------------------
    anchored = [c for c in checkpoints if is_externally_anchored(c)]
    verdict = "INTACT" if report.intact else "INTEGRITY FAILURE"
    colour = GOOD if report.intact else BAD

    summary = _table(
        [
            ["Verification result", verdict],
            ["Entries covered", str(report.entries_checked)],
            ["Signatures verified", str(report.signatures_checked)],
            ["Checkpoints verified", str(report.checkpoints_checked)],
            ["Externally anchored", f"{len(anchored)} of {len(checkpoints)}"],
            ["Chain head", report.head_hash],
            ["Chain version", str(CHAIN_VERSION)],
        ],
        [55 * mm, 119 * mm],
        header=False,
    )
    summary.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 5), (1, 5), "Courier"),
                ("FONTSIZE", (1, 5), (1, 5), 7),
                ("TEXTCOLOR", (1, 0), (1, 0), colour),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
            ]
        )
    )
    flow.append(Paragraph("1. Integrity verification", st["h2"]))
    flow.append(summary)

    if report.findings:
        flow.append(Spacer(1, 6))
        rows: list[list[Any]] = [["Seq", "Check", "Severity", "Finding and implication"]]
        for finding in report.findings:
            rows.append(
                [
                    str(finding.seq or "-"),
                    finding.check,
                    finding.severity.value,
                    Paragraph(
                        f"{finding.detail}<br/><font color='#5c6370'>&rarr; "
                        f"{finding.implication}</font>",
                        st["small"],
                    ),
                ]
            )
        table = _table(rows, [14 * mm, 28 * mm, 20 * mm, 112 * mm])
        for index, finding in enumerate(report.findings, start=1):
            shade = {Severity.CRITICAL: BAD, Severity.HIGH: BAD, Severity.WARNING: WARN}[
                finding.severity
            ]
            table.setStyle(TableStyle([("TEXTCOLOR", (2, index), (2, index), shade)]))
        flow.append(table)
    else:
        flow.append(Spacer(1, 6))
        flow.append(
            Paragraph(
                "Every entry's hash matches its contents, every entry links to its "
                "predecessor, every signature verifies against a key in the ring, and "
                "the sequence is unbroken.",
                st["body"],
            )
        )

    # -- what a third party should re-check on their own ---------------------
    flow.append(Paragraph("2. What this pack does and does not establish", st["h2"]))
    checked = [
        "Each entry's SHA-256 matches a canonical serialisation of its own fields.",
        "Each entry commits to the hash of its predecessor, with no gaps in sequence.",
        "Each entry carries an Ed25519 signature that verifies against a listed key.",
        "Each checkpoint's head hash and Merkle root match the entries it covers.",
    ]
    not_checked = [
        "The timestamp authority's own signature on its tokens. Tokens are included "
        "verbatim in section 5; validate them with <font face='Courier'>openssl ts "
        "-verify</font> against your own trusted roots.",
        "That every event which occurred was submitted. This pack proves nothing was "
        "altered or removed after submission; it cannot prove something was never written.",
    ]
    if len(checkpoints) == 0:
        not_checked.append(
            "Truncation of the most recent entries. No checkpoint exists, so entries "
            "deleted from the end of the trail would leave a chain that still verifies."
        )
    elif not anchored:
        not_checked.append(
            "Independent dating. No checkpoint carries a third-party timestamp, so the "
            "dates rest on the operator's own signing key and clock."
        )

    flow.append(Paragraph("<b>Established by this pack</b>", st["body"]))
    for item in checked:
        flow.append(Paragraph(f"&bull;&nbsp;&nbsp;{item}", st["small"]))
    flow.append(Spacer(1, 5))
    flow.append(Paragraph("<b>Not established, and why</b>", st["body"]))
    for item in not_checked:
        flow.append(Paragraph(f"&bull;&nbsp;&nbsp;{item}", st["small"]))

    # -- keys -----------------------------------------------------------------
    if keyring is not None and len(keyring):
        flow.append(Paragraph("3. Signing keys", st["h2"]))
        flow.append(
            Paragraph(
                "Ed25519 public keys, raw encoding, hex. Signatures are computed over the "
                "32-byte entry hash. Retired keys are retained so historical entries "
                "remain verifiable after a rotation.",
                st["small"],
            )
        )
        flow.append(Spacer(1, 4))
        rows = [["Key ID", "Public key (hex)"]]
        import base64

        for key_id in keyring.ids():
            raw = base64.b64decode(keyring._meta[key_id]["public_key"])
            rows.append([key_id, Paragraph(raw.hex(), st["mono"])])
        flow.append(_table(rows, [34 * mm, 140 * mm]))

    # -- checkpoints ----------------------------------------------------------
    flow.append(Paragraph("4. Checkpoint commitments", st["h2"]))
    if checkpoints:
        rows = [["Covers to", "Created", "Head hash", "Authority", "TSA time"]]
        for checkpoint in checkpoints:
            authority = checkpoint.get("tsa_authority") or "none"
            rows.append(
                [
                    str(checkpoint["covers_to_seq"]),
                    checkpoint["created_at"],
                    Paragraph(checkpoint["head_hash"][:32] + "...", st["mono"]),
                    Paragraph(authority[:38], st["small"]),
                    checkpoint.get("tsa_time") or "-",
                ]
            )
        flow.append(_table(rows, [18 * mm, 34 * mm, 52 * mm, 40 * mm, 30 * mm]))
    else:
        flow.append(
            Paragraph(
                "No checkpoints. Deleting entries from the end of this trail would "
                "leave a chain that still verifies; nothing here would detect it.",
                st["body"],
            )
        )

    # -- events ---------------------------------------------------------------
    flow.append(PageBreak())
    flow.append(Paragraph("5. Event records", st["h2"]))
    flow.append(
        Paragraph(
            f"{len(entries)} entries, in sequence order. The hash column is the first 16 "
            "hex characters of each entry's SHA-256.",
            st["small"],
        )
    )
    flow.append(Spacer(1, 4))

    rows = [["Seq", "Timestamp", "Actor", "Action", "Resource", "Outcome", "Hash"]]
    for entry in entries:
        rows.append(
            [
                str(entry.seq),
                entry.timestamp.replace("T", " ").replace("+00:00", "Z"),
                Paragraph(entry.actor, st["small"]),
                Paragraph(entry.action, st["small"]),
                Paragraph(entry.resource, st["small"]),
                entry.outcome,
                Paragraph(entry.entry_hash[:16], st["mono"]),
            ]
        )
    flow.append(
        _table(rows, [11 * mm, 30 * mm, 26 * mm, 32 * mm, 30 * mm, 18 * mm, 27 * mm])
    )

    flow.append(Spacer(1, 10))
    flow.append(
        KeepTogether(
            Paragraph(
                "<b>Reproducing these hashes independently.</b> Each entry hash is "
                "SHA-256 over a canonical JSON object with sorted keys, no whitespace, "
                "UTF-8, containing exactly: version, seq, timestamp, actor, action, "
                "resource, outcome, payload_hash, prev_hash — where payload_hash is the "
                "same construction applied to the payload object. Run "
                "<font face='Courier'>attest verify --json</font> against the exported "
                "trail to re-derive every value in this document.",
                st["small"],
            )
        )
    )

    doc.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def _footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Generated by attest — tamper-evident audit trail")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.restoreState()
