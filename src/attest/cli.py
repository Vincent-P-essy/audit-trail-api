"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .core.anchor import create_checkpoint, is_externally_anchored, unanchored_window
from .core.signing import KeyPair, KeyRing
from .core.store import Store
from .core.verify import Severity, VerificationReport, verify_chain

SEVERITY_STYLE = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.WARNING: "yellow",
}


def _open(args: argparse.Namespace) -> tuple[Store, KeyPair | None, KeyRing]:
    store = Store(args.db)
    signer = KeyPair.load(args.key) if args.key and Path(args.key).exists() else None
    ring = KeyRing()
    if signer:
        ring.add_keypair(signer)
    for record in store.registered_keys():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        ring.add(Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["public_key"])))
    return store, signer, ring


def render_report(report: VerificationReport, store: Store, console: Console) -> None:
    header = Text()
    if report.intact:
        header.append("TRAIL INTACT\n", style="bold bright_green")
    else:
        header.append("INTEGRITY FAILURE\n", style="bold bright_red")
    header.append(f"entries        {report.entries_checked}\n", style="dim")
    header.append(f"signatures     {report.signatures_checked} verified\n", style="dim")
    header.append(f"checkpoints    {report.checkpoints_checked} verified\n", style="dim")
    window = unanchored_window(store)
    header.append("unanchored     ", style="dim")
    header.append(
        f"{window} entries since the last checkpoint",
        style="yellow" if window else "dim",
    )
    if window:
        header.append("\n               deletable without detection", style="yellow")
    console.print(
        Panel(
            header,
            title="attest verify",
            border_style="green" if report.intact else "red",
            expand=False,
        )
    )

    if not report.findings:
        return

    table = Table(title="Findings", title_style="bold", header_style="dim", show_lines=True)
    table.add_column("seq", justify="right")
    table.add_column("check", style="bold")
    table.add_column("sev")
    table.add_column("what it means", overflow="fold")
    for finding in report.findings:
        detail = Text(finding.detail + "\n")
        detail.append(f"→ {finding.implication}", style="dim")
        if finding.expected:
            detail.append(f"\n  expected {finding.expected}  found {finding.found}", style="dim")
        table.add_row(
            str(finding.seq or "-"),
            finding.check,
            Text(finding.severity.value, style=SEVERITY_STYLE[finding.severity]),
            detail,
        )
    console.print(table)


def cmd_init(args: argparse.Namespace, console: Console) -> int:
    path = Path(args.key)
    if path.exists() and not args.force:
        console.print(f"[red]refusing to overwrite {path}[/] (pass --force if you mean it)")
        return 1
    keypair = KeyPair.generate()
    keypair.save(path)
    store = Store(args.db)
    store.register_key(keypair.key_id, keypair.public_bytes().hex(), keypair.created_at)
    console.print(f"[green]generated[/] Ed25519 signing key [bold]{keypair.key_id}[/]")
    console.print(f"[dim]private key {path} (mode 0600) · registered in {args.db}[/]")
    return 0


def cmd_append(args: argparse.Namespace, console: Console) -> int:
    store, signer, _ = _open(args)
    if signer is None:
        console.print(f"[red]no signing key at {args.key}[/] — run `attest init` first")
        return 1
    payload = json.loads(args.payload) if args.payload else {}
    entry = store.append(
        actor=args.actor,
        action=args.action,
        resource=args.resource,
        outcome=args.outcome,
        payload=payload,
        signer=signer,
    )
    console.print(f"[green]appended[/] seq [bold]{entry.seq}[/]  hash {entry.entry_hash[:16]}...")
    return 0


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    store, _, ring = _open(args)
    report = verify_chain(store.entries(), ring, store.checkpoints())
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.intact else 2
    render_report(report, store, console)
    return 0 if report.intact else 2


def cmd_checkpoint(args: argparse.Namespace, console: Console) -> int:
    store, signer, _ = _open(args)
    if signer is None:
        console.print(f"[red]no signing key at {args.key}[/] — run `attest init` first")
        return 1
    checkpoint = create_checkpoint(store, signer, tsa_url=args.tsa)
    external = is_externally_anchored(checkpoint)
    console.print(
        f"[green]checkpoint[/] covers seq [bold]{checkpoint['covers_to_seq']}[/]  "
        f"root {checkpoint['merkle_root'][:16]}..."
    )
    if external:
        console.print(
            f"[green]anchored[/] by {checkpoint['tsa_authority']} at {checkpoint['tsa_time']}"
        )
    else:
        console.print(
            f"[yellow]not externally anchored[/] ({checkpoint['tsa_authority']}) — "
            "this checkpoint's date rests on your own key"
        )
    return 0


def cmd_export(args: argparse.Namespace, console: Console) -> int:
    from .export.pdf import build_evidence_pack

    store, _, ring = _open(args)
    report = verify_chain(store.entries(), ring, store.checkpoints())
    pdf = build_evidence_pack(
        entries=store.entries(actor=args.actor, resource=args.resource),
        report=report,
        checkpoints=store.checkpoints(),
        keyring=ring,
        organisation=args.organisation or "",
    )
    Path(args.out).write_bytes(pdf)
    console.print(
        f"[green]wrote[/] {args.out}  ({len(pdf) // 1024} KB, "
        f"{report.entries_checked} entries, "
        f"{'intact' if report.intact else str(len(report.findings)) + ' findings'})"
    )
    return 0


def cmd_serve(args: argparse.Namespace, console: Console) -> int:
    from .api.app import create_app

    store, signer, ring = _open(args)
    app = create_app(store, signer or KeyPair.generate(), ring)
    console.print(f"[green]attest[/] listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_demo(args: argparse.Namespace, console: Console) -> int:
    """Build a trail, then attack it three ways and show what each one leaves behind.

    The third scenario is the interesting one: the chain alone reports nothing
    wrong, because a truncated chain is a valid chain.
    """
    keypair = KeyPair.generate()
    ring = KeyRing()
    ring.add_keypair(keypair)

    events = [
        ("m.dubois", "payment.initiate", "PAY-88120", "success", {"amount_cents": 1842000}),
        ("s.laurent", "payment.approve", "PAY-88120", "success", {"role": "second_approver"}),
        ("batch.settle", "payment.settle", "PAY-88120", "success", {"value_date": "2026-04-18"}),
        ("m.dubois", "customer.view", "CUST-40182", "success", {"fields": ["balance"]}),
        ("n.duarte", "access.grant", "ROLE-treasury", "success", {"grantee": "m.dubois"}),
        ("m.dubois", "payment.initiate", "PAY-88121", "denied", {"reason": "limit_exceeded"}),
    ]

    console.print("[bold]1. A trail with six signed entries[/]")
    store = Store()
    for actor, action, resource, outcome, payload in events:
        store.append(actor, action, resource, outcome, payload, signer=keypair)
    create_checkpoint(store, keypair)
    for actor, action, resource, outcome, payload in events[:2]:
        store.append(actor, action, resource, outcome, payload, signer=keypair)
    render_report(verify_chain(store.entries(), ring, store.checkpoints()), store, console)

    console.print("\n[bold]2. An insider edits an approval amount directly in the database[/]")
    console.print("[dim]   UPDATE runs with the append-only triggers dropped[/]")
    tampered = Store()
    for actor, action, resource, outcome, payload in events:
        tampered.append(actor, action, resource, outcome, payload, signer=keypair)
    create_checkpoint(tampered, keypair)
    tampered.force_mutate(1, payload=json.dumps({"amount_cents": 18420}))
    render_report(verify_chain(tampered.entries(), ring, tampered.checkpoints()), tampered, console)

    console.print("\n[bold]3. The same insider deletes the last two entries instead[/]")
    truncated = Store()
    for actor, action, resource, outcome, payload in events:
        truncated.append(actor, action, resource, outcome, payload, signer=keypair)
    create_checkpoint(truncated, keypair)
    truncated.force_delete(6)
    truncated.force_delete(5)

    chain_only = verify_chain(truncated.entries(), ring)
    console.print(
        f"   [dim]hash chain alone:[/] "
        f"[{'bright_green' if chain_only.intact else 'red'}]"
        f"{'no findings — a truncated chain is a valid chain' if chain_only.intact else 'broken'}"
        f"[/]"
    )
    render_report(
        verify_chain(truncated.entries(), ring, truncated.checkpoints()), truncated, console
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attest", description="Tamper-evident audit trail.")
    parser.add_argument("--version", action="version", version=f"attest {__version__}")
    parser.add_argument("--db", default="attest.db", help="SQLite database path")
    parser.add_argument("--key", default="attest-key.pem", help="Ed25519 private key path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="generate a signing key")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("append", help="append one entry")
    p.add_argument("--actor", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--resource", required=True)
    p.add_argument("--outcome", default="success")
    p.add_argument("--payload", help="JSON object")
    p.set_defaults(func=cmd_append)

    p = sub.add_parser("verify", help="verify the whole trail")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("checkpoint", help="cut and anchor a checkpoint")
    p.add_argument("--tsa", help="RFC 3161 authority URL (e.g. https://freetsa.org/tsr)")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("export", help="write the regulator evidence pack")
    p.add_argument("--out", default="evidence-pack.pdf")
    p.add_argument("--actor")
    p.add_argument("--resource")
    p.add_argument("--organisation")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="run the HTTP API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("demo", help="build a trail and attack it three ways")
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
