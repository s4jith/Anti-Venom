from __future__ import annotations
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(help="Manage quarantined chunks and audit logs.")
console = Console()


def _get_store(db_path: str = "antivenom_audit.db"):
    from antivenom.audit.quarantine import QuarantineStore
    return QuarantineStore(db_path=db_path)


@app.command("list")
def audit_list(
    limit: int = typer.Option(50, "--limit", "-n", help="Max entries to show."),
    db_path: str = typer.Option("antivenom_audit.db", "--db", help="Path to audit database."),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: suspicious|malicious"),
) -> None:
    """List quarantined chunks."""
    store = _get_store(db_path)
    entries = store.list_quarantined(limit=limit)

    if severity:
        entries = [e for e in entries if e.severity == severity]

    if not entries:
        console.print("[green]No quarantined chunks found.[/green]")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID", width=10)
    table.add_column("Source")
    table.add_column("Severity", width=12)
    table.add_column("Confidence", width=10)
    table.add_column("Quarantined At", width=22)

    _COLORS = {"suspicious": "yellow", "malicious": "red", "clean": "green"}
    for e in entries:
        color = _COLORS.get(e.severity, "white")
        table.add_row(
            e.quarantine_id[:8],
            e.source_id[:40] or "(unknown)",
            f"[{color}]{e.severity}[/{color}]",
            f"{e.confidence:.2f}",
            e.quarantined_at[:19],
        )

    console.print(table)
    console.print(f"[dim]Total quarantined: {store.count()}[/dim]")


@app.command("show")
def audit_show(
    quarantine_id: str = typer.Argument(..., help="Quarantine entry ID."),
    db_path: str = typer.Option("antivenom_audit.db", "--db"),
) -> None:
    """Show detail of a quarantined chunk."""
    store = _get_store(db_path)
    entry = store.get_quarantined(quarantine_id)
    if not entry:
        # try prefix match
        all_entries = store.list_quarantined(limit=1000)
        matches = [e for e in all_entries if e.quarantine_id.startswith(quarantine_id)]
        if not matches:
            console.print(f"[red]Not found:[/red] {quarantine_id}")
            raise typer.Exit(1)
        entry = matches[0]

    import json
    console.print(f"[bold]Quarantine ID:[/bold] {entry.quarantine_id}")
    console.print(f"[bold]Source:[/bold]        {entry.source_id}")
    console.print(f"[bold]Severity:[/bold]      [red]{entry.severity}[/red]")
    console.print(f"[bold]Confidence:[/bold]    {entry.confidence:.2f}")
    console.print(f"[bold]Quarantined:[/bold]   {entry.quarantined_at}")
    console.print(f"\n[bold]Chunk text (first 500 chars):[/bold]")
    console.print(f"[dim]{entry.chunk_text[:500]}[/dim]")
    evidence = json.loads(entry.evidence) if isinstance(entry.evidence, str) else entry.evidence
    if evidence:
        console.print(f"\n[bold]Evidence:[/bold]")
        for e in evidence:
            console.print(f"  • {e}")


@app.command("release")
def audit_release(
    quarantine_id: str = typer.Argument(..., help="Quarantine ID to release."),
    db_path: str = typer.Option("antivenom_audit.db", "--db"),
) -> None:
    """Release a chunk from quarantine."""
    store = _get_store(db_path)
    released = store.release(quarantine_id)
    if released:
        console.print(f"[green]Released:[/green] {quarantine_id}")
    else:
        console.print(f"[red]Not found:[/red] {quarantine_id}")
        raise typer.Exit(1)
