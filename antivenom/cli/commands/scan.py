from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.result import Severity
from antivenom.core.scanner import AntiVenomScanner

app = typer.Typer(help="Scan files or text for prompt injection.")
console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

_SEVERITY_COLORS = {
    Severity.CLEAN: "green",
    Severity.SUSPICIOUS: "yellow",
    Severity.MALICIOUS: "red",
}


def _make_bar(confidence: float, width: int = 20) -> str:
    filled = int(confidence * width)
    return "#" * filled + "-" * (width - filled)


@app.callback(invoke_without_command=True)
def scan_command(
    input_path: Path | None = typer.Argument(None, help="File to scan. Use '-' for stdin."),
    threshold: float = typer.Option(0.7, "--threshold", "-t", help="Confidence threshold (0.0-1.0)."),
    chunk_size: int = typer.Option(500, "--chunk-size", help="Auto-chunk text at this character size."),
    format: str = typer.Option("text", "--format", "-f", help="Output format: text|json."),
    no_quarantine: bool = typer.Option(False, "--no-quarantine", help="Skip quarantine on detection."),
    layers: str | None = typer.Option(None, "--layers", help="Comma-separated layer names to enable."),
) -> None:
    """Scan a file or stdin for adversarial prompt injections."""
    if input_path is None or str(input_path) == "-":
        text = sys.stdin.read()
        source = "stdin"
    else:
        if not input_path.exists():
            err_console.print(f"[red]File not found:[/red] {input_path}")
            raise typer.Exit(1)
        text = input_path.read_text(encoding="utf-8", errors="replace")
        source = str(input_path)

    enabled = [name.strip() for name in layers.split(",")] if layers else None
    config = ScannerConfig(
        confidence_threshold=threshold,
        quarantine_on_detection=not no_quarantine,
        enabled_layers=enabled,
    )
    scanner = AntiVenomScanner(config=config)

    # Split into chunks
    chunks: list[Chunk] = []
    for i in range(0, len(text), chunk_size):
        chunk_text = text[i : i + chunk_size].strip()
        if chunk_text:
            chunks.append(Chunk(text=chunk_text, source_id=source, chunk_index=i // chunk_size))

    if not chunks:
        console.print("[yellow]No content to scan.[/yellow]")
        raise typer.Exit(0)

    results = scanner.scan_batch(chunks)

    if format == "json":
        output = []
        for chunk, result in zip(chunks, results):
            output.append({
                "chunk_index": chunk.chunk_index,
                "is_poisoned": result.is_poisoned,
                "confidence": result.confidence,
                "severity": result.severity.value,
                "evidence": [e for r in result.layer_results for e in r.evidence],
            })
        console.print_json(json.dumps(output))
    else:
        table = Table(box=box.ASCII, show_header=True, header_style="bold")
        table.add_column("Chunk", style="dim", width=6)
        table.add_column("Verdict", width=12)
        table.add_column("Confidence", width=26)
        table.add_column("Evidence")

        poisoned_count = 0
        suspicious_count = 0
        for chunk, result in zip(chunks, results):
            if result.is_poisoned:
                if result.severity == Severity.MALICIOUS:
                    poisoned_count += 1
                else:
                    suspicious_count += 1
            if result.is_poisoned or result.confidence > 0.3:
                color = _SEVERITY_COLORS[result.severity]
                evidence = " | ".join([e for r in result.layer_results for e in r.evidence][:2])
                table.add_row(
                    f"#{chunk.chunk_index:03d}",
                    f"[{color}]{result.severity.value.upper()}[/{color}]",
                    f"[{color}]{_make_bar(result.confidence)}[/{color}] {result.confidence:.2f}",
                    evidence[:80],
                )

        clean_count = len(results) - poisoned_count - suspicious_count
        console.print(f"\n[bold]Scanning {len(chunks)} chunks from:[/bold] {source}")
        console.print(table)
        console.print(
            f"Results: [green]{clean_count} clean[/green], "
            f"[yellow]{suspicious_count} suspicious[/yellow], "
            f"[red]{poisoned_count} malicious[/red]"
        )

    has_malicious = any(r.is_poisoned and r.severity == Severity.MALICIOUS for r in results)
    raise typer.Exit(1 if has_malicious else 0)
