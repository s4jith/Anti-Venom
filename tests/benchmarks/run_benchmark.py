"""Benchmark harness: measures precision, recall, F1, and latency per layer.

Usage:
    python -m antivenom.benchmark                    # run all layers
    python -m antivenom.benchmark --fail-below-recall 0.90   # CI mode
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

DATASETS_DIR = Path(__file__).parent / "datasets"
ATTACKS_FILE = DATASETS_DIR / "known_attacks.jsonl"
BENIGN_FILE = DATASETS_DIR / "benign_docs.jsonl"

console = Console()


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run_benchmark(fail_below_recall: float | None = None) -> int:
    from antivenom.core.scanner import AntiVenomScanner
    from antivenom.core.config import ScannerConfig
    from antivenom.core.chunk import Chunk

    attacks = load_jsonl(ATTACKS_FILE)
    benign = load_jsonl(BENIGN_FILE)

    if not attacks or not benign:
        console.print("[yellow]Benchmark datasets not found. Run: python scripts/build_benchmark_dataset.py[/yellow]")
        return 0

    scanner = AntiVenomScanner(config=ScannerConfig(
        quarantine_on_detection=False,
        audit_log_path=None,
        db_path=None,
    ))

    all_texts = [(d["text"], True) for d in attacks] + [(d["text"], False) for d in benign]

    tp = fp = tn = fn = 0
    latencies: list[float] = []

    for text, is_attack in all_texts:
        chunk = Chunk(text=text, source_id="benchmark")
        t0 = time.perf_counter()
        result = scanner.scan_text(text)
        latencies.append((time.perf_counter() - t0) * 1000)

        if is_attack and result.is_poisoned:
            tp += 1
        elif is_attack and not result.is_poisoned:
            fn += 1
        elif not is_attack and result.is_poisoned:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]

    table = Table(title="Anti-Venom Benchmark Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    p_color = "green" if precision >= 0.9 else "yellow" if precision >= 0.7 else "red"
    r_color = "green" if recall >= 0.9 else "yellow" if recall >= 0.7 else "red"
    f_color = "green" if f1 >= 0.9 else "yellow" if f1 >= 0.7 else "red"

    table.add_row("Attack samples", str(len(attacks)))
    table.add_row("Benign samples", str(len(benign)))
    table.add_row("True Positives", str(tp))
    table.add_row("False Positives", str(fp))
    table.add_row("True Negatives", str(tn))
    table.add_row("False Negatives", str(fn))
    table.add_row("Precision", f"[{p_color}]{precision:.3f}[/{p_color}]")
    table.add_row("Recall", f"[{r_color}]{recall:.3f}[/{r_color}]")
    table.add_row("F1 Score", f"[{f_color}]{f1:.3f}[/{f_color}]")
    table.add_row("False Positive Rate", f"{fpr:.3f}")
    table.add_row("Latency p50", f"{p50:.1f}ms")
    table.add_row("Latency p95", f"{p95:.1f}ms")

    console.print(table)

    if fail_below_recall is not None and recall < fail_below_recall:
        console.print(f"\n[red]FAIL:[/red] Recall {recall:.3f} < required {fail_below_recall:.2f}")
        return 1

    console.print(f"\n[green]PASS[/green] — Recall {recall:.3f}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Anti-Venom benchmark harness")
    parser.add_argument("--fail-below-recall", type=float, default=None)
    args = parser.parse_args()
    sys.exit(run_benchmark(fail_below_recall=args.fail_below_recall))


if __name__ == "__main__":
    main()
