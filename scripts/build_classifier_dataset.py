"""Build train/val/test JSONL datasets for DistilBERT classifier fine-tuning.

Usage:
    python scripts/build_classifier_dataset.py
    python scripts/build_classifier_dataset.py --builtin-only
    python scripts/build_classifier_dataset.py --output-dir /tmp/classifier_data
"""
from __future__ import annotations
import argparse
import json
import random
import sys
import warnings
from pathlib import Path

# Reuse the built-in corpora from the benchmark dataset builder
_SCRIPTS_DIR = Path(__file__).parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.build_benchmark_dataset import _BUILTIN_ATTACKS, _BUILTIN_BENIGN  # type: ignore[import]

DEFAULT_OUTPUT_DIR = _PROJECT_ROOT / "tests" / "benchmarks" / "datasets" / "classifier"


def _try_hf_injections() -> list[dict]:
    samples: list[dict] = []
    try:
        from datasets import load_dataset  # type: ignore[import]
        ds = load_dataset("jackhhao/jailbreak-classification", split="train", trust_remote_code=False)
        for row in ds:
            if row.get("type") == "injection":
                samples.append({"text": row["prompt"], "label": 1})
        print(f"  jackhhao/jailbreak-classification: {len(samples)} injection samples")
    except Exception as e:
        warnings.warn(f"jackhhao/jailbreak-classification unavailable: {e}", stacklevel=2)

    try:
        from datasets import load_dataset  # type: ignore[import]
        ds2 = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train", trust_remote_code=False)
        count = 0
        for row in ds2:
            text = row.get("Prompt") or row.get("text") or ""
            if text:
                samples.append({"text": text, "label": 1})
                count += 1
        print(f"  rubend18/ChatGPT-Jailbreak-Prompts: {count} samples")
    except Exception as e:
        warnings.warn(f"rubend18/ChatGPT-Jailbreak-Prompts unavailable: {e}", stacklevel=2)

    try:
        from datasets import load_dataset  # type: ignore[import]
        ds3 = load_dataset("notrichardren/prompt-injection-merged", split="train", trust_remote_code=False)
        count = 0
        for row in ds3:
            text = row.get("text") or row.get("prompt") or ""
            lbl = row.get("label", row.get("is_injection", -1))
            if text and lbl == 1:
                samples.append({"text": text, "label": 1})
                count += 1
        print(f"  notrichardren/prompt-injection-merged: {count} injection samples")
    except Exception as e:
        warnings.warn(f"notrichardren/prompt-injection-merged unavailable: {e}", stacklevel=2)

    return samples


def _try_hf_benign(n: int) -> list[dict]:
    samples: list[dict] = []
    try:
        from datasets import load_dataset  # type: ignore[import]
        ds = load_dataset("wikipedia", "20220301.en", split="train", streaming=True, trust_remote_code=False)
        for item in ds:
            para = item.get("text", "").split("\n\n")[0].strip()
            if 80 <= len(para) <= 800:
                samples.append({"text": para, "label": 0})
            if len(samples) >= n:
                break
        print(f"  Wikipedia: {len(samples)} benign samples")
    except Exception as e:
        warnings.warn(f"Wikipedia dataset unavailable: {e}", stacklevel=2)
    return samples


def _split(items: list[dict], seed: int = 42) -> tuple[list[dict], list[dict], list[dict]]:
    rng = random.Random(seed)
    shuffled = items[:]
    rng.shuffle(shuffled)
    n = len(shuffled)
    train_end = int(n * 0.8)
    val_end = train_end + int(n * 0.1)
    return shuffled[:train_end], shuffled[train_end:val_end], shuffled[val_end:]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    print(f"  Wrote {len(rows):>5} rows → {path}")


def build(output_dir: Path, builtin_only: bool = False) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Attack samples ---
    print("Collecting injection samples...")
    injections: list[dict] = []
    if not builtin_only:
        try:
            injections = _try_hf_injections()
        except Exception as e:
            warnings.warn(f"HuggingFace download failed entirely, falling back to built-in: {e}", stacklevel=2)

    # Pad / fill from built-in corpus
    builtin_inj = [{"text": t, "label": 1} for t in _BUILTIN_ATTACKS]
    if len(injections) < len(builtin_inj):
        existing_texts = {r["text"] for r in injections}
        injections += [r for r in builtin_inj if r["text"] not in existing_texts]
    print(f"  Total injection samples: {len(injections)}")

    # --- Benign samples ---
    print("Collecting benign samples...")
    n_benign_target = max(len(injections), 200)
    benign: list[dict] = []
    if not builtin_only:
        try:
            benign = _try_hf_benign(n_benign_target)
        except Exception as e:
            warnings.warn(f"HuggingFace benign download failed: {e}", stacklevel=2)

    builtin_ben = [{"text": t, "label": 0} for t in _BUILTIN_BENIGN]
    if len(benign) < len(builtin_ben):
        existing_texts = {r["text"] for r in benign}
        benign += [r for r in builtin_ben if r["text"] not in existing_texts]
    print(f"  Total benign samples: {len(benign)}")

    # --- Balance and split ---
    n_min = min(len(injections), len(benign))
    random.seed(42)
    random.shuffle(injections)
    random.shuffle(benign)
    all_data = injections[:n_min] + benign[:n_min]
    random.shuffle(all_data)

    train, val, test = _split(all_data)

    print("\nWriting splits...")
    _write_jsonl(output_dir / "train.jsonl", train)
    _write_jsonl(output_dir / "val.jsonl", val)
    _write_jsonl(output_dir / "test.jsonl", test)
    print(f"\nDone. Total {len(all_data)} samples split 80/10/10.")
    print(f"Train classifier with: python scripts/train_classifier.py --dataset-dir {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Anti-Venom classifier training datasets")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write train/val/test JSONL files",
    )
    parser.add_argument(
        "--builtin-only",
        action="store_true",
        help="Use only built-in curated samples (no HuggingFace download)",
    )
    args = parser.parse_args()
    build(output_dir=args.output_dir, builtin_only=args.builtin_only)
