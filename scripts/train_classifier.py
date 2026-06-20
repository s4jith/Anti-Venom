"""Fine-tune DistilBERT for prompt injection classification.

Usage:
    python scripts/train_classifier.py --dataset-dir tests/benchmarks/datasets/classifier/
    python scripts/train_classifier.py --dataset-dir /data/clf --output-dir /data/model --epochs 5
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _check_deps() -> None:
    import importlib.util
    missing = [
        pkg for pkg in ("transformers", "torch", "sklearn")
        if importlib.util.find_spec(pkg) is None
    ]
    if missing:
        print(
            f"Missing required packages: {', '.join(missing)}\n"
            "Install with: pip install antivenom[classifier] scikit-learn",
            file=sys.stderr,
        )
        sys.exit(1)


def _load_jsonl(path: Path) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        texts.append(row["text"])
        labels.append(int(row["label"]))
    return texts, labels


def train(
    dataset_dir: Path,
    output_dir: Path,
    model_name: str,
    epochs: int,
    batch_size: int,
) -> None:
    _check_deps()

    import numpy as np
    from datasets import Dataset  # type: ignore[import]
    from sklearn.metrics import (  # type: ignore[import]
        accuracy_score,
        precision_recall_fscore_support,
    )
    from transformers import (  # type: ignore[import]
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    train_path = dataset_dir / "train.jsonl"
    val_path = dataset_dir / "val.jsonl"
    for p in (train_path, val_path):
        if not p.exists():
            print(f"Dataset file not found: {p}", file=sys.stderr)
            print("Run: python scripts/build_classifier_dataset.py first.", file=sys.stderr)
            sys.exit(1)

    print(f"Loading datasets from {dataset_dir}...")
    train_texts, train_labels = _load_jsonl(train_path)
    val_texts, val_labels = _load_jsonl(val_path)
    print(f"  Train: {len(train_texts)} | Val: {len(val_texts)}")

    print(f"Loading tokenizer: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=256, padding="max_length")

    train_ds = Dataset.from_dict({"text": train_texts, "label": train_labels})
    val_ds = Dataset.from_dict({"text": val_texts, "label": val_labels})
    train_ds = train_ds.map(tokenize, batched=True)
    val_ds = val_ds.map(tokenize, batched=True)
    train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
    val_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

    print(f"Loading model: {model_name}")
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        acc = accuracy_score(labels, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(labels, preds, average="binary", zero_division=0)
        return {"accuracy": acc, "precision": float(prec), "recall": float(rec), "f1": float(f1)}

    output_dir.mkdir(parents=True, exist_ok=True)

    # transformers >=4.46 renamed `evaluation_strategy` -> `eval_strategy`.
    import inspect
    eval_kw = (
        "eval_strategy"
        if "eval_strategy" in inspect.signature(TrainingArguments.__init__).parameters
        else "evaluation_strategy"
    )
    ta_kwargs = {
        "output_dir": str(output_dir),
        "num_train_epochs": epochs,
        "per_device_train_batch_size": batch_size,
        "per_device_eval_batch_size": batch_size,
        eval_kw: "epoch",
        "save_strategy": "epoch",
        "load_best_model_at_end": True,
        "metric_for_best_model": "f1",
        "logging_steps": 50,
        "report_to": "none",
    }
    training_args = TrainingArguments(**ta_kwargs)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
    )

    print(f"\nTraining for {epochs} epoch(s) with batch_size={batch_size}...")
    trainer.train()

    print("\nFinal evaluation on validation set:")
    metrics = trainer.evaluate()
    for k, v in metrics.items():
        print(f"  {k}: {v:.4f}" if isinstance(v, float) else f"  {k}: {v}")

    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    print(f"\nModel saved to {output_dir}")
    print(f"Set env var: ANTIVENOM_CLASSIFIER_MODEL={output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fine-tune DistilBERT for Anti-Venom injection classification")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("tests/benchmarks/datasets/classifier"),
        help="Directory containing train.jsonl and val.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("models/antivenom-classifier"),
        help="Directory to save the fine-tuned model",
    )
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs (default: 3)")
    parser.add_argument("--batch-size", type=int, default=16, help="Per-device batch size (default: 16)")
    parser.add_argument(
        "--model",
        default="distilbert-base-uncased",
        help="Base model name or path (default: distilbert-base-uncased)",
    )
    args = parser.parse_args()
    train(
        dataset_dir=args.dataset_dir,
        output_dir=args.output_dir,
        model_name=args.model,
        epochs=args.epochs,
        batch_size=args.batch_size,
    )
