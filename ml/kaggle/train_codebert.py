#!/usr/bin/env python3
"""Fine-tune CodeBERT as a vulnerable/clean function classifier.

Run this on Kaggle (GPU), never on the extension's development machine:

    !python ml/kaggle/train_codebert.py \
        --data /kaggle/working/primevul \
        --output /kaggle/working/codebert-vuln

The output directory is a normal Hugging Face checkpoint and can be passed to
`export_onnx.py`. It also contains `training_metrics.json`, which records the
numbers the README quotes — including the ones that look bad.

Design notes:
  * PR-AUC, not accuracy, drives model selection. PrimeVul is imbalanced and a
    "predict clean" model would otherwise look excellent.
  * The decision threshold is chosen for a recall floor on validation. In this
    extension a false negative is a function the AI verifier never sees, while a
    false positive only costs one LLM request.
  * `training_metrics.json` always contains the 0.5-threshold numbers too, so the
    default threshold's honest performance is visible next to the tuned one.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

DEFAULT_MODEL = "microsoft/codebert-base"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Directory from prepare_primevul.py")
    parser.add_argument("--output", type=Path, required=True, help="Checkpoint output directory")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Base model (default: {DEFAULT_MODEL})")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--grad-accum", type=int, default=1)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.06)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.95,
        help="Validation recall floor used to pick the triage threshold (default: 0.95).",
    )
    parser.add_argument(
        "--max-train",
        type=int,
        default=0,
        help="Subsample the training split (0 = all). For smoke runs.",
    )
    parser.add_argument(
        "--max-eval",
        type=int,
        default=0,
        help="Subsample validation/test (0 = all). For smoke runs.",
    )
    parser.add_argument("--num-workers", type=int, default=2)
    parser.add_argument("--no-fp16", action="store_true", help="Disable mixed precision even on GPU.")
    return parser.parse_args()


# --------------------------------------------------------------------------
# Pure metric helpers. Kept free of torch so they can be reasoned about (and
# unit-tested) without a GPU.
# --------------------------------------------------------------------------


def recall_at_fpr(labels: Sequence[int], scores: Sequence[float], max_fpr: float) -> float:
    """Recall at the largest threshold whose false-positive rate is <= max_fpr."""
    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    positives = y == 1
    negatives = ~positives
    if positives.sum() == 0 or negatives.sum() == 0:
        return 0.0

    order = np.argsort(-s, kind="mergesort")
    y = y[order]
    tp = np.cumsum(y == 1)
    fp = np.cumsum(y == 0)

    fpr = fp / negatives.sum()
    recall = tp / positives.sum()
    allowed = fpr <= max_fpr
    return float(recall[allowed].max()) if allowed.any() else 0.0


def threshold_metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict[str, Any]:
    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    predicted = s >= threshold
    tp = int(np.sum(predicted & (y == 1)))
    fp = int(np.sum(predicted & (y == 0)))
    fn = int(np.sum(~predicted & (y == 1)))
    tn = int(np.sum(~predicted & (y == 0)))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    return {
        "threshold": round(float(threshold), 6),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
    }


def choose_threshold(
    labels: Sequence[int], scores: Sequence[float], min_recall: float
) -> float:
    """Highest-precision threshold that still meets the recall floor.

    Ties break toward the higher threshold, which trims false positives without
    spending any of the recall budget. If no threshold reaches the floor, fall
    back to the lowest observed score so nothing is silently dropped.
    """
    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    if len(s) == 0:
        return 0.5

    candidates = np.unique(s)
    best: tuple[float, float] | None = None  # (precision, threshold)
    for threshold in candidates:
        metrics = threshold_metrics(y, s, float(threshold))
        if metrics["recall"] + 1e-12 < min_recall:
            continue
        key = (metrics["precision"], float(threshold))
        if best is None or key > best:
            best = key

    return float(best[1]) if best is not None else float(candidates.min())


def summarise(labels: Sequence[int], scores: Sequence[float], min_recall: float) -> dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    threshold = choose_threshold(y, s, min_recall)

    result: dict[str, Any] = {
        "rows": int(len(y)),
        "vulnerable": int((y == 1).sum()),
        "clean": int((y == 0).sum()),
        "pr_auc": round(float(average_precision_score(y, s)), 6),
        "roc_auc": round(float(roc_auc_score(y, s)), 6),
        "at_0.5": threshold_metrics(y, s, 0.5),
        "at_selected": threshold_metrics(y, s, threshold),
        "selected_threshold": round(threshold, 6),
        "min_recall": min_recall,
    }
    for max_fpr in (0.01, 0.05, 0.10):
        result[f"recall_at_fpr_{max_fpr:g}"] = round(recall_at_fpr(y, s, max_fpr), 6)
    return result


# --------------------------------------------------------------------------
# Training
# --------------------------------------------------------------------------


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


def autocast(enabled: bool):
    import torch

    if not enabled:
        return nullcontext()
    if hasattr(torch, "amp") and hasattr(torch.amp, "autocast"):
        return torch.amp.autocast("cuda", dtype=torch.float16)
    return torch.cuda.amp.autocast(dtype=torch.float16)


def make_scaler(enabled: bool):
    import torch

    if hasattr(torch, "amp") and hasattr(torch.amp, "GradScaler"):
        return torch.amp.GradScaler("cuda", enabled=enabled)
    return torch.cuda.amp.GradScaler(enabled=enabled)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def subsample(rows: list[dict[str, Any]], limit: int, seed: int) -> list[dict[str, Any]]:
    if limit <= 0 or limit >= len(rows):
        return rows
    rng = random.Random(seed)
    return rng.sample(rows, limit)


def tokenize_rows(tokenizer: Any, rows: Iterable[dict[str, Any]], max_length: int) -> Any:
    from datasets import Dataset

    dataset = Dataset.from_dict(
        {
            "text": [row["code"] for row in rows],
            "label": [int(row["label"]) for row in rows],
        }
    )

    def encode(batch: dict[str, list[Any]]) -> dict[str, Any]:
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=max_length,
            padding=False,
        )

    return dataset.map(encode, batched=True, remove_columns=["text"])


def evaluate(model: Any, loader: Any, device: Any, fp16: bool) -> tuple[list[float], list[int]]:
    import torch

    model.eval()
    scores: list[float] = []
    labels: list[int] = []

    with torch.no_grad():
        for batch in loader:
            labels.extend(batch.pop("labels").tolist())
            batch = {key: value.to(device) for key, value in batch.items()}
            with autocast(fp16):
                logits = model(**batch).logits
            scores.extend(torch.sigmoid(logits.float()).cpu().tolist())

    return scores, labels


def main() -> int:
    args = parse_args()

    try:
        import torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            get_linear_schedule_with_warmup,
        )
        from torch.utils.data import DataLoader
    except ImportError as error:
        print(
            f"Missing dependency: {error.name}. On Kaggle:\n"
            "  !pip install -q transformers datasets scikit-learn\n",
            file=sys.stderr,
        )
        return 1

    seed_everything(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    fp16 = device.type == "cuda" and not args.no_fp16

    files = {"train": "train.jsonl", "validation": "valid.jsonl", "test": "test.jsonl"}
    raw: dict[str, list[dict[str, Any]]] = {}
    for split, name in files.items():
        path = args.data / name
        if not path.exists():
            print(f"Missing {path}. Run prepare_primevul.py first.", file=sys.stderr)
            return 1
        raw[split] = load_jsonl(path)

    raw["train"] = subsample(raw["train"], args.max_train, args.seed)
    raw["validation"] = subsample(raw["validation"], args.max_eval, args.seed)
    raw["test"] = subsample(raw["test"], args.max_eval, args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    encoded = {split: tokenize_rows(tokenizer, rows, args.max_length) for split, rows in raw.items()}

    collator = DataCollatorWithPadding(tokenizer=tokenizer)
    loaders = {
        split: DataLoader(
            dataset,
            batch_size=args.batch_size,
            shuffle=(split == "train"),
            collate_fn=collator,
            num_workers=args.num_workers,
            pin_memory=device.type == "cuda",
        )
        for split, dataset in encoded.items()
    }

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=2,
        id2label={0: "safe", 1: "vulnerable"},
        label2id={"safe": 0, "vulnerable": 1},
    ).to(device)

    train_labels = np.asarray(encoded["train"]["label"], dtype=np.int64)
    positives = int((train_labels == 1).sum())
    negatives = int((train_labels == 0).sum())
    if positives == 0 or negatives == 0:
        print(
            "Training split needs both classes. PrimeVul lists vulnerable rows "
            "first, so re-run prepare_primevul.py with --limit 0 (full corpus) "
            "or a per-class smoke limit.",
            file=sys.stderr,
        )
        return 1

    # Inverse-frequency weights: the model is a candidate generator, so a missed
    # vulnerable function costs more than a false alarm. This is deliberately not
    # "balanced accuracy" theatre — it shifts the operating point toward recall.
    weights = torch.tensor(
        [len(train_labels) / (2 * negatives), len(train_labels) / (2 * positives)],
        dtype=torch.float32,
        device=device,
    )
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)

    updates_per_epoch = math.ceil(len(loaders["train"]) / max(1, args.grad_accum))
    total_steps = max(1, updates_per_epoch * args.epochs)
    warmup_steps = int(total_steps * args.warmup_ratio)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)
    scaler = make_scaler(fp16)

    args.output.mkdir(parents=True, exist_ok=True)
    history: list[dict[str, Any]] = []
    best_score = -1.0
    best_epoch = -1

    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        seen = 0
        step = 0

        def apply_step() -> None:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            optimizer.zero_grad(set_to_none=True)

        for step, batch in enumerate(loaders["train"], start=1):
            labels = batch.pop("labels").to(device)
            batch = {key: value.to(device) for key, value in batch.items()}

            with autocast(fp16):
                logits = model(**batch).logits
                loss = loss_fn(logits, labels) / max(1, args.grad_accum)

            scaler.scale(loss).backward()
            running += float(loss.detach()) * max(1, args.grad_accum) * labels.size(0)
            seen += labels.size(0)

            if step % max(1, args.grad_accum) == 0:
                apply_step()

        # Flush a trailing partial accumulation window instead of discarding it.
        if step % max(1, args.grad_accum) != 0:
            apply_step()

        valid_scores, valid_labels = evaluate(model, loaders["validation"], device, fp16)
        valid = summarise(valid_labels, valid_scores, args.min_recall)
        history.append(
            {
                "epoch": epoch,
                "train_loss": round(running / max(1, seen), 6),
                "validation": valid,
            }
        )
        print(
            f"epoch {epoch}: loss {running / max(1, seen):.4f}  "
            f"val PR-AUC {valid['pr_auc']:.4f}  "
            f"recall@0.5 {valid['at_0.5']['recall']:.4f}  "
            f"selected threshold {valid['selected_threshold']:.4f}",
            flush=True,
        )

        # Select on PR-AUC: threshold-free and insensitive to the chosen floor.
        if valid["pr_auc"] > best_score:
            best_score = valid["pr_auc"]
            best_epoch = epoch
            model.save_pretrained(args.output)
            tokenizer.save_pretrained(args.output)
            print(f"  saved checkpoint to {args.output}", flush=True)

    if best_epoch == -1:
        print("No checkpoint was saved.", file=sys.stderr)
        return 1

    # Reload the best checkpoint rather than trusting the last epoch in memory.
    best_model = AutoModelForSequenceClassification.from_pretrained(args.output).to(device)
    valid_scores, valid_labels = evaluate(best_model, loaders["validation"], device, fp16)
    test_scores, test_labels = evaluate(best_model, loaders["test"], device, fp16)

    validation = summarise(valid_labels, valid_scores, args.min_recall)
    test = summarise(test_labels, test_scores, args.min_recall)

    metrics = {
        "base_model": args.model,
        "best_epoch": best_epoch,
        "args": {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()},
        "label_weights": {"safe": float(weights[0]), "vulnerable": float(weights[1])},
        "validation": validation,
        "test": test,
        "history": history,
        "caveat": (
            "PrimeVul is C/C++. These numbers measure C/C++ function classification, "
            "not Python performance. Run eval/run_model_eval.ts on the Python corpus "
            "before quoting them for this extension."
        ),
    }

    (args.output / "training_metrics.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )

    print("\nTest metrics (best checkpoint):")
    print(f"  PR-AUC            {test['pr_auc']:.4f}")
    print(f"  ROC-AUC           {test['roc_auc']:.4f}")
    print(f"  recall @ FPR 1%   {test['recall_at_fpr_0.01']:.4f}")
    print(f"  recall @ FPR 5%   {test['recall_at_fpr_0.05']:.4f}")
    print(f"  recall @ 0.5      {test['at_0.5']['recall']:.4f}")
    print(f"  selected threshold {test['selected_threshold']:.4f} -> recall {test['at_selected']['recall']:.4f}")
    print(f"\nWrote {args.output / 'training_metrics.json'}")
    print("Export with: python ml/kaggle/export_onnx.py --checkpoint", args.output, "--out ml/out")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())