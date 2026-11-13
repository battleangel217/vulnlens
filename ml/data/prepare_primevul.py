#!/usr/bin/env python3
"""Prepare PrimeVul for fine-tuning.

PrimeVul is C/C++ data, but it is the only large function-level vulnerability
corpus with a clean vulnerable/benign split that fits a Kaggle session. The
cross-language transfer to Python is a real limitation, not a detail to hide;
see ml/README.md.

Output layout (default `ml/data/primevul`):

    train.jsonl
    valid.jsonl
    test.jsonl
    manifest.json

Each line is `{"code": "...", "label": 0|1, "cwe": ["CWE-..."], "project": "..."}`.

The script is idempotent: rows are deduplicated by a hash of the whitespace-
normalised function body, across all splits. Validation and test are never
polluted by a function that also appears in train.

Usage:
    python ml/data/prepare_primevul.py
    python ml/data/prepare_primevul.py --limit 2000 --out /tmp/primevul-smoke
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Iterator

DEFAULT_OUT = Path("ml/data/primevul")
MAX_CODE_CHARS = 20_000

WHITESPACE = re.compile(r"\s+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="colin/PrimeVul",
        help="Hugging Face dataset id (default: colin/PrimeVul)",
    )
    parser.add_argument(
        "--config",
        default="default",
        help="Dataset config: default or paired (default: default)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output directory (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "Keep at most N rows per class per split (0 = all). This keeps both "
            "classes in a smoke run; PrimeVul lists vulnerable rows first."
        ),
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=MAX_CODE_CHARS,
        help=f"Skip functions longer than this many characters (default: {MAX_CODE_CHARS}).",
    )
    return parser.parse_args()


def normalise(code: str) -> str:
    """Whitespace-insensitive form used only for hashing."""
    return WHITESPACE.sub(" ", code).strip()


def fingerprint(code: str) -> str:
    return hashlib.sha256(normalise(code).encode("utf-8", errors="replace")).hexdigest()


def coerce_label(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return 1 if int(value) == 1 else 0
    text = str(value).strip().lower()
    if text in {"1", "vulnerable", "true", "yes"}:
        return 1
    return 0


def coerce_cwe(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value and value != "None" else []
    try:
        return [str(item) for item in value if item and str(item) != "None"]
    except TypeError:
        return []


def to_item(row: Any) -> dict[str, Any] | None:
    code = row.get("func") or ""
    if not isinstance(code, str) or not code.strip():
        return None
    return {
        "code": code,
        "label": coerce_label(row.get("target")),
        "cwe": coerce_cwe(row.get("cwe")),
        "project": row.get("project") or "",
    }


def rows(dataset: Any, split: str, limit: int) -> Iterator[dict[str, Any]]:
    """Yield rows, keeping at most `limit` per class when limit > 0.

    PrimeVul lists vulnerable functions first, so taking the first N rows of a
    split produces a single-class training set. Sampling per class keeps smoke
    runs trainable without scanning the whole corpus.
    """
    if split not in dataset:
        return

    stream = dataset[split]

    if limit <= 0:
        for row in stream:
            item = to_item(row)
            if item is not None:
                yield item
        return

    kept = {0: 0, 1: 0}
    for row in stream:
        item = to_item(row)
        if item is None:
            continue

        label = item["label"]
        if kept[label] >= limit:
            if kept[0] >= limit and kept[1] >= limit:
                break
            continue

        kept[label] += 1
        yield item


def write_split(path: Path, items: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"rows": 0, "vulnerable": 0, "clean": 0}
    with path.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
            counts["rows"] += 1
            counts["vulnerable" if item["label"] == 1 else "clean"] += 1
    return counts


def main() -> int:
    args = parse_args()

    try:
        from datasets import load_dataset
    except ImportError:
        print(
            "Missing dependency. On Kaggle: !pip install -q datasets\n"
            "Locally: python -m pip install datasets",
            file=sys.stderr,
        )
        return 1

    print(f"Loading {args.dataset} [{args.config}]...", flush=True)
    dataset = load_dataset(args.dataset, args.config)

    # Test first so that it keeps every row, then validation, then train. If a
    # function appears in more than one split, it is kept only in the earliest
    # split in this order. That biases against leakage, at the cost of a few
    # training rows — the right trade for an honest evaluation.
    order = [split for split in ("test", "validation", "train") if split in dataset]
    seen: set[str] = set()
    kept: dict[str, list[dict[str, Any]]] = {split: [] for split in order}
    skipped: dict[str, int] = {split: 0 for split in order}
    duplicates = 0

    for split in order:
        for item in rows(dataset, split, args.limit):
            if len(item["code"]) > args.max_chars:
                skipped[split] += 1
                continue
            digest = fingerprint(item["code"])
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            kept[split].append(item)

    args.out.mkdir(parents=True, exist_ok=True)
    names = {"train": "train.jsonl", "validation": "valid.jsonl", "test": "test.jsonl"}
    stats: dict[str, Any] = {}

    for split, items in kept.items():
        if not items:
            print(f"warning: split {split!r} has no rows", file=sys.stderr)
            continue
        stats[split] = write_split(args.out / names[split], items)
        stats[split]["skipped_too_long"] = skipped[split]

    manifest = {
        "dataset": args.dataset,
        "config": args.config,
        "limit_per_class": args.limit,
        "max_chars": args.max_chars,
        "dedupe": "sha256 of whitespace-normalised function body",
        "duplicates_removed": duplicates,
        "splits": stats,
        "note": "PrimeVul is C/C++; transfer to Python is evaluated separately.",
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    for split, counts in stats.items():
        total = max(1, counts["rows"])
        share = counts["vulnerable"] / total
        print(
            f"{split:10s} {counts['rows']:>7d} rows  "
            f"{counts['vulnerable']:>7d} vulnerable ({share:.1%})  "
            f"{counts['skipped_too_long']} too long"
        )
    print(f"removed {duplicates} cross-split duplicate(s)")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())