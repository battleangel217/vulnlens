#!/usr/bin/env python3
"""Export a fine-tuned CodeBERT checkpoint to the ONNX artifact VulnGuard loads.

    python ml/kaggle/export_onnx.py \
        --checkpoint /kaggle/working/codebert-vuln \
        --out /kaggle/working/vuln-model

The output directory is the thing you copy to `vulnGuard.localModel.path`:

    model.onnx      int64 input_ids/attention_mask -> float32 logits [1, 2]
    vocab.json      RoBERTa byte-level BPE vocabulary
    merges.txt      RoBERTa BPE merges
    labels.json     {"labels": ["safe", "vulnerable"]}
    model_card.json provenance, checksums, validation drift

`onnxruntime-node` is not needed to export; it is needed to run the model in the
extension (`npm install onnxruntime-node`) and to run the local evaluation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

DEFAULT_OPSET = 14


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True, help="HF checkpoint directory")
    parser.add_argument("--out", type=Path, required=True, help="Artifact directory to create")
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--opset", type=int, default=DEFAULT_OPSET)
    parser.add_argument(
        "--no-quantize",
        action="store_true",
        help="Skip dynamic int8 quantization (bigger, slightly more accurate).",
    )
    parser.add_argument(
        "--keep-fp32",
        action="store_true",
        help="Also keep the unquantized graph as model.fp32.onnx.",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=1e-3,
        help="Max absolute logit drift allowed when validating the export (default: 1e-3).",
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def logits_from_onnx(session: Any, input_ids: Any, attention_mask: Any) -> Any:
    import numpy as np

    return session.run(
        ["logits"],
        {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        },
    )[0]


def check_drift(
    torch_logits: Any,
    onnx_logits: Any,
    tolerance: float,
    label: str,
) -> dict[str, Any]:
    import numpy as np

    delta = np.abs(np.asarray(torch_logits) - np.asarray(onnx_logits))
    maximum = float(delta.max()) if delta.size else 0.0
    result = {
        "stage": label,
        "max_abs_delta": round(maximum, 8),
        "mean_abs_delta": round(float(delta.mean()) if delta.size else 0.0, 8),
        "tolerance": tolerance,
        "passed": maximum <= tolerance,
    }
    status = "ok" if result["passed"] else "TOO LARGE"
    print(f"  {label}: max |delta| = {maximum:.6g} ({status})")
    return result


def main() -> int:
    args = parse_args()

    try:
        import numpy as np
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as error:
        print(
            f"Missing dependency: {error.name}. On Kaggle:\n"
            "  !pip install -q transformers torch onnx onnxruntime\n",
            file=sys.stderr,
        )
        return 1

    if not args.checkpoint.exists():
        print(f"No checkpoint at {args.checkpoint}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.checkpoint}")
    tokenizer = AutoTokenizer.from_pretrained(args.checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(args.checkpoint)
    model.eval()
    model.cpu()

    # Persist the tokenizer files next to the graph: the extension's own BPE
    # implementation reads vocab.json/merges.txt directly.
    tokenizer.save_pretrained(args.out)

    labels = []
    for index in range(model.config.num_labels):
        # config JSON round-trips keys as strings; normalise before lookup.
        label = model.config.id2label.get(index) or model.config.id2label.get(str(index)) or str(index)
        labels.append(str(label))

    if "vulnerable" not in [label.lower() for label in labels]:
        print(
            f"warning: labels {labels} do not name a 'vulnerable' class. "
            "The extension falls back to the last logit; verify the export.",
            file=sys.stderr,
        )

    (args.out / "labels.json").write_text(
        json.dumps({"labels": labels}, indent=2) + "\n", encoding="utf-8"
    )

    class LogitsOnly(torch.nn.Module):
        """Wrap the classification head so only the logits tensor is exported."""

        def __init__(self, model: Any) -> None:
            super().__init__()
            self.model = model

        def forward(self, input_ids: Any, attention_mask: Any) -> Any:
            return self.model(input_ids=input_ids, attention_mask=attention_mask).logits

    sample = tokenizer(
        [
            "def lookup(cursor, name):\n"
            '    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
            "    return cursor.fetchone()\n",
            "def add(a, b):\n    return a + b\n",
        ],
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=args.max_length,
    )
    input_ids = sample["input_ids"].to(torch.int64)
    attention_mask = sample["attention_mask"].to(torch.int64)

    with torch.no_grad():
        reference = LogitsOnly(model)(input_ids, attention_mask).cpu().numpy()

    fp32_path = args.out / "model.fp32.onnx"
    export_path = args.out / "model.onnx"

    print(f"Exporting ONNX (opset {args.opset}, dynamic batch and sequence length)")
    wrapper = LogitsOnly(model)
    torch.onnx.export(
        wrapper,
        (input_ids, attention_mask),
        str(fp32_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=args.opset,
        do_constant_folding=True,
    )

    drift: list[dict[str, Any]] = []

    try:
        import onnxruntime as ort

        session = ort.InferenceSession(str(fp32_path), providers=["CPUExecutionProvider"])
        fp32_out = logits_from_onnx(
            session,
            input_ids.numpy().astype(np.int64),
            attention_mask.numpy().astype(np.int64),
        )
        drift.append(check_drift(reference, fp32_out, args.tolerance, "fp32 export"))
    except ImportError:
        print("  onnxruntime not installed: skipped numerical validation", file=sys.stderr)
        session = None

    quantized = not args.no_quantize
    if quantized:
        try:
            from onnxruntime.quantization import QuantType, quantize_dynamic
        except ImportError:
            print("  onnxruntime.quantization missing: keeping fp32 graph", file=sys.stderr)
            quantized = False

    if quantized:
        print("Quantizing MatMul weights to int8 (dynamic)")
        quantize_dynamic(
            str(fp32_path),
            str(export_path),
            weight_type=QuantType.QInt8,
            per_channel=False,
            reduce_range=False,
        )

        try:
            import onnxruntime as ort

            q_session = ort.InferenceSession(str(export_path), providers=["CPUExecutionProvider"])
            q_out = logits_from_onnx(
                q_session,
                input_ids.numpy().astype(np.int64),
                attention_mask.numpy().astype(np.int64),
            )
            drift.append(check_drift(reference, q_out, args.tolerance, "int8 export"))
        except ImportError:
            pass
    else:
        shutil.copyfile(fp32_path, export_path)

    if not args.keep_fp32 and fp32_path.exists():
        fp32_path.unlink()

    if not any(item["passed"] for item in drift):
        print(
            "Numerical validation did not run or failed. Inspect model_card.json before shipping.",
            file=sys.stderr,
        )
    elif not all(item["passed"] for item in drift):
        failed = [item["stage"] for item in drift if not item["passed"]]
        print(
            f"warning: export drift above tolerance for: {', '.join(failed)}. "
            "Consider --no-quantize or a looser --tolerance.",
            file=sys.stderr,
        )

    metrics = None
    metrics_path = args.checkpoint / "training_metrics.json"
    if metrics_path.exists():
        shutil.copyfile(metrics_path, args.out / "training_metrics.json")
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    card = {
        "format": 1,
        "checkpoint": str(args.checkpoint),
        "max_length": args.max_length,
        "opset": args.opset,
        "quantized": quantized,
        "labels": labels,
        "inputs": ["input_ids", "attention_mask"],
        "output": "logits",
        "model_sha256": sha256(export_path),
        "model_bytes": export_path.stat().st_size,
        "validation": drift,
        "training": {
            "base_model": (metrics or {}).get("base_model"),
            "caveat": (metrics or {}).get("caveat"),
            "test": (metrics or {}).get("test"),
        },
    }
    (args.out / "model_card.json").write_text(
        json.dumps(card, indent=2) + "\n", encoding="utf-8"
    )

    print(f"\nWrote {export_path} ({card['model_bytes'] / 1e6:.1f} MB)")
    print(f"Artifact directory: {args.out}")
    print("Next: npm run eval:model -- --model", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())