# Local triage model

This directory trains and exports the optional ONNX classifier that sits between
the rule engine and the AI verifier.

```
functions ──▶ 6 rules ──▶ findings (always)
                │
                └──▶ CodeBERT ONNX ──▶ P(vulnerable) per function
                                            │
                        above threshold ────┴──▶ LLM verifier
```

The model is a **candidate generator**. It never creates a finding and never
assigns a CWE. That constraint is deliberate: a miscalibrated classifier can
cost an extra LLM request, but it cannot invent a diagnostic.

Nothing here runs on the extension's development machine. `ml/` is Python and
PyTorch; the extension is TypeScript and only loads the exported files.

## Artifact contract

`export_onnx.py` produces a directory the extension can load directly:

| File | Required | Purpose |
|---|---|---|
| `model.onnx` | yes | `input_ids`/`attention_mask` (int64) → `logits` (float32) |
| `vocab.json` | yes | RoBERTa byte-level BPE vocabulary |
| `merges.txt` | yes | RoBERTa BPE merges |
| `labels.json` | no | `{"labels": ["safe", "vulnerable"]}`; defaults to this order |
| `model_card.json` | no | provenance, checksums, export drift; ignored by the extension |
| `training_metrics.json` | no | copied from the checkpoint; ignored by the extension |

Inputs are fixed-width `[1, max_length]` with right padding. The extension's
tokenizer (`src/ml/bpe.ts`) adds `<s>`/`</s>`, pads with `<pad>` (id 1), and
truncates to 512 tokens. Both inputs are int64, matching what the export
declares.

## Kaggle walkthrough

Use a **GPU T4 x2** notebook with internet enabled. Run from the repository
root.

```python
!pip install -q transformers datasets scikit-learn onnx onnxruntime
!git clone https://github.com/<you>/vuln-guard.git
%cd vuln-guard
```

### 1. Prepare PrimeVul

```python
!python ml/data/prepare_primevul.py --out /kaggle/working/primevul
```

This downloads [`colin/PrimeVul`](https://huggingface.co/datasets/colin/PrimeVul)
(config `default`), drops functions longer than 20k characters, and removes
duplicates by a SHA-256 of the whitespace-normalised body. Test wins over
validation wins over train when a function appears in several splits, so no
training row leaks into evaluation.

Smoke run before committing to hours of GPU time:

```python
!python ml/data/prepare_primevul.py --out /kaggle/working/smoke --limit 2000
```

### 2. Fine-tune

```python
!python ml/kaggle/train_codebert.py \
    --data /kaggle/working/primevul \
    --output /kaggle/working/codebert-vuln \
    --epochs 3 --batch-size 16 --lr 2e-5
```

Plan for several hours on a T4. The script saves the checkpoint with the best
**validation PR-AUC**, then reloads it and evaluates the test split. It writes
`training_metrics.json` containing:

- PR-AUC and ROC-AUC
- recall at 1%, 5%, and 10% false-positive rate
- precision/recall/F1 at threshold 0.5 **and** at the selected threshold
- the selected threshold, chosen as the highest-precision point that still
  reaches `--min-recall` (default 0.95)

The 0.5 numbers are always recorded next to the tuned ones. If they look bad,
that is information, not a bug in the report.

Quick end-to-end smoke test (minutes, not a real model):

```python
!python ml/kaggle/train_codebert.py \
    --data /kaggle/working/smoke \
    --output /kaggle/working/codebert-smoke \
    --epochs 1 --max-train 500 --max-eval 200
```

### 3. Export

```python
!python ml/kaggle/export_onnx.py \
    --checkpoint /kaggle/working/codebert-vuln \
    --out /kaggle/working/vuln-model
```

The export verifies the ONNX graph against PyTorch logits and, when
`onnxruntime` is present, checks the int8-quantized graph too. Any drift above
`--tolerance` (default `1e-3`) is recorded in `model_card.json` and printed.

Options:

- `--no-quantize` keeps the fp32 graph (roughly 4× larger, marginally more
  accurate).
- `--keep-fp32` keeps both graphs; the extension loads `model.onnx`.
- `--max-length` must stay ≤ 512 to match the extension's tokenizer budget.

### 4. Bring it back

Download the artifact directory from Kaggle, then:

```bash
cd vuln-guard
npm install onnxruntime-node   # optional, ~100 MB; only needed for local inference
```

Set in VS Code:

```json
{
  "vulnGuard.localModel.enabled": true,
  "vulnGuard.localModel.path": "/absolute/path/to/vuln-model",
  "vulnGuard.localModel.threshold": 0.35
}
```

Run **VulnGuard: Check Local Model** to load the graph and score a known
SQL-injection probe. The command reports the worker count, probe probability,
latency, and the active threshold.

## Evaluate on the Python corpus

The C/C++ test split is not evidence that the model works on Python. Measure it
against the same 50 files the rules are measured on:

```bash
npm run eval:model -- --model /absolute/path/to/vuln-model
```

This writes `eval/MODEL_RESULTS.md` and `eval/results/model.json`. It reports two
different things:

1. **File-level precision/recall** — a file is flagged if its highest-scoring
   function crosses the threshold.
2. **Issue coverage** — whether the labelled line sits inside a function that
   scored above the threshold. This is the number that matters, because an
   uncovered issue never reaches the verifier.

Threshold guidance for triage: prefer a lower threshold than the F1 optimum.
A false negative is invisible; a false positive costs one bounded LLM request.

## Honest limitations

- **PrimeVul is C/C++.** Transfer to Python is the central caveat. The model
  learns C idioms (`memcpy`, pointer arithmetic, `sprintf`) that do not occur in
  Python, and misses Python-specific shapes (`pickle.loads`, f-string SQL,
  `subprocess` with `shell=True`). Treat the first export as a baseline, not a
  result.
- **Function-level labels, not line-level.** The corpus marks a whole function
  vulnerable. That is enough for triage, not for localisation.
- **50-file Python corpus.** Useful for catching regressions and for an honest
  sanity check; far too small for a benchmark claim.
- **Class weighting shifts toward recall.** Expect more false positives than a
  balanced model. The rule layer and the verifier exist to absorb them.
- **The model does not name a CWE.** Never display its output as a diagnosis.

If the Python evaluation is poor, the correct response is more in-domain Python
data (or a Python-specific model), not a lower threshold that hides the problem.

## Files

| Path | Role |
|---|---|
| `ml/data/prepare_primevul.py` | download, dedupe, write `train/valid/test.jsonl` |
| `ml/kaggle/train_codebert.py` | class-weighted fine-tuning + metrics + threshold selection |
| `ml/kaggle/export_onnx.py` | ONNX export, int8 quantization, drift checks, artifact card |
| `ml/requirements.txt` | Kaggle-side dependencies |

Runtime code lives in `src/ml/`: `bpe.ts` (tokenizer), `classifier.ts` (ONNX
session), `pool.ts`/`worker.ts` (worker threads), `triage.ts` (per-function
scoring), `setup.ts` (VS Code settings and pool lifecycle).
