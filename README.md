# VulnLens

Security review for Python, inside VS Code. Deterministic rules run on every
save and flag the obvious things in milliseconds. An optional AI layer then
confirms or rejects those findings, explains the data flow, and writes the fix.

A local CodeBERT triage model is also wired in, but it is **experimental and off
by default**: trained on C/C++, it does not transfer to Python (see
[`eval/MODEL_RESULTS.md`](eval/MODEL_RESULTS.md)). The rules and the AI verifier
are the parts that work.

The point of running rules first is cost and honesty: the model only sees
functions that already look suspicious, and every verdict can be compared against
the rule that produced it.

```
save ──▶ 6 CWE rules (offline, ~5ms) ──▶ diagnostics appear immediately
                  │
                  └──▶ candidates ──▶ local CodeBERT triage (experimental, off)
                                            │ nominates extra functions
                                            ▼
                                     BYOK / Copilot / Ollama
                                                │
                            confirms ──▶ severity + explanation + fix
                            rejects  ──▶ finding struck through as "false positive"
                            new issue ──▶ added finding the rules missed
```

## What it detects

| CWE | Class | Rule severity |
|---|---|---|
| CWE-89 | SQL injection (f-strings, `%`, `+`, `.format`) | high |
| CWE-78 | OS command injection (`os.system`, `shell=True`) | high |
| CWE-22 | Path traversal (untrusted input reaching `open`/`Path`) | medium |
| CWE-502 | Insecure deserialization (`pickle`, unsafe `yaml.load`) | critical |
| CWE-798 | Hardcoded credentials (literals, AWS keys, private keys, JWTs) | high |
| CWE-327 | Weak cryptography (MD5, SHA-1, DES, legacy TLS) | medium |

## Install

From the packaged VSIX:

```bash
code --install-extension vuln-lens-0.2.0.vsix
```

Or open the Extensions view, click `...`, and choose **Install from VSIX…**.

## Quick start (from source)

```bash
npm install
npm run compile
```

Press **F5**, open `demo/orders_api.py`, and save. Four findings appear with no
network access at all. Then pick an AI backend:

### Option A — your own API key (recommended)

The shortest path: no model download, and it works on any machine. Use any
OpenAI-compatible endpoint — OpenAI, Groq, Together, OpenRouter, Google AI
Studio, LM Studio, llama.cpp.

1. Point VulnLens at the endpoint. [Groq](https://console.groq.com) has a free
   tier and is a good default:

   ```json
   {
     "vulnLens.ai.mode": "byok",
     "vulnLens.byok.baseUrl": "https://api.groq.com/openai/v1",
     "vulnLens.byok.model": "llama-3.3-70b-versatile"
   }
   ```

2. Run **VulnLens: Set API Key (BYOK)** and paste the key. It goes into the OS
   keychain via `SecretStorage`, never into `settings.json`.
3. Run **VulnLens: Check AI Provider** to confirm the endpoint and model.

The function under review is sent to that endpoint. If that matters, use
Option C instead. Already have Copilot? Option B needs no key at all.

### Option B — GitHub Copilot

Set `vulnLens.ai.mode` to `copilot` and run **VulnLens: Analyze Current File
with AI** once to grant consent. Requires the official **GitHub Copilot Chat**
extension and a Copilot subscription. This does **not** work in `code-oss`
builds, which ship without Copilot Chat — use A or C there.

### Option C — Ollama (local, nothing leaves the machine)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:3b
```

Set `vulnLens.ai.mode` to `ollama`, set `vulnLens.ollama.model` to
`qwen2.5-coder:3b`, and raise `vulnLens.ai.timeoutMs` to `120000` on a
CPU-only machine. Then run **VulnLens: Check AI Provider**.

## What the AI layer does

- **Confirms or rejects** each rule finding. Rejected findings are kept, but
  rendered as a struck-through hint instead of an error, so false positives stop
  shouting without hiding the evidence.
- **Explains** the finding in the hover: severity, confidence, the data-flow
  reasoning, and which provider produced it.
- **Fixes** it. When the model returns a complete corrected function, the Quick
  Fix offers *Apply suggested fix*. The edit is refused if the code changed since
  the analysis ran, and refuses anything that is not a whole definition.
- **Finds what the rules missed** in the same function, added as separate
  findings with an `AI` badge.

### Suggest a secure rewrite

The fix above appears when the AI verifies a rule finding. To rewrite a function
the rules did not flag, put the cursor inside it and run **VulnLens: Suggest
Secure Rewrite** (also in the editor context menu). The model receives the
function plus any rule hints inside it, returns a complete replacement, and
VulnLens opens it in a side-by-side preview before asking whether to apply it.
If the function is already safe, it says so and changes nothing.

Requests are bounded: one function per call, default concurrency 2, 25s timeout,
`vulnLens.ai.maxChunks` per file (40), and a content-addressed cache so an
unchanged function is never billed twice. Cancelling a scan aborts in-flight
requests.

## Local triage model (experimental, off by default)

The plumbing exists: a fine-tuned CodeBERT classifier runs locally, in worker
threads, before the AI layer. It scores each function and promotes the ones above
`vulnLens.localModel.threshold` into the candidate list. It **cannot create a
finding on its own**: its only output is "send this function to the verifier".

**It is not enabled by default, and the first model is not useful on Python.**
Trained on PrimeVul (C/C++), it scored every chunk in the 50-file Python corpus
between 0.005 and 0.015 and covered 7/29 labelled issues only by flagging most
files. The full numbers are in [`eval/MODEL_RESULTS.md`](eval/MODEL_RESULTS.md).
A model trained on Python data is the M5 roadmap item; until then, leave this
layer off and use the rules plus the AI verifier.

If you want to experiment with your own artifact, it needs two things:

1. An exported artifact (`model.onnx`, `vocab.json`, `merges.txt`) from
   [`ml/`](ml/README.md). No model is committed to this repository.
2. `npm install onnxruntime-node` in the extension folder. The runtime is loaded
   lazily, so rules-only installs stay small. This path is for source installs;
   the packaged VSIX does not bundle the runtime.

```json
{
  "vulnLens.localModel.enabled": true,
  "vulnLens.localModel.path": "/absolute/path/to/vuln-model",
  "vulnLens.localModel.threshold": 0.35
}
```

Run **VulnLens: Check Local Model** to verify the graph, worker count, probe
latency, and threshold. The probe now warns when its score sits below the
threshold, which is the expected result for a C/C++ model on Python. A missing
runtime, missing file, or corrupt graph produces an actionable warning; it never
breaks activation or the rule layer. Inference failures are isolated per
function, and a timed-out worker is replaced.

Training and export happen on Kaggle, not here: `ml/data/prepare_primevul.py`,
`ml/kaggle/train_codebert.py`, and `ml/kaggle/export_onnx.py`.

## Commands

| Command | Purpose |
|---|---|
| `VulnLens: Scan Current File` | Rules only, instant |
| `VulnLens: Analyze Current File with AI` | Rules + verification (honours `ai.deepScan`) |
| `VulnLens: Suggest Secure Rewrite` | Rewrite the function under the cursor with AI and preview it |
| `VulnLens: Check AI Provider` | Reachability, model presence, actionable fix |
| `VulnLens: Check Local Model` | Load the ONNX artifact and score a probe function |
| `VulnLens: Set API Key (BYOK)` | Store key in the OS keychain |
| `VulnLens: Forget API Key` | Delete it |
| `VulnLens: Show Report` | Per-file summary in the output panel |
| `VulnLens: Clear Findings` | Reset |

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `vulnLens.enable` | `true` | Master switch |
| `vulnLens.scanOnSave` / `scanOnOpen` | `true` | When the rules run |
| `vulnLens.minSeverity` | `low` | Hide findings below this level |
| `vulnLens.ai.mode` | `off` | `off` \| `ollama` \| `byok` \| `copilot` |
| `vulnLens.ai.analyzeOnSave` | `true` | Verify rule findings on save |
| `vulnLens.ai.deepScan` | `false` | Also analyse functions no rule flagged |
| `vulnLens.ai.minConfidence` | `0.6` | Confidence needed to dismiss a finding |
| `vulnLens.ai.concurrency` | `2` | Parallel model requests (max 4) |
| `vulnLens.ai.timeoutMs` | `25000` | Per-request timeout |
| `vulnLens.ai.maxChunks` | `40` | Requests per file |
| `vulnLens.ollama.baseUrl` / `.model` | `127.0.0.1:11434` / `qwen2.5-coder:7b` | Local backend |
| `vulnLens.byok.baseUrl` / `.model` | OpenAI / `gpt-4o-mini` | Remote backend |
| `vulnLens.localModel.enabled` | `false` | Run the ONNX triage model |
| `vulnLens.localModel.path` | `""` | Artifact directory (`model.onnx`, tokenizer files) |
| `vulnLens.localModel.threshold` | `0.5` | P(vulnerable) needed to add a candidate |
| `vulnLens.localModel.maxChunks` | `40` | Functions scored per file |
| `vulnLens.localModel.workers` | `2` | Inference worker threads (max 4) |
| `vulnLens.localModel.timeoutMs` | `10000` | Per-function inference timeout |

## Privacy

AI mode is **off by default**. When you enable it, the analysed function — not
the file, not the repository, not your other tabs — is sent to the backend you
chose. `ollama` keeps everything on localhost. `byok` and `copilot` send code to
that vendor under your account. Diagnostics and the cache stay in memory and are
discarded when the window closes.

The local triage model is **offline**. It runs in worker threads inside the
extension host, reads only the configured artifact directory, and makes no
network requests.

## Suppressing a finding

```python
password = "..."  # vuln-ignore
password = "..."  # vuln-ignore: CWE-798
# vuln-ignore          <- applies to the next line
```

The Quick Fix *Ignore this finding* inserts the right comment for you.

## How it is structured

```
src/
  types.ts                 Severity, Chunk, RuleHit, CodeRule
  scan/
    chunker.ts             indentation splitter, no parser dependency
    python-syntax.ts       quote/bracket-aware argument parsing
    scanner.ts             dedupe, suppression, severity filter
    rules/python.ts        six pure CodeRule implementations
  lm/
    verdict.ts             zod schema + tolerant JSON extraction
    prompt.ts              the prompt and its output contract
    complete.ts            one retry when a reply is not valid JSON
    ollama.ts              POST /api/chat, format=json, temp=0
    openai.ts              POST /chat/completions, response_format fallback
    copilot.ts             vscode.lm, consent-safe, no retry
    candidates.ts          which functions deserve a request
    analyzer.ts            worker pool, timeout, cache, cancellation
  ui/
    present.ts             merge rules + verdicts into renderable findings
    hover.ts               explanation, confidence, suggested fix
    codeActions.ts         apply fix / ignore / re-analyze
  ml/
    bpe.ts                 RoBERTa byte-level BPE, no native dependency
    classifier.ts          lazy ONNX session, logits -> probabilities
    pool.ts                worker pool: startup, crash, timeout, close
    worker.ts              worker entry; owns the ONNX session
    triage.ts              score functions, isolate failures
    setup.ts               VS Code config and pool lifecycle
  extension.ts             wiring, commands, status bar, report
ml/
  data/prepare_primevul.py download, dedupe, split the training corpus
  kaggle/train_codebert.py class-weighted fine-tuning, PR-AUC, recall floors
  kaggle/export_onnx.py    ONNX export, int8 quantization, drift checks
eval/
  labeled/                 corpus source of truth, inline # KLABEL markers
  corpus/                  generated marker-free copies (gitignored)
  extract-labels.mjs       markers -> labels.json, strips the markers
  run_eval.ts              rules -> provider -> presentFindings, end to end
  run_model_eval.ts        ONNX triage: file precision/recall + issue coverage
  score.ts                 TP/FP/FN matching and precision/recall
  model_score.ts           threshold sweep for the local model
  RESULTS.md               committed output of the last rules run
```

Everything under `scan/`, `lm/verdict.ts`, `lm/prompt.ts`, `lm/analyzer.ts`,
`lm/candidates.ts`, `ui/present.ts`, and `ml/` (except `setup.ts`) is free of
`vscode` imports and is unit tested without an extension host. Only the
providers that need VS Code (`copilot.ts`, `index.ts`), the UI layer, and
`ml/setup.ts` touch the editor API.

## Evaluation

Rules are measured, not assumed. `eval/` contains a 50-file Python corpus with
line-level CWE labels: 20 straightforward vulnerable files, 20 clean files, and
10 hand-written adversarial files that probe known blind spots (multiline
expressions, interprocedural flow, aliased imports, encoded secrets).

```bash
npm run eval      # rules only, offline
npm run eval:ai   # rules, rules+ollama, rules+deep scan (needs Ollama)
```

The evaluator runs the production pipeline end to end — `scanPython` →
`buildCandidates` → provider → `presentFindings` — and matches predictions to
labels by CWE within ±2 lines. A finding the AI dismisses counts as a miss, not
a false positive, so a model cannot inflate precision by suppressing everything.

### Local model evaluation

The ONNX classifier is evaluated as a triage step, not as a CWE detector:

```bash
npm run eval:model -- --model /absolute/path/to/vuln-model
```

It writes `eval/MODEL_RESULTS.md` and `eval/results/model.json`, reporting
file-level precision/recall across a threshold sweep and, more importantly, how
many labelled issues fall inside a function the model scored above the threshold.
The sweep includes quantiles of the model's own scores, so a model whose range
sits below 0.1 is still measured instead of showing an empty table.
No model artifact is committed and `onnxruntime-node` is optional, so this
command exits with a clear message when either is missing rather than printing
invented numbers.

### Measured result: PrimeVul → Python

The full run used the complete PrimeVul corpus (175,797 train / 23,948
validation / 24,788 test functions; 2.6% vulnerable) for 3 epochs.

In-domain (C/C++, 24,647 test rows):

| Metric | Value |
|---|---|
| PR-AUC | 0.069 (baseline 0.021) |
| ROC-AUC | 0.808 |
| Recall @ 0.5 | 0.0% |
| Recall @ FPR 1% / 5% / 10% | 4.2% / 19.8% / 40.5% |

On the 50-file Python corpus the model is effectively flat: every chunk scored
between 0.00526 and 0.01534. At the best threshold (0.00537) it flags 22/28
vulnerable files and 13/22 clean files, and covers 7/29 labelled issues. At a
threshold high enough to avoid false positives it catches 2 of 28 files.

The conclusion is negative and worth stating plainly: **a PrimeVul-trained
CodeBERT does not transfer to Python.** Keep `vulnLens.localModel.enabled` off
unless you train on Python data. The rule engine and the AI verifier are the
parts that work.

### Current results (rules only)

| TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|
| 22 | 2 | 7 | 91.7% | 75.9% | 83.0% |

| CWE | TP | FP | FN |
|---|---|---|---|
| CWE-89 SQL injection | 4 | 0 | 2 |
| CWE-78 Command injection | 4 | 0 | 0 |
| CWE-22 Path traversal | 3 | 1 | 2 |
| CWE-502 Deserialization | 3 | 0 | 0 |
| CWE-798 Hardcoded secret | 5 | 0 | 2 |
| CWE-327 Weak crypto | 3 | 1 | 1 |

**These numbers are in-sample.** The corpus was authored alongside the rules, so
they describe behaviour on this corpus, not on arbitrary code. The adversarial
files are the honest part: they are the misses and false positives that remain.

Both false positives are deliberate:

- `h09_clean_whitelist.py` — input is checked against an allow-list before
  reaching `open()`. The rule tracks taint, not validation.
- `h10_clean_md5_dedup.py` — MD5 used for content deduplication, not for
  signatures or passwords. The rule cannot see the purpose.

Known misses, all by design of the current single-file, single-line analyzer:

- multiline SQL assembled across statements (`h01`)
- taint crossing a function boundary (`h02`)
- a secret built by concatenation (`h03`)
- an ORM query builder (`.extra()`) instead of `execute` (`h04`)
- a base64-encoded credential (`h06`)
- DES imported under a different name (`h07`)
- `Path` imported as `P` (`h08`)

Full output, including per-file predictions, is committed in
[`eval/RESULTS.md`](eval/RESULTS.md) and `eval/results/results.json`. AI modes
are written but not measured here: Ollama is not installed on the machine that
produced these numbers, and no API key was used. Running `npm run eval:ai` on a
machine with Ollama produces the rules+AI and deep-scan rows.

## Tests

```bash
npm test        # 141 tests, ~1s
npm run check   # typecheck + tests
```

The suite includes:

- a **zero-false-positive gate**: five safe Python fixtures must produce no
  findings, so every rule change is forced to justify itself
- prompt/verdict contract tests, including `82%` → `0.82`, fenced JSON, prose
  wrapped JSON, and rejection of malformed verdicts
- provider tests with stubbed HTTP, plus one **real-socket** test against a stub
  Ollama server (model discovery, retry, parsing)
- analyzer tests for concurrency, timeout, cancellation, and cache reuse
- merge tests for confirm, reject, and AI-only findings
- scoring tests for the evaluator itself: tolerance, CWE mismatch, duplicate
  findings, and empty-denominator handling
- tokenizer tests against the RoBERTa byte-level BPE contract, including
  multi-byte UTF-8 and merge ordering
- classifier tests with an injected fake runtime: two-logit, sigmoid, reordered
  labels, and every `LocalModelError` path
- worker-pool tests using a real child process: startup failure, crash
  replacement, per-request timeout, and queued requests during close
- triage tests for clamping, caps, short snippets, failure isolation, and
  timeouts; candidate tests prove rule hits win the request budget over model
  hits
- model-evaluation tests for threshold sweeps, file-level metrics, and issue
  coverage

## Known limitations

- **Single-line expressions only.** A call split across lines with a dynamic
  argument is missed. A real parser is a v2 dependency.
- **Intraprocedural taint only.** Assignments from a tainted name are followed,
  but data crossing a function boundary or a class attribute is not.
- **Rules are heuristics, AI is probabilistic.** A finding means "look here".
  A dismissal means "the model disagreed", not "proven safe".
- **The local model does not transfer to Python.** It is trained on PrimeVul
  (C/C++) and scored every Python chunk between 0.005 and 0.015 in the full run;
  see `eval/MODEL_RESULTS.md`. Local triage is off by default and should stay off
  until it is trained on Python data.
- **Python only.**

## Roadmap

- **M3** — evaluation harness over a hand-labelled Python corpus: precision,
  recall, and false positives on clean repositories for rules vs rules+AI vs
  deep scan. Rules are measured; AI rows need a local model or a key.
- **M4** — CodeBERT fine-tuned on PrimeVul, exported to ONNX, run in a worker
  thread as a local high-recall triage step in front of the LLM. Training and
  export scripts live in `ml/`; the artifact is intentionally not committed.
  **Done, with a negative transfer result**: the model is weak on C/C++ and flat
  on Python, so it stays off by default.
- **M5** — in-domain Python training data. PrimeVul is C/C++, and the measured
  transfer result confirms that a C/C++ model is not a Python detector. The next
  honest improvement is a labelled Python corpus (or a Python-specific encoder),
  evaluated with `npm run eval:model` before any threshold is advertised.

## License

MIT
