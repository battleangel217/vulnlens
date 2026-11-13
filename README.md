# VulnGuard

Security review for Python, inside VS Code. Deterministic rules run on every
save and flag the obvious things in milliseconds. An optional AI layer then
confirms or rejects those findings, explains the data flow, and writes the fix.

The point of running rules first is cost and honesty: the model only sees
functions that already look suspicious, and every verdict can be compared against
the rule that produced it.

```
save ──▶ 6 CWE rules (offline, ~5ms) ──▶ diagnostics appear immediately
                  │
                  └──▶ candidates only ──▶ Ollama / BYOK / Copilot
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

## Quick start

```bash
npm install
npm run compile
```

Press **F5**, open `demo/orders_api.py`, and save. Four findings appear with no
network access at all. Then pick an AI backend:

### Option A — local model (recommended, nothing leaves the machine)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b
```

Set `vulnGuard.ai.mode` to `ollama`, then run **VulnGuard: Check AI Provider**.

### Option B — your own API key

Run **VulnGuard: Set API Key (BYOK)**. The key goes into the OS keychain via
`SecretStorage`, never into `settings.json`. Any OpenAI-compatible endpoint works
(OpenAI, Groq, Together, OpenRouter, LM Studio, llama.cpp): point
`vulnGuard.byok.baseUrl` at it and set `vulnGuard.byok.model`.

### Option C — GitHub Copilot

Set `vulnGuard.ai.mode` to `copilot` and run **VulnGuard: Analyze Current File
with AI** once to grant consent. Requires the official **GitHub Copilot Chat**
extension and a Copilot subscription. This does **not** work in `code-oss`
builds, which ship without Copilot Chat — use A or B there.

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

Requests are bounded: one function per call, default concurrency 2, 25s timeout,
`vulnGuard.ai.maxChunks` per file (40), and a content-addressed cache so an
unchanged function is never billed twice. Cancelling a scan aborts in-flight
requests.

## Commands

| Command | Purpose |
|---|---|
| `VulnGuard: Scan Current File` | Rules only, instant |
| `VulnGuard: Analyze Current File with AI` | Rules + verification (honours `ai.deepScan`) |
| `VulnGuard: Check AI Provider` | Reachability, model presence, actionable fix |
| `VulnGuard: Set API Key (BYOK)` | Store key in the OS keychain |
| `VulnGuard: Forget API Key` | Delete it |
| `VulnGuard: Show Report` | Per-file summary in the output panel |
| `VulnGuard: Clear Findings` | Reset |

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `vulnGuard.enable` | `true` | Master switch |
| `vulnGuard.scanOnSave` / `scanOnOpen` | `true` | When the rules run |
| `vulnGuard.minSeverity` | `low` | Hide findings below this level |
| `vulnGuard.ai.mode` | `off` | `off` \| `ollama` \| `byok` \| `copilot` |
| `vulnGuard.ai.analyzeOnSave` | `true` | Verify rule findings on save |
| `vulnGuard.ai.deepScan` | `false` | Also analyse functions no rule flagged |
| `vulnGuard.ai.minConfidence` | `0.6` | Confidence needed to dismiss a finding |
| `vulnGuard.ai.concurrency` | `2` | Parallel model requests (max 4) |
| `vulnGuard.ai.timeoutMs` | `25000` | Per-request timeout |
| `vulnGuard.ai.maxChunks` | `40` | Requests per file |
| `vulnGuard.ollama.baseUrl` / `.model` | `127.0.0.1:11434` / `qwen2.5-coder:7b` | Local backend |
| `vulnGuard.byok.baseUrl` / `.model` | OpenAI / `gpt-4o-mini` | Remote backend |

## Privacy

AI mode is **off by default**. When you enable it, the analysed function — not
the file, not the repository, not your other tabs — is sent to the backend you
chose. `ollama` keeps everything on localhost. `byok` and `copilot` send code to
that vendor under your account. Diagnostics and the cache stay in memory and are
discarded when the window closes.

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
  extension.ts             wiring, commands, status bar, report
```

Everything under `scan/`, `lm/verdict.ts`, `lm/prompt.ts`, `lm/analyzer.ts`,
`lm/candidates.ts`, and `ui/present.ts` is free of `vscode` imports and is unit
tested without an extension host. Only the providers that need VS Code
(`copilot.ts`, `index.ts`) and the UI layer touch the editor API.

## Tests

```bash
npm test        # 90 tests, ~0.6s
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

## Known limitations

- **Single-line expressions only.** A call split across lines with a dynamic
  argument is missed. A real parser is a v2 dependency.
- **One-hop taint.** Data crossing a function boundary or a class attribute is
  not followed.
- **Rules are heuristics, AI is probabilistic.** A finding means "look here".
  A dismissal means "the model disagreed", not "proven safe".
- **Python only.**

## Roadmap

- **M3** — evaluation harness over a hand-labelled Python corpus: precision,
  recall, and false positives on clean repositories for rules vs rules+AI vs
  deep scan. This is where the claims get numbers.
- **M4** — CodeBERT fine-tuned on PrimeVul, exported to ONNX, run in a worker
  thread as a local high-recall triage step in front of the LLM.

## License

MIT
