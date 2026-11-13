# VulnGuard

Flags vulnerable Python code directly in VS Code: red squiggles on the exact line,
a severity in the Problems panel, and a status bar counter. It runs on every save,
takes milliseconds, and has no network dependency.

This is **milestone 1** of a larger project: deterministic rules first, then LLM
verdicts, then a fine-tuned local model. The rule engine exists so the AI layer
has something honest to be measured against.

## What it detects (v1)

| CWE | Class | Default severity |
|---|---|---|
| CWE-89 | SQL injection (f-strings, `%`, `+`, `.format`) | high |
| CWE-78 | OS command injection (`os.system`, `shell=True`) | high |
| CWE-22 | Path traversal (untrusted input reaching `open`/`Path`) | medium |
| CWE-502 | Insecure deserialization (`pickle`, unsafe `yaml.load`) | critical |
| CWE-798 | Hardcoded credentials (literals, AWS keys, private keys, JWTs) | high |
| CWE-327 | Weak cryptography (MD5, SHA-1, DES, legacy TLS) | medium |

## Run it

```bash
npm install
npm run compile
```

Then press **F5** ("Run Extension") and open `demo/orders_api.py`. Save the file.
You should get exactly four findings — SQL injection, command injection, a
hardcoded password, and `pickle.loads` — and nothing on the three labelled safe
counterparts.

Check the core logic without launching VS Code:

```bash
npm test        # 35 tests, runs in ~1s
npm run check   # typecheck + tests
```

## How it works

```
source
  └─ chunker.ts        split into functions + top-level module statements
       └─ rules/*.ts   6 pure CodeRule implementations
            └─ scanner.ts   de-duplicate, apply suppressions, sort, filter
                 └─ extension.ts  DiagnosticCollection + status bar
```

Everything under `src/scan/` is a pure function with no `vscode` import, which is
why the rule tests need no extension host. The editor glue is ~180 lines in
`src/extension.ts`.

### Chunking

Python is split by indentation into function-level chunks (decorators included)
plus `<module>` chunks for top-level statements. This is not a parser — it is
intentionally dependency-free and runs in under a millisecond. The chunk
boundaries are also the unit that the future LLM layer will send for analysis,
so a single function is the smallest thing ever transmitted.

### Design choices that keep the false-positive rate down

- **Parameterized queries are explicitly excluded.** `execute("... %s", params)`
  produces nothing; only *interpolated* query text is flagged.
- **Argument lists are safe.** `subprocess.run(["ls", dir])` is silent;
  `shell=True` with a dynamic string is not.
- **One-hop taint tracking.** `name = request.args["f"]` followed by `open(name)`
  is caught, and a `basename`/`realpath`/`secure_filename` call clears the taint.
- **Placeholders and env lookups are ignored.** `os.environ["DB_PASSWORD"]`,
  `"your-api-key-here"`, `"changeme"`, and `"client_secret"` (a config key name)
  are not findings.
- **Safe loaders are ignored.** `yaml.safe_load`, `Loader=yaml.SafeLoader`,
  `torch.load(..., weights_only=True)` are silent.

Because of this, `npm test` includes a hard gate: **the five files in
`test/fixtures/safe/` must produce zero findings.** Every rule change has to keep
that green or explicitly justify a new exception.

## Suppressing a finding

```python
password = "..."  # vuln-ignore
password = "..."  # vuln-ignore: CWE-798
# vuln-ignore          <- applies to the next line
```

A bare `vuln-ignore` suppresses anything on that line (or the line below); a
qualified one only suppresses the matching CWE.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `vulnGuard.enable` | `true` | Master switch |
| `vulnGuard.scanOnSave` | `true` | Scan on save |
| `vulnGuard.scanOnOpen` | `true` | Scan on open |
| `vulnGuard.minSeverity` | `low` | Hide findings below this level |

## Known limitations (v1)

- **Single-line expressions only.** A call split across lines with a dynamic
  argument is missed. Deliberate: a real parser is a v2 dependency.
- **One-hop taint.** Data flowing through a function argument, a class attribute,
  or two chained assignments is not followed.
- **No interprocedural analysis.** Sanitizers in helper functions are invisible.
- **Patterns, not proofs.** These are high-precision heuristics. A finding means
  "look here", not "exploitable".
- Python only.

## Roadmap

- **M2** — `LlmProvider` interface with Ollama, BYOK, and `vscode.lm` (Copilot)
  adapters. Rules become a prefilter; the model verifies and explains. Hover
  provider plus a "Suggest fix" code action.
- **M3** — evaluation harness over a hand-labelled Python corpus, reporting
  precision/recall and false positives on clean repos, so claims are measured.
- **M4** — CodeBERT fine-tuned on PrimeVul, exported to ONNX, run in a worker
  thread. Local triage filters ~90% of chunks; only candidates reach an LLM.

`# vuln-ignore` exists from day one on purpose: a scanner that cannot be
silenced gets uninstalled before it gets trusted.

## License

MIT
