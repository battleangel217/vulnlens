# Changelog

## 0.2.0

First packaged release.

### Added

- Deterministic Python rules for CWE-89, CWE-78, CWE-22, CWE-502, CWE-798, and
  CWE-327, running on save with no network access.
- AI verification through Ollama, any OpenAI-compatible BYOK endpoint, or GitHub
  Copilot (dormant unless selected).
- Diagnostics, hover text, code actions, and a report command.
- Evaluation harness over a 50-file Python corpus. Rules score 22 TP / 2 FP /
  7 FN (91.7% precision, 75.9% recall).
- Experimental local ONNX triage, off by default.

### Known limitations

- Taint tracking is intraprocedural and single-line.
- The PrimeVul-trained local model does not transfer to Python. It is kept off
  by default; the measured result is in `eval/MODEL_RESULTS.md`.
