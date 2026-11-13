# Local model evaluation

Model: `/home/battleangel/models/vulnlens/codebert-vuln`
Corpus: **50 files** (28 vulnerable, 22 clean), **29 labelled issues**.
File-level prediction uses the maximum chunk probability. Issue coverage counts a label as covered only when the chunk containing it scores at or above the threshold.

## Score distribution

| Category | Files | Min | Median | Max |
|---|---|---|---|---|
| vulnerable | 28 | 0.00526 | 0.00541 | 0.01534 |
| clean | 22 | 0.00532 | 0.00538 | 0.00879 |

Every chunk scored below **0.10**, so the fixed threshold grid never fires. The sweep also includes quantiles of this model's own scores; a flat row there is the honest result.

| Threshold | TP | FP | FN | TN | Precision | Recall | F1 | Issue coverage |
|---|---|---|---|---|---|---|---|---|
| 0.00537 | 22 | 13 | 6 | 9 | 62.9% | 78.6% | 69.8% | 7/29 (24.1%) |
| 0.00542 | 14 | 3 | 14 | 19 | 82.4% | 50.0% | 62.2% | 4/29 (13.8%) |
| 0.00551 | 6 | 2 | 22 | 20 | 75.0% | 21.4% | 33.3% | 0/29 (0.0%) |
| 0.00721 | 3 | 1 | 25 | 21 | 75.0% | 10.7% | 18.8% | 0/29 (0.0%) |
| 0.02 | 2 | 0 | 26 | 22 | 100.0% | 7.1% | 13.3% | 0/29 (0.0%) |
| 0.10 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.20 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.30 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.40 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.50 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.60 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.70 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.80 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |
| 0.90 | 0 | 0 | 28 | 22 | 100.0% | 0.0% | 0.0% | 0/29 (0.0%) |

Highest file-level F1: **0.00537** (69.8%).
For triage, prefer a lower threshold than the F1 optimum: a missed function never reaches the verifier.
