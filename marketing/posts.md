# VulnLens launch posts

Two posts, in the order they should go out:

1. **The training story** — published first. It is the honest, technical post and
   it earns the launch. It also sets expectations: the local model did not work.
2. **The launch** — published 1–2 days later, once the training post has been
   seen.

Rules for both: do not claim the model works on Python, do not claim the rules
find everything, and keep the numbers exactly as measured.

---

## Post 1 — the training story

### LinkedIn

I fine-tuned CodeBERT to find Python vulnerabilities.

The result was a clean negative, and it taught me more than a good number would have.

Here is what happened.

I trained on PrimeVul: 175,797 C/C++ functions, 3 epochs on a Kaggle GPU. In-domain, the model was weak but not dead:
• PR-AUC 0.069 (baseline 0.021)
• ROC-AUC 0.808
• Recall at a 10% false-positive rate: 40.5%

Then I ran it on 50 Python files from my own test corpus.

Every function scored between 0.005 and 0.015. Not "low confidence" — flat. At the threshold that avoided false positives, it caught 2 of 28 vulnerable files and 0 of 29 labelled issues. At the threshold that caught the most, it flagged 13 of 22 clean files.

The model had learned C/C++ tokens and patterns, not Python semantics. Domain transfer failed.

So I changed the plan:
• Shipped the deterministic rule engine, which measured 22 true positives, 2 false positives and 7 misses on the same corpus (91.7% precision, 75.9% recall)
• Kept the model in the repo as an experimental, off-by-default layer
• Wrote the negative result down, with numbers, in the README

The lesson: measure transfer before you market a model. A classifier that looks acceptable in-domain can be useless in another language.

Repo: https://github.com/battleangel217/vulnlens

#MachineLearning #AppSec #Python #CodeBERT #AI

### X / Twitter (thread)

1/
I fine-tuned CodeBERT to find Python vulnerabilities.

It didn't work.

Here's the honest data 🧵

2/
Trained on PrimeVul: 175,797 C/C++ functions, 3 epochs on a Kaggle GPU.

In-domain it was weak but alive:
• PR-AUC 0.069 (baseline 0.021)
• ROC-AUC 0.808
• Recall @ 10% FPR: 40.5%

3/
On 50 Python files, every function scored between 0.005 and 0.015. Flat.

Zero-FP threshold: 2 of 28 vulnerable files, 0 of 29 labelled issues.
Best-coverage threshold: 7 of 29 issues, but 13 of 22 clean files flagged too.

4/
The model learned C/C++ syntax, not Python semantics.

Domain transfer failed. Not a tuning bug — a data problem.

5/
So I shipped the rules instead:
22 TP / 2 FP / 7 FN on the same corpus
91.7% precision, 75.9% recall

The model stays off by default and the negative result is documented.

6/
Repo: https://github.com/battleangel217/vulnlens

---

## Post 2 — the launch

### LinkedIn

VulnLens 0.2.0 is live on the VS Code Marketplace.

It is a Python security reviewer that runs where you write code.

What it does:
• Six deterministic CWE rules on every save — SQL injection, command injection, path traversal, insecure deserialization, hardcoded credentials, weak crypto. Offline, in milliseconds.
• An optional AI layer that confirms or rejects each finding, explains the data flow, and writes the fix. Ollama locally, your own API key, or Copilot.
• "Suggest Secure Rewrite": put the cursor in a function and get a complete safer version, previewed side by side before anything changes.

What it does not do:
• It is not a proof of safety. A finding means "look here".
• The AI is off by default. No surprise network calls.
• It is Python only for now.

The rules are measured, not assumed: 22 true positives, 2 false positives and 7 misses on a 50-file corpus (91.7% precision, 75.9% recall). The numbers and the misses are in the repo.

Free and MIT.

Marketplace: https://marketplace.visualstudio.com/items?itemName=battleangel.vuln-lens
GitHub: https://github.com/battleangel217/vulnlens

#AppSec #Python #VSCode #StaticAnalysis #AI

### X / Twitter (thread)

1/
VulnLens 0.2.0 is live on the VS Code Marketplace.

Python security review as you save: 6 CWE rules, offline, in milliseconds.

2/
SQL injection, command injection, path traversal, insecure deserialization, hardcoded secrets, weak crypto.

No network. No account. Just diagnostics.

3/
Optional AI layer: Ollama locally, your own key, or Copilot.

It confirms or rejects each finding, explains the data flow, and writes the fix.

4/
New: Suggest Secure Rewrite.

Cursor in a function → complete safer version → side-by-side preview → apply.

Refused if the code changed while it was generating.

5/
Rules measured on 50 files:
22 TP / 2 FP / 7 FN
91.7% precision, 75.9% recall

AI is opt-in. No surprise calls.

6/
Free + MIT
https://marketplace.visualstudio.com/items?itemName=battleangel.vuln-lens
https://github.com/battleangel217/vulnlens

---

## Posting notes

- **Order matters.** Training post first, launch 1–2 days later. The negative
  result is the interesting part; the launch is the payoff.
- **LinkedIn:** put the link in the first comment instead of the body. External
  links in the body reduce reach, and the comment keeps the post clean.
- **X:** the thread format above is written for the 280-character limit. Post it
  as a thread, not one long post.
- **Attach one image.** A screenshot of the four diagnostics in
  `demo/orders_api.py`, or a GIF of the rewrite preview, does more than any
  paragraph.
- **Do not edit the numbers.** They are the reason the post is credible.
