# VulnLens evaluation

Corpus: **50 files** (28 vulnerable, 22 clean), **29 labelled issues**.
Matching: same CWE within ±2 lines. A finding dismissed by the AI counts as a miss, not a false positive.

| Mode | TP | FP | FN | Precision | Recall | F1 | FP on clean | Clean files with FP | ms/file | requests |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 22 | 2 | 7 | 91.7% | 75.9% | 83.0% | 2 | 2 | 0 | 0 |

## rules

Provider: none

| CWE | TP | FP | FN | Recall |
|---|---|---|---|---|
| CWE-22 | 3 | 1 | 2 | 60.0% |
| CWE-327 | 3 | 1 | 1 | 75.0% |
| CWE-502 | 3 | 0 | 0 | 100.0% |
| CWE-78 | 4 | 0 | 0 | 100.0% |
| CWE-798 | 5 | 0 | 2 | 71.4% |
| CWE-89 | 4 | 0 | 2 | 66.7% |

**Missed:**
- `h01_sqli_multiline.py:11` CWE-89
- `h02_path_interprocedural.py:11` CWE-22
- `h03_secret_concat.py:1` CWE-798
- `h04_sqli_orm_extra.py:2` CWE-89
- `h06_secret_base64.py:3` CWE-798
- `h07_crypto_alias.py:7` CWE-327
- `h08_path_alias.py:8` CWE-22

**False positives:**
- `h09_clean_whitelist.py:10` CWE-22 (clean file, rules)
- `h10_clean_md5_dedup.py:5` CWE-327 (clean file, rules)

