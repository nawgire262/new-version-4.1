**SIMULATED DATA. This checks that the code runs. It is NOT a research result.**

### Grouped 3-fold CV by session_id, 2 seeds (mean ± std over folds×seeds)

| Model | precision | recall | f1 | fpr | roc_auc | pr_auc |
|---|---|---|---|---|---|---|
| RF | 0.987 ± 0.031 | 0.889 ± 0.125 | 0.930 ± 0.070 | 0.007 ± 0.017 | 1.000 ± 0.000 | 1.000 ± 0.000 |
| KNN | 0.972 ± 0.044 | 0.958 ± 0.070 | 0.964 ± 0.051 | 0.014 ± 0.022 | 0.995 ± 0.008 | 0.985 ± 0.031 |
| IsolationForest | 0.744 ± 0.375 | 0.681 ± 0.367 | 0.706 ± 0.362 | 0.042 ± 0.032 | 0.923 ± 0.122 | 0.863 ± 0.200 |
| RF+KNN (no IF) | 0.987 ± 0.031 | 0.958 ± 0.070 | 0.971 ± 0.037 | 0.007 ± 0.017 | 0.999 ± 0.003 | 0.998 ± 0.005 |
| Hybrid stacked | 0.987 ± 0.031 | 0.958 ± 0.070 | 0.971 ± 0.037 | 0.007 ± 0.017 | 0.999 ± 0.003 | 0.998 ± 0.005 |

### False-positive rate by environment (Legit rows only)

| model           |   crowded |   quiet |
|:----------------|----------:|--------:|
| RF              |     0.012 |   0     |
| KNN             |     0.024 |   0     |
| IsolationForest |     0.048 |   0.036 |
| RF+KNN (no IF)  |     0.012 |   0     |
| Hybrid stacked  |     0.012 |   0     |

### Zero-day: recall on an attack type never seen in training

| held_out_attack   |    RF |   KNN |   IsolationForest |   RF+KNN (no IF) |   Hybrid stacked |
|:------------------|------:|------:|------------------:|-----------------:|-----------------:|
| open_clone        | 1     | 1     |             0.792 |            1     |            1     |
| other_channel     | 0.792 | 1     |             0.625 |            1     |            1     |
| wpa2_clone        | 0.708 | 0.833 |             0.5   |            0.792 |            0.792 |

### Permutation importance on HELD-OUT rows (ROC-AUC drop)

| label           |   importance |
|:----------------|-------------:|
| RSSI            |       0.1653 |
| Signal variance |       0.0229 |
| AP count        |       0.0073 |
| Channel (MHz)   |       0.0035 |
| Security        |       0      |
