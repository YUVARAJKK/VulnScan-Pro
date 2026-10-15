# Machine Learning Classification — VulnScan Pro

This document describes the ML classification pipeline: what it does, how it
is trained, how it is integrated with the scanning engine, and — importantly —
what it does **not** do.

## Role of the model (read this first)

> **The scanning engine discovers candidate findings. The ML model classifies
> the collected observations; it does not discover vulnerabilities.**

The Random Forest classifier estimates, for each finding, whether it is a
likely **genuine** vulnerability (`1`) or a likely **false positive** (`0`),
based on the evidence collected by the scanner. A classification probability
is a decision-support signal — never proof that a vulnerability exists or is
exploitable.

## Where it runs in the pipeline

```
Crawl/discovery → detectors → dedup → MITRE + remediation
                                        │
                                        ▼
                        Phase 4.5: ML classification  ← main.py
                                        │
                                        ▼
              ml_classification + ml_verification_status written to
              vulnerabilities / public_vulnerabilities (JSONB + string)
                                        │
                                        ▼
              Scan detail UI (MlBlock) and PDF/HTML reports
```

Implementation files:

| File | Purpose |
|------|---------|
| `scanner_engine/ml/feature_schema.py` | Single source of truth for the feature list (34 features, schema v1.0.0) |
| `scanner_engine/ml/feature_extractor.py` | Finding dict → fixed-length feature vector |
| `scanner_engine/ml/classifier.py` | Training, serialization, loading, inference, rule-based fallback |
| `scanner_engine/ml/train_model.py` | CLI training script |
| `scanner_engine/tests/test_ml_pipeline.py` | 16 tests covering the pipeline |

## Classification output (stored per finding)

```json
{
  "predicted_class": 1,
  "positive_probability": 0.8712,
  "classification_label": "genuine",
  "verification_status": "likely",
  "model_version": "20260921_085038",
  "schema_version": "1.0.0",
  "threshold": 0.5,
  "requires_manual_review": true,
  "classification_method": "ml_random_forest",
  "classified_at": "2026-09-21T09:12:44.512"
}
```

`ml_verification_status` is also stored as its own column for filtering:

| Status | Meaning |
|--------|---------|
| `confirmed` | Model, probability ≥ 0.85 — still subject to manual verification for high-impact remediation |
| `likely` | Model, probability ≥ 0.65 — verify before remediation |
| `suspected` | Model, probability ≥ threshold but low confidence — manual review |
| `likely_false_positive` | Model, probability < 0.25 — review before discarding |
| `inconclusive` | Ambiguous — manual verification required |

**Honesty rule:** the rule-based fallback (below) never emits `confirmed`,
and always sets `requires_manual_review: true`.

## When no trained model exists

`get_classifier()` tries to load the latest model from
`scanner_engine/ml/saved_models/`. If none is available (or scikit-learn is
not installed, or the schema version changed), classification falls back to a
transparent, deterministic rule-based score built from:

- detector confidence (high/medium/low),
- evidence completeness (number of non-empty evidence fields),
- presence of reflection / error-pattern evidence,
- severity (slight boost so serious findings are not auto-discarded).

The result is clearly labelled `classification_method:
"rule_based_fallback"` with a `note` explaining that ML was unavailable and
manual verification is required. The scan summary and report state which
method was used. **No untrained model is ever presented as trained.**

## Training the model

```bash
cd scanner_engine

# With a real labelled dataset (CSV):
python -m ml.train_model --dataset path/to/dataset.csv

# Dataset formats (auto-detected):
#   1. Pre-extracted features: FEATURE_NAMES columns + label (1/0)
#   2. Raw findings: finding_json column + label column

# Pipeline test with clearly-marked synthetic data (NOT for production):
python -m ml.train_model --synthetic --samples 500
```

Outputs are written to `scanner_engine/ml/saved_models/<version>/`
(`model.joblib` + `metadata.json`) with a `latest.json` pointer. The metadata
records model version, feature schema version, hyperparameters, threshold,
and full evaluation metrics. Inference refuses to load a model trained on a
different feature-schema version.

### Dataset schema and labeling guidance

- `label = 1`: expert-confirmed genuine vulnerability (verified exploitation
  or unambiguous evidence).
- `label = 0`: expert-confirmed false positive.
- Do **not** label raw unverified scanner output as ground truth.
- Where possible, split/evaluate by target application rather than randomly,
  so highly related findings do not straddle the train/test boundary.
- Keep class balance in mind; the default `class_weight: "balanced"`
  mitigates but does not replace a sensibly sampled dataset.

## Hyperparameters (defaults, and why)

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `n_estimators` | 200 | Stable predictions without excessive training time |
| `max_depth` | 15 | Limits over-fitting to noisy scanner output |
| `min_samples_split` | 5 | Regularization; leaves stay meaningful |
| `min_samples_leaf` | 3 | Same |
| `max_features` | `sqrt` | Standard RF practice; decorrelates trees |
| `class_weight` | `balanced` | Handles class imbalance (FPs usually outnumber genuine findings) |
| `random_state` | 42 | Reproducibility |

All are configurable via `VulnClassifier(hyperparams={...})` or the metadata
override at load time.

## Evaluation — what has actually been measured

The training pipeline was verified end-to-end using the synthetic fixture
(`--synthetic --samples 400`): train/test split (320/80), stratification,
metric computation (accuracy/precision/recall/F1/confusion matrix), feature
importances, serialization, and reload — all passing. **These numbers come
from synthetic data and must not be quoted as real-world accuracy.** No
expert-labelled real dataset exists in this repository yet; until one is
provided and a model is trained on it, production classification uses the
rule-based fallback and every finding is flagged for manual review.

## Tests

```bash
cd scanner_engine && python -m pytest tests/test_ml_pipeline.py -v
```

Covers: schema/vector length consistency, deterministic extraction, safe
handling of malformed/missing fields, detector one-hot encoding, fallback
behaviour (never `confirmed`, always manual review, monotonic evidence
scoring), verification-status thresholds, train→save→load→infer roundtrip,
schema-mismatch rejection, batch classification order, and the Finding model
integration.
