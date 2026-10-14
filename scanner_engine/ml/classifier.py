"""Random Forest classifier — training, serialization, and inference.

This module manages the complete lifecycle of the VulnScan Pro ML model:
  1. Dataset loading and validation
  2. Feature preprocessing
  3. Train/test splitting with stratification
  4. Model training with explicit, documented hyperparameters
  5. Model serialization with version metadata
  6. Model loading and inference
  7. Evaluation metrics

IMPORTANT: The model classifies scanner findings as likely genuine (1) or
likely false positive (0). It does NOT discover vulnerabilities — the
scanning engine discovers candidate findings; the ML model filters them.

The model is only available for classification after it has been trained on
a valid, labelled dataset. Until then, a rule-based fallback is used and the
system clearly indicates that ML classification is unavailable.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Lazy imports — sklearn is an optional dependency ─────────────────────
_sklearn_available = False
try:
    import numpy as np
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report,
    )
    _sklearn_available = True
except ImportError:
    logger.warning(
        'scikit-learn/numpy/joblib not installed — ML classification will use '
        'rule-based fallback. Install with: pip install scikit-learn numpy joblib'
    )

from ml.feature_schema import FEATURE_NAMES, NUM_FEATURES, SCHEMA_VERSION
from ml.feature_extractor import extract_features, extract_features_batch

# Default model directory
MODEL_DIR = Path(__file__).parent / 'saved_models'

# ── Hyperparameters ──────────────────────────────────────────────────────
# Rationale for defaults:
# - n_estimators=200: enough trees for stable predictions without excessive
#   training time on datasets ≤50k samples.
# - max_depth=15: prevents over-fitting to noisy scanner output while
#   allowing the model to capture multi-level decision boundaries.
# - min_samples_split=5, min_samples_leaf=3: regularization that ensures each
#   leaf represents a meaningful group of findings.
# - max_features='sqrt': standard RF best practice — each tree sees √n
#   features per split, reducing correlation between trees.
# - class_weight='balanced': handles class imbalance (scanners typically
#   produce more false positives than genuine vulnerabilities).
# - random_state=42: reproducibility.

DEFAULT_HYPERPARAMS = {
    'n_estimators': 200,
    'max_depth': 15,
    'min_samples_split': 5,
    'min_samples_leaf': 3,
    'max_features': 'sqrt',
    'criterion': 'gini',
    'class_weight': 'balanced',
    'random_state': 42,
    'n_jobs': -1,
}

DEFAULT_CLASSIFICATION_THRESHOLD = 0.5


class VulnClassifier:
    """Random Forest classifier for vulnerability finding validation.

    Attributes
    ----------
    model : RandomForestClassifier | None
        The trained model, or None if not yet trained/loaded.
    model_version : str
        Version string (timestamp-based) of the loaded model.
    schema_version : str
        Feature schema version the model was trained on.
    threshold : float
        Classification threshold for the positive class.
    is_trained : bool
        Whether a valid model is currently loaded.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_CLASSIFICATION_THRESHOLD,
        hyperparams: dict[str, Any] | None = None,
    ):
        self.model = None
        self.model_version: str = ''
        self.schema_version: str = SCHEMA_VERSION
        self.threshold = threshold
        self.hyperparams = {**DEFAULT_HYPERPARAMS, **(hyperparams or {})}
        self.is_trained = False
        self._training_metrics: dict[str, Any] = {}

    # ── Training ─────────────────────────────────────────────────────────

    def train(
        self,
        X: list[list[float]],
        y: list[int],
        test_size: float = 0.2,
        stratify: bool = True,
    ) -> dict[str, Any]:
        """Train the Random Forest model.

        Parameters
        ----------
        X : list of feature vectors
        y : list of labels (1 = genuine, 0 = false positive)
        test_size : float
            Fraction reserved for evaluation.
        stratify : bool
            Whether to use stratified split (recommended for imbalanced data).

        Returns
        -------
        dict
            Training results including evaluation metrics.
        """
        if not _sklearn_available:
            raise RuntimeError(
                'scikit-learn is required for training. '
                'Install with: pip install scikit-learn numpy joblib'
            )

        X_arr = np.array(X, dtype=np.float64)
        y_arr = np.array(y, dtype=np.int32)

        # Validate
        if len(X_arr) == 0:
            raise ValueError('Training dataset is empty')
        if X_arr.shape[1] != NUM_FEATURES:
            raise ValueError(
                f'Feature count mismatch: got {X_arr.shape[1]}, '
                f'expected {NUM_FEATURES} (schema v{SCHEMA_VERSION})'
            )
        if set(y_arr.tolist()) - {0, 1}:
            raise ValueError('Labels must be binary: 0 (false positive) or 1 (genuine)')

        # Handle NaN / Inf
        X_arr = np.nan_to_num(X_arr, nan=0.0, posinf=0.0, neginf=0.0)

        # Split — stratified when possible
        split_kwargs = {}
        if stratify and len(set(y_arr.tolist())) > 1:
            split_kwargs['stratify'] = y_arr

        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y_arr, test_size=test_size, random_state=42, **split_kwargs,
        )

        logger.info(
            f'Training RF model: {len(X_train)} train, {len(X_test)} test, '
            f'{NUM_FEATURES} features, schema v{SCHEMA_VERSION}'
        )

        # Train
        start = time.time()
        self.model = RandomForestClassifier(**self.hyperparams)
        self.model.fit(X_train, y_train)
        train_time = time.time() - start

        # Evaluate on held-out test set
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else None

        metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1': float(f1_score(y_test, y_pred, zero_division=0)),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True, zero_division=0),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'feature_count': NUM_FEATURES,
            'training_time_seconds': round(train_time, 2),
        }

        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_.tolist()
            feature_importance = sorted(
                zip(FEATURE_NAMES, importances),
                key=lambda x: x[1],
                reverse=True,
            )
            metrics['feature_importance'] = [
                {'feature': name, 'importance': round(imp, 4)}
                for name, imp in feature_importance[:15]
            ]

        self.model_version = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        self.schema_version = SCHEMA_VERSION
        self.is_trained = True
        self._training_metrics = metrics

        logger.info(
            f'Model trained: accuracy={metrics["accuracy"]:.3f}, '
            f'precision={metrics["precision"]:.3f}, '
            f'recall={metrics["recall"]:.3f}, '
            f'f1={metrics["f1"]:.3f}, '
            f'time={train_time:.1f}s'
        )

        return {
            'model_version': self.model_version,
            'schema_version': self.schema_version,
            'hyperparams': self.hyperparams,
            'metrics': metrics,
            'threshold': self.threshold,
        }

    # ── Serialization ────────────────────────────────────────────────────

    def save(self, model_dir: str | Path | None = None) -> str:
        """Save the trained model and metadata to disk.

        Returns the directory path where the model was saved.
        """
        if not _sklearn_available:
            raise RuntimeError('scikit-learn required for model serialization')
        if not self.is_trained or self.model is None:
            raise RuntimeError('No trained model to save')

        model_dir = Path(model_dir or MODEL_DIR)
        model_dir.mkdir(parents=True, exist_ok=True)

        version_dir = model_dir / self.model_version
        version_dir.mkdir(parents=True, exist_ok=True)

        # Save model
        model_path = version_dir / 'model.joblib'
        joblib.dump(self.model, model_path)

        # Save metadata
        metadata = {
            'model_version': self.model_version,
            'schema_version': self.schema_version,
            'feature_names': FEATURE_NAMES,
            'num_features': NUM_FEATURES,
            'hyperparams': self.hyperparams,
            'threshold': self.threshold,
            'training_metrics': self._training_metrics,
            'saved_at': datetime.utcnow().isoformat(),
        }
        meta_path = version_dir / 'metadata.json'
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)

        # Update "latest" symlink-like pointer
        latest_path = model_dir / 'latest.json'
        with open(latest_path, 'w') as f:
            json.dump({'version': self.model_version}, f)

        logger.info(f'Model saved to {version_dir}')
        return str(version_dir)

    def load(self, model_dir: str | Path | None = None, version: str | None = None) -> bool:
        """Load a trained model from disk.

        Parameters
        ----------
        model_dir : optional path to models directory
        version : optional specific version to load; defaults to latest

        Returns
        -------
        bool
            True if model was loaded successfully, False otherwise.
        """
        if not _sklearn_available:
            logger.warning('scikit-learn not available — cannot load model')
            return False

        model_dir = Path(model_dir or MODEL_DIR)

        if version is None:
            latest_path = model_dir / 'latest.json'
            if not latest_path.exists():
                logger.info('No trained model found (no latest.json)')
                return False
            with open(latest_path) as f:
                version = json.load(f).get('version')

        if not version:
            return False

        version_dir = model_dir / version
        model_path = version_dir / 'model.joblib'
        meta_path = version_dir / 'metadata.json'

        if not model_path.exists():
            logger.warning(f'Model file not found: {model_path}')
            return False

        # Load metadata first to check schema compatibility
        if meta_path.exists():
            with open(meta_path) as f:
                metadata = json.load(f)

            saved_schema = metadata.get('schema_version', '')
            if saved_schema != SCHEMA_VERSION:
                logger.warning(
                    f'Schema version mismatch: model was trained on v{saved_schema}, '
                    f'current schema is v{SCHEMA_VERSION}. Model will NOT be loaded. '
                    f'Retrain the model with the current schema.'
                )
                return False

            self.model_version = metadata.get('model_version', version)
            self.schema_version = saved_schema
            self.threshold = metadata.get('threshold', DEFAULT_CLASSIFICATION_THRESHOLD)
            self.hyperparams = metadata.get('hyperparams', DEFAULT_HYPERPARAMS)
            self._training_metrics = metadata.get('training_metrics', {})

        try:
            self.model = joblib.load(model_path)
            self.is_trained = True
            logger.info(f'Model loaded: version={self.model_version}, schema=v{self.schema_version}')
            return True
        except Exception as e:
            logger.error(f'Failed to load model: {e}')
            return False

    # ── Inference ─────────────────────────────────────────────────────────

    def classify(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Classify a single finding.

        Returns a classification result dict with the predicted class,
        probability, model metadata, and recommendation for manual review.
        """
        if not self.is_trained or self.model is None:
            return self._fallback_classification(finding)

        try:
            features = extract_features(finding)
            X = np.array([features], dtype=np.float64)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            proba = self.model.predict_proba(X)[0]
            positive_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            predicted_class = 1 if positive_prob >= self.threshold else 0

            # Determine verification status
            verification_status = self._determine_verification_status(
                predicted_class, positive_prob, finding
            )

            return {
                'predicted_class': predicted_class,
                'positive_probability': round(positive_prob, 4),
                'classification_label': 'genuine' if predicted_class == 1 else 'false_positive',
                'verification_status': verification_status,
                'model_version': self.model_version,
                'schema_version': self.schema_version,
                'threshold': self.threshold,
                'requires_manual_review': verification_status in ('suspected', 'inconclusive'),
                'classification_method': 'ml_random_forest',
                'classified_at': datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f'ML classification failed: {e}')
            return self._fallback_classification(finding)

    def classify_batch(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Classify a batch of findings."""
        return [self.classify(f) for f in findings]

    # ── Fallback ─────────────────────────────────────────────────────────

    def _fallback_classification(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Rule-based fallback when no trained model is available.

        Uses evidence completeness, confidence level, and severity to produce
        a transparent, deterministic classification without pretending an ML
        model was involved.
        """
        confidence = finding.get('confidence', 'medium')
        severity = finding.get('severity', 'info')
        evidence = finding.get('evidence', {})
        evidence_fields = sum(1 for v in evidence.values() if v is not None and v != '' and v != {})

        # Rule-based scoring
        score = 0.5  # neutral starting point
        if confidence == 'high':
            score += 0.25
        elif confidence == 'low':
            score -= 0.2

        if evidence_fields >= 4:
            score += 0.15
        elif evidence_fields <= 1:
            score -= 0.15

        if severity in ('critical', 'high'):
            score += 0.05  # slight boost — don't auto-discard serious findings

        if evidence.get('reflected_unencoded') or evidence.get('error_pattern'):
            score += 0.15

        score = max(0.0, min(1.0, score))
        predicted_class = 1 if score >= self.threshold else 0

        verification_status = self._determine_verification_status(
            predicted_class, score, finding
        )
        # A rule-based score is not a model probability: never claim
        # 'confirmed' from the fallback. Cap at 'likely' and keep manual review.
        if verification_status == 'confirmed':
            verification_status = 'likely'

        return {
            'predicted_class': predicted_class,
            'positive_probability': round(score, 4),
            'classification_label': 'genuine' if predicted_class == 1 else 'false_positive',
            'verification_status': verification_status,
            'model_version': 'none',
            'schema_version': SCHEMA_VERSION,
            'threshold': self.threshold,
            'requires_manual_review': True,
            'classification_method': 'rule_based_fallback',
            'classified_at': datetime.utcnow().isoformat(),
            'note': (
                'ML model not available. Classification uses a rule-based '
                'fallback based on evidence completeness and confidence. '
                'Results should be verified manually.'
            ),
        }

    @staticmethod
    def _determine_verification_status(
        predicted_class: int,
        probability: float,
        finding: dict[str, Any],
    ) -> str:
        """Map prediction confidence to a human-readable verification status.

        Statuses:
          - confirmed:   high-confidence genuine finding (prob ≥ 0.85)
          - likely:      moderate-confidence genuine finding (prob ≥ 0.65)
          - suspected:   low-confidence — may be genuine, manual review needed
          - likely_fp:   moderate-confidence false positive (prob < 0.35)
          - inconclusive: ambiguous result — requires manual review
        """
        if predicted_class == 1:
            if probability >= 0.85:
                return 'confirmed'
            elif probability >= 0.65:
                return 'likely'
            else:
                return 'suspected'
        else:
            if probability < 0.25:
                return 'likely_false_positive'
            else:
                return 'inconclusive'

    # ── Utilities ────────────────────────────────────────────────────────

    def get_model_info(self) -> dict[str, Any]:
        """Return model metadata for API responses and reports."""
        return {
            'is_trained': self.is_trained,
            'model_version': self.model_version,
            'schema_version': self.schema_version,
            'threshold': self.threshold,
            'hyperparams': self.hyperparams,
            'classification_method': 'ml_random_forest' if self.is_trained else 'rule_based_fallback',
            'training_metrics': self._training_metrics if self.is_trained else None,
        }


# ── Module-level singleton ───────────────────────────────────────────────
_classifier: VulnClassifier | None = None


def get_classifier() -> VulnClassifier:
    """Get or create the global classifier instance, loading the latest model
    if available."""
    global _classifier
    if _classifier is None:
        _classifier = VulnClassifier()
        _classifier.load()
    return _classifier
