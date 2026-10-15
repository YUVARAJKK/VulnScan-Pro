"""Tests for the ML classification pipeline.

Covers feature-schema consistency, feature extraction, the trained-model
path (when scikit-learn is available), the rule-based fallback, verification
status mapping, and the finding model's classification field.
"""

import uuid

import pytest

from ml.feature_schema import (
    FEATURE_NAMES,
    NUM_FEATURES,
    SCHEMA_VERSION,
    FEATURE_DEFAULTS,
)
from ml.feature_extractor import extract_features, extract_features_batch
from ml.classifier import VulnClassifier, get_classifier
from models.finding import Finding


def _sample_finding(**overrides):
    finding = {
        'severity': 'high',
        'confidence': 'high',
        'detected_by': 'xss',
        'category': 'injection',
        'parameter': 'q',
        'method': 'GET',
        'evidence': {
            'status_code': 200,
            'response_length': 5321,
            'response_time_ms': 120.5,
            'url': 'https://target.example/search?q=1',
            'payload': '<script>alert(1)</script>',
            'response_snippet': '<script>alert(1)</script>',
            'reflected_unencoded': True,
            'content_type': 'text/html',
        },
    }
    finding.update(overrides)
    return finding


# ── Feature schema consistency ────────────────────────────────────────────

def test_feature_vector_length_matches_schema():
    vector = extract_features(_sample_finding())
    assert len(vector) == NUM_FEATURES == len(FEATURE_NAMES)


def test_feature_extraction_is_deterministic():
    f = _sample_finding()
    assert extract_features(f) == extract_features(f)


def test_missing_finding_fields_fall_back_to_schema_defaults():
    vector = extract_features({})
    defaults = {name: float(FEATURE_DEFAULTS[name]) for name in FEATURE_NAMES}
    # An empty finding has no detector/payload category, which correctly maps
    # to the passive-payload indicator instead of the zero default.
    defaults['payload_passive'] = 1.0
    expected = [defaults[name] for name in FEATURE_NAMES]
    assert vector == expected


def test_malformed_values_are_handled_safely():
    finding = _sample_finding(
        evidence={'status_code': 'not-an-int', 'response_length': None},
        severity='bogus',
        detected_by='unknown_detector',
    )
    vector = extract_features(finding)  # must not raise
    assert len(vector) == NUM_FEATURES
    assert all(isinstance(v, float) for v in vector)


def test_batch_extraction_preserves_order_and_length():
    findings = [_sample_finding(), {}, _sample_finding(detected_by='sqli')]
    vectors = extract_features_batch(findings)
    assert len(vectors) == 3
    assert all(len(v) == NUM_FEATURES for v in vectors)


def test_detector_one_hot_encoding():
    vector = dict(zip(FEATURE_NAMES, extract_features(_sample_finding())))
    assert vector['det_xss'] == 1.0
    assert vector['det_sqli'] == 0.0
    assert vector['payload_xss'] == 1.0


# ── Rule-based fallback (no model available) ──────────────────────────────

def test_fallback_used_when_untrained():
    classifier = VulnClassifier()
    result = classifier.classify(_sample_finding())
    assert result['classification_method'] == 'rule_based_fallback'
    assert result['model_version'] == 'none'
    assert result['requires_manual_review'] is True
    assert 'note' in result


def test_fallback_never_claims_confirmed():
    """A rule-based score is not a model probability — it must never map to
    the 'confirmed' verification status, even with maximal evidence."""
    classifier = VulnClassifier()
    result = classifier.classify(_sample_finding())
    assert result['verification_status'] != 'confirmed'


def test_fallback_low_evidence_scores_lower_than_high_evidence():
    classifier = VulnClassifier()
    strong = classifier.classify(_sample_finding())['positive_probability']
    weak = classifier.classify(_sample_finding(
        confidence='low',
        severity='info',
        detected_by='security_headers',
        evidence={'status_code': 200},
    ))['positive_probability']
    assert strong > weak


def test_fallback_binary_class_and_probability_bounds():
    classifier = VulnClassifier()
    for finding in (_sample_finding(), {}, _sample_finding(severity='critical')):
        result = classifier.classify(finding)
        assert result['predicted_class'] in (0, 1)
        assert 0.0 <= result['positive_probability'] <= 1.0


# ── Verification status mapping (model path) ──────────────────────────────

def test_verification_status_thresholds():
    status = VulnClassifier._determine_verification_status
    assert status(1, 0.90, {}) == 'confirmed'
    assert status(1, 0.70, {}) == 'likely'
    assert status(1, 0.55, {}) == 'suspected'
    assert status(0, 0.10, {}) == 'likely_false_positive'
    assert status(0, 0.30, {}) == 'inconclusive'


# ── Training pipeline (requires scikit-learn) ─────────────────────────────

pytest.importorskip('sklearn', reason='scikit-learn not installed')


def _synthetic_dataset(n=120):
    import random
    random.seed(7)
    X, y = [], []
    for i in range(n):
        genuine = i % 5 == 0  # deterministic 20/80 split
        finding = _sample_finding(
            confidence='high' if genuine else 'low',
            severity='high' if genuine else 'info',
            detected_by='xss' if genuine else 'security_headers',
            evidence={
                'status_code': 200,
                'url': f'https://t.example/?q={i}' if genuine else None,
                'payload': 'p' if genuine else None,
                'response_snippet': 's' if genuine else None,
                'reflected_unencoded': genuine,
                'error_pattern': 'SQL syntax' if genuine else None,
                'baseline_differs': genuine,
            },
        )
        X.append(extract_features(finding))
        y.append(1 if genuine else 0)
    return X, y


def test_training_and_inference_roundtrip(tmp_path):
    X, y = _synthetic_dataset()
    classifier = VulnClassifier()
    results = classifier.train(X, y, test_size=0.25)

    assert classifier.is_trained
    assert results['model_version']
    assert results['schema_version'] == SCHEMA_VERSION
    metrics = results['metrics']
    assert 0.0 <= metrics['accuracy'] <= 1.0
    assert metrics['train_samples'] + metrics['test_samples'] == len(X)

    # Saved model can be reloaded and used for inference
    classifier.save(tmp_path)
    reloaded = VulnClassifier()
    assert reloaded.load(tmp_path) is True
    assert reloaded.is_trained

    result = reloaded.classify(_sample_finding())
    assert result['classification_method'] == 'ml_random_forest'
    assert result['model_version'] == results['model_version']
    assert 'positive_probability' in result
    assert 0.0 <= result['positive_probability'] <= 1.0


def test_loading_rejects_incompatible_schema_version(tmp_path):
    import json
    X, y = _synthetic_dataset()
    classifier = VulnClassifier()
    classifier.train(X, y)
    classifier.save(tmp_path)

    # Corrupt the recorded schema version to simulate an old model
    version = classifier.model_version
    meta_path = tmp_path / version / 'metadata.json'
    metadata = json.loads(meta_path.read_text())
    metadata['schema_version'] = '0.0.1-different'
    meta_path.write_text(json.dumps(metadata))

    fresh = VulnClassifier()
    assert fresh.load(tmp_path) is False  # refuses incompatible model
    assert fresh.is_trained is False


def test_classify_batch_preserves_order():
    classifier = VulnClassifier()
    findings = [_sample_finding(), {}, _sample_finding(detected_by='sqli')]
    results = classifier.classify_batch(findings)
    assert len(results) == len(findings)
    assert all('verification_status' in r for r in results)


def test_singleton_classifier_loads_without_error():
    classifier = get_classifier()
    assert isinstance(classifier, VulnClassifier)


# ── Finding model integration ─────────────────────────────────────────────

def test_finding_accepts_classification_result():
    classification = {
        'predicted_class': 1,
        'positive_probability': 0.9,
        'verification_status': 'likely',
        'classification_method': 'rule_based_fallback',
    }
    finding = Finding(
        scan_id=uuid.uuid4(),
        title='Reflected XSS',
        detected_by='xss',
        ml_classification=classification,
    )
    dumped = finding.model_dump(mode='json')
    assert dumped['ml_classification'] == classification

    unclassified = Finding(scan_id=uuid.uuid4(), title='Missing HSTS')
    assert unclassified.ml_classification is None
