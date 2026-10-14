#!/usr/bin/env python3
"""Training script — train or retrain the VulnScan Pro Random Forest model.

Usage:
    python -m ml.train_model --dataset path/to/dataset.csv [--output path/to/models]

Dataset format (CSV):
    The CSV must contain columns matching the feature schema plus a ``label``
    column (1 = genuine vulnerability, 0 = false positive).  Alternatively the
    CSV may contain raw finding JSON in a ``finding_json`` column — the script
    will extract features automatically.

If no real labelled dataset is available, the script generates a clearly
labelled synthetic fixture dataset for **software-testing purposes only**.
The synthetic data carries a ``is_synthetic`` flag and the resulting model
is NOT recommended for production classification.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path

# Allow running from the scanner_engine directory
if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_schema import FEATURE_NAMES, NUM_FEATURES, SCHEMA_VERSION
from ml.feature_extractor import extract_features
from ml.classifier import VulnClassifier

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('train_model')


def load_dataset_csv(path: str) -> tuple[list[list[float]], list[int]]:
    """Load a labelled dataset from CSV.

    Supports two formats:
      1. Pre-extracted features: columns match FEATURE_NAMES + 'label'.
      2. Raw findings: column 'finding_json' (JSON string) + 'label'.
    """
    X, y = [], []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []

        if 'finding_json' in columns:
            # Format 2: raw findings
            for row in reader:
                try:
                    finding = json.loads(row['finding_json'])
                    features = extract_features(finding)
                    label = int(row['label'])
                    if label not in (0, 1):
                        continue
                    X.append(features)
                    y.append(label)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
        elif all(fn in columns for fn in FEATURE_NAMES):
            # Format 1: pre-extracted features
            for row in reader:
                try:
                    features = [float(row.get(fn, 0)) for fn in FEATURE_NAMES]
                    label = int(row['label'])
                    if label not in (0, 1):
                        continue
                    X.append(features)
                    y.append(label)
                except (KeyError, ValueError):
                    continue
        else:
            raise ValueError(
                f'CSV does not match expected schema. Expected columns: '
                f'{FEATURE_NAMES} + label, or finding_json + label'
            )

    logger.info(f'Loaded {len(X)} samples from {path}')
    return X, y


def generate_synthetic_dataset(n_samples: int = 500) -> tuple[list[list[float]], list[int]]:
    """Generate a synthetic dataset for testing the training pipeline.

    WARNING: This data is SYNTHETIC and does NOT represent real-world
    vulnerability findings. Models trained on this data should NOT be used
    for production classification. The dataset exists solely to verify that
    the ML pipeline (feature extraction → training → inference) works
    correctly end-to-end.

    The synthetic data creates two clusters:
      - Genuine findings: higher evidence counts, reflected content, error
        patterns, higher severity.
      - False positives: low evidence, no reflection, low severity, passive
        detectors.
    """
    import random
    random.seed(42)

    X, y = [], []
    detectors = ['xss', 'sqli', 'security_headers', 'cookie_security', 'cors',
                 'http_methods', 'information_disclosure', 'directory_exposure',
                 'open_redirect', 'path_traversal']

    for i in range(n_samples):
        is_genuine = i < int(n_samples * 0.4)  # 40% genuine, 60% false positive
        label = 1 if is_genuine else 0

        finding = {
            'severity': random.choice(['critical', 'high', 'medium']) if is_genuine else random.choice(['low', 'info', 'medium']),
            'confidence': random.choice(['high', 'medium']) if is_genuine else random.choice(['low', 'medium']),
            'detected_by': random.choice(detectors),
            'category': 'injection' if random.random() > 0.5 and is_genuine else 'misconfig',
            'parameter': f'param_{i}' if random.random() > 0.3 else '',
            'evidence': {
                'status_code': random.choice([200, 200, 200, 500, 302]) if is_genuine else 200,
                'response_length': random.randint(500, 50000),
                'response_time_ms': random.uniform(50, 2000),
                'redirect_count': random.randint(0, 3) if is_genuine else 0,
                'reflected_unencoded': is_genuine and random.random() > 0.4,
                'error_pattern': 'MySQL syntax error' if is_genuine and random.random() > 0.5 else None,
                'baseline_differs': is_genuine and random.random() > 0.3,
                'url': f'https://example.com/page?param={i}' if random.random() > 0.2 else None,
                'payload': f'test_payload_{i}' if is_genuine and random.random() > 0.3 else None,
                'response_snippet': f'<html>response_{i}</html>' if random.random() > 0.5 else None,
                'content_type': 'text/html',
            },
        }

        features = extract_features(finding)
        X.append(features)
        y.append(label)

    logger.info(
        f'Generated {n_samples} synthetic samples '
        f'(genuine={sum(y)}, false_positive={len(y)-sum(y)})'
    )
    return X, y


def main():
    # Windows consoles often default to cp1252; force UTF-8 so the summary
    # box-drawing characters (═, █) do not raise UnicodeEncodeError.
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(description='Train VulnScan Pro ML Model')
    parser.add_argument('--dataset', help='Path to labelled dataset CSV')
    parser.add_argument('--output', default=None, help='Output directory for the model')
    parser.add_argument('--synthetic', action='store_true',
                        help='Use synthetic data for testing (NOT for production)')
    parser.add_argument('--samples', type=int, default=500,
                        help='Number of synthetic samples to generate')
    parser.add_argument('--threshold', type=float, default=0.5,
                        help='Classification threshold for positive class')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Fraction of data for test split')
    args = parser.parse_args()

    # Load data
    if args.dataset:
        X, y = load_dataset_csv(args.dataset)
    elif args.synthetic:
        logger.warning(
            '⚠️  Using SYNTHETIC data for pipeline testing. '
            'The resulting model is NOT suitable for production classification.'
        )
        X, y = generate_synthetic_dataset(args.samples)
    else:
        logger.error(
            'No dataset provided. Use --dataset path/to/data.csv or '
            '--synthetic for pipeline testing.'
        )
        sys.exit(1)

    if len(X) < 20:
        logger.error(f'Dataset too small ({len(X)} samples). Need at least 20.')
        sys.exit(1)

    # Train
    classifier = VulnClassifier(threshold=args.threshold)
    results = classifier.train(X, y, test_size=args.test_size)

    # Save
    output_dir = classifier.save(args.output)

    # Print summary
    metrics = results['metrics']
    print('\n' + '═' * 60)
    print('  VulnScan Pro — Model Training Complete')
    print('═' * 60)
    print(f'  Model Version:    {results["model_version"]}')
    print(f'  Schema Version:   {results["schema_version"]}')
    print(f'  Threshold:        {results["threshold"]}')
    print(f'  Training Samples: {metrics["train_samples"]}')
    print(f'  Test Samples:     {metrics["test_samples"]}')
    print(f'  Accuracy:         {metrics["accuracy"]:.4f}')
    print(f'  Precision:        {metrics["precision"]:.4f}')
    print(f'  Recall:           {metrics["recall"]:.4f}')
    print(f'  F1 Score:         {metrics["f1"]:.4f}')
    print(f'  Training Time:    {metrics["training_time_seconds"]:.2f}s')
    print(f'  Saved To:         {output_dir}')
    if args.synthetic:
        print('\n  ⚠️  SYNTHETIC DATA — NOT FOR PRODUCTION USE')
    print('═' * 60)

    # Print top features
    if 'feature_importance' in metrics:
        print('\n  Top 10 Feature Importances:')
        for item in metrics['feature_importance'][:10]:
            bar = '█' * int(item['importance'] * 50)
            print(f'    {item["feature"]:<30} {item["importance"]:.4f} {bar}')

    return results


if __name__ == '__main__':
    main()
