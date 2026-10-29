"""Validate the serving artifact without importing training dependencies."""
import math
from numbers import Real

from detector import FEATURE_NAMES


def validate_artifact(artifact):
    if not isinstance(artifact, dict) or artifact.get('features') != list(FEATURE_NAMES):
        raise ValueError('Model feature schema changed. Retrain with the current code.')
    model = artifact.get('model')
    if not callable(getattr(model, 'predict_proba', None)) or list(getattr(model, 'classes_', [])) != [0, 1]:
        raise ValueError('Expected a binary probability model with classes [0, 1].')
    if 'threshold' not in artifact:
        raise ValueError('Missing model decision threshold.')
    for key in ['threshold', 'model_threshold', 'rf_threshold']:
        value = artifact.get(key, .5)
        if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value) or not 0 <= value <= 1.000000000000001:
            raise ValueError(f'Invalid model {key}.')
    weight = artifact.get('model_weight', .8)
    if not isinstance(weight, Real) or not math.isfinite(weight) or not 0 <= weight <= 1:
        raise ValueError('Invalid model weight.')
    if not isinstance(artifact.get('trained_at'), str) or not artifact['trained_at']:
        raise ValueError('Missing model version.')
    return artifact
