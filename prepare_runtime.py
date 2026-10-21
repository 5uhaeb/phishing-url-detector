"""Pack the trained model for hosting without changing its learned parameters.

The full research artifact stays intact for independent-domain evaluation.
The runtime copy omits evaluation-only domain hashes and stores every trained
tree in compact, uncompressed arrays for memory-mapped inference.
"""
import argparse
from pathlib import Path

import joblib
import numpy as np
from runtime_model import CompactForest

ROOT = Path(__file__).resolve().parent


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Keep the full research model separate from the runtime copy.')
    artifact = joblib.load(source)
    artifact.pop('development_group_hashes', None)
    original = artifact['model']
    runtime = CompactForest.from_sklearn(original)
    # Fail the build rather than ship an exporter incompatible with this model.
    probes = np.random.default_rng(42).uniform(0, 1000, (128, runtime.n_features_in_))
    np.testing.assert_allclose(runtime.predict_proba(probes), original.predict_proba(probes),
                               rtol=0, atol=1e-12)
    artifact['model'] = runtime
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, destination, compress=0)
    print(f'Runtime model written to {destination.name}; trained parameters unchanged.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'model.joblib')
    parser.add_argument('--output', type=Path, default=ROOT / 'runtime-model.joblib')
    args = parser.parse_args()
    prepare(args.source, args.output)
