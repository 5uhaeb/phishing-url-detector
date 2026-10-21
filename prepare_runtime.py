"""Pack the trained model for hosting without changing its learned parameters.

The full research artifact stays intact for independent-domain evaluation.
The runtime copy omits only evaluation-only domain hashes and uses uncompressed
arrays so joblib can memory-map them while loading the trees.
"""
import argparse
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parent


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('Keep the full research model separate from the runtime copy.')
    artifact = joblib.load(source)
    artifact.pop('development_group_hashes', None)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, destination, compress=0)
    print(f'Runtime model written to {destination.name}; trained parameters unchanged.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'model.joblib')
    parser.add_argument('--output', type=Path, default=ROOT / 'runtime-model.joblib')
    args = parser.parse_args()
    prepare(args.source, args.output)
