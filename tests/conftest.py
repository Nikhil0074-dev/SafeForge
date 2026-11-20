import os
import sys
import warnings

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "corpus"), os.path.join(ROOT, "scripts")]
warnings.filterwarnings("ignore", message=".*init_forms.*")
warnings.filterwarnings("ignore", category=UserWarning, module="zipfile")

import make_corpus

from safeforge.engine import sanitize


@pytest.fixture(scope="session")
def corpus():
    return {f.name: f for f in make_corpus.build_all()}


@pytest.fixture(scope="session")
def run(corpus):
    cache = {}

    def _run(name, mode="balanced", **overrides):
        key = (name, mode, tuple(sorted(overrides.items())))
        if key not in cache:
            f = corpus[name]
            cache[key] = sanitize(f.data, f.filename, mode, overrides or None)
        return cache[key]
    return _run
