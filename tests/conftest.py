from pathlib import Path

import pytest

from twin.engine import Twin
from twin.loader import load_snapshot

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="session")
def lab1():
    return load_snapshot(SAMPLES / "lab1")


@pytest.fixture(scope="session")
def twin(lab1):
    return Twin(lab1)


@pytest.fixture(scope="session")
def ent():
    return Twin(load_snapshot(SAMPLES / "enterprise"))
