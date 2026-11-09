from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"
RULES = ROOT / "secwatch" / "rules"


@pytest.fixture
def samples() -> Path:
    return SAMPLES


@pytest.fixture
def rules_dir() -> Path:
    return RULES
