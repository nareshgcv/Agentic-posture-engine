import pytest
from ape_linter import load_policy

@pytest.fixture
def default_policy():
    """Returns default policy dictionary."""
    return load_policy(None)
