# test/minimal_test.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_minimal():
    # Basic passing test to ensure discovery works
    assert 1 + 1 == 2  # Simple assertion