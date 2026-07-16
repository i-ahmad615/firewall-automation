"""Root conftest.py -- makes the project root importable from tests."""
import sys
import os

# Ensure 'core' is importable as a top-level package when running pytest
# from any working directory.
sys.path.insert(0, os.path.dirname(__file__))
