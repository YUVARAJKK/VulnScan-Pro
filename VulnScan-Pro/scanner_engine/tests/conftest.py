"""Pytest configuration and shared fixtures."""

import sys
import os

# Add scanner_engine to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
