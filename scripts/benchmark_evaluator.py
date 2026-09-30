"""Runs only INSIDE the credential-free evaluator container; pytest owns exit codes."""

import sys

import pytest

sys.path.insert(0, "/case")
raise SystemExit(pytest.main(["-q", "-p", "no:cacheprovider", "/case/test_generated.py"]))
