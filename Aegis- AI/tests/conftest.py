import os
import sys

# Make `src.*` importable when tests are run from the project root or from
# within tests/ (mirrors what src/api/main.py does manually at import time).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# src/api/main.py resolves config/data paths relative to the current working
# directory (e.g. "./config/config.yaml", "./data/aegis.db"), so tests need
# to run with the project root as cwd regardless of where pytest was invoked
# from.
os.chdir(PROJECT_ROOT)

# Give every test run a stable, known API key instead of a randomly
# generated one, so tests don't need to scrape stdout for the key.
os.environ.setdefault("AEGIS_API_KEY", "test-key-do-not-use-in-prod")
