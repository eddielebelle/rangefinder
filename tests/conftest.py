# Ensures the tests directory is importable so `from helpers import ...` works
# regardless of pytest import mode.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
