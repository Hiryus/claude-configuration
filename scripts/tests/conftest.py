import sys
from pathlib import Path

# The hook scripts use top-level imports (`from model import ...`).
# So the `scripts/` dir must be on sys.path for the test process to import them.
SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))
