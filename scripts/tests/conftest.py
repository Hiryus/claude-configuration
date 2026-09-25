import sys
from pathlib import Path

# The `agnostic` and `claude` packages are rooted at `scripts/` (`from agnostic.models import ...`),
# so the `scripts/` dir must be on sys.path for the test process to import them.
SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))
