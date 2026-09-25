from dataclasses import dataclass
from pathlib import Path

from agnostic.models.mode import Mode


@dataclass(frozen=True)
class Context:
    """
    The ambient facts of one call, whatever the harness that makes it.
    """
    current_cwd:Path = Path()
    harness_root:Path = Path()  # the harness own directory, read-only unless it is the project
    intent:str = ""
    mode:Mode = Mode.MANUAL
    project_root:Path = Path()
