from dataclasses import dataclass, field
from pathlib import Path

from agnostic.models.mode import Mode


@dataclass(frozen=True)
class Context:
    """
    The ambient facts of one call, whatever the harness that makes it.
    """
    current_cwd:Path = Path()
    harness_roots:list[Path] = field(default_factory=list)
    intent:str = ""
    mode:Mode = Mode.MANUAL
    project_root:Path = Path()
