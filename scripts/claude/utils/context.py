import os
from collections.abc import Mapping
from pathlib import Path

from agnostic.models.context import Context
from agnostic.models.mode import Mode
from agnostic.models.parsing import ContextError
from claude.utils import session


def context_of(input_data: dict, environ: Mapping[str, str] = os.environ) -> Context:
    """
    The ambient facts of one Claude Code hook call, read from its payload and environment.
    """
    cwd:str|None = input_data.get("cwd")
    project_root:str|None = environ.get("CLAUDE_PROJECT_DIR")
    if not cwd:
        raise ContextError("the payload carries no `cwd`")
    if not project_root:
        raise ContextError("the `CLAUDE_PROJECT_DIR` environment variable is not set")
    mode_name = session.read_mode(str(input_data.get("session_id") or ""))
    return Context(
        current_cwd=Path(cwd).resolve(),
        harness_root=Path.home() / ".claude",
        intent=input_data.get("tool_input", {}).get("description") or "",
        mode=Mode.of(mode_name),
        project_root=Path(project_root).resolve(),
    )
