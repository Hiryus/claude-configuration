from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Decision(Enum):
    """
    The verdict for one command. ALLOW < ASK < DENY in severity.
    """
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"

class Mode(Enum):
    """
    How much autonomy the call runs with, derived from the harness permission mode.
    Source: https://code.claude.com/docs/en/permissions#permission-modes
    """
    MANUAL = "manual"  # the user validates most calls
    EDIT = "edit"      # most edits are pre-approved
    AUTO = "auto"      # the agent runs unattended

    @staticmethod
    def of(permission_mode: str) -> "Mode":
        if permission_mode in ("default", "plan"):
            return Mode.MANUAL
        if permission_mode == "acceptEdits":
            return Mode.EDIT
        return Mode.AUTO

@dataclass(frozen=True)
class Context:
    """
    The ambient facts of one hook call, passed to every check so a rule can
    depend on the mode or the project boundary without re-reading the payload.
    """
    hook_event_name:str = ""
    intent:str = ""
    mode:Mode = Mode.MANUAL
    project_root:Path = Path()
    tool_name:str = ""

    @staticmethod
    def of(input_data: dict) -> "Context":
        return Context(
            hook_event_name=input_data.get("hook_event_name", ""),
            intent=input_data.get("tool_input", {}).get("description") or "",
            mode=Mode.of(input_data.get("permission_mode", "default")),
            project_root=Path(input_data.get("cwd", "")),
            tool_name=input_data.get("tool_name", ""),
        )
