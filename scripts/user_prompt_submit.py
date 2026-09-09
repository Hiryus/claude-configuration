"""
Hook pre-processing the user prompts to carry the session mode:
- `/mode manual|edit|auto` changes the mode and never reaches the model,
- `/mode info` - or `/mode` alone - reports the current mode (and never reaches the model),
- any other prompt gets a system note injected while the session is in auto mode.

The `/mode` skill (`~/.claude/skills/mode/SKILL.md`) only registers the name so that the harness
accepts and completes it: the prompt is stopped here, before the skill body is ever expanded.

The mode is stored per session in `~/.claude/sessions/<session_id>.json`, so that the file hooks
can read it back: it is the only thing they consult, the harness permission mode plays no part.
"""

import json
import re
import sys

from models.analyzer import Mode
from utils.session import read_mode, write_mode

AUTO_MODE_NOTE = "**You are running in auto mode.**"
MODE_COMMAND = re.compile(r"^\s*/mode(\s+(?P<name>manual|edit|auto|info))?\s*$", re.IGNORECASE)
REPORT = "info"  # `/mode info` and `/mode` alone both report rather than switch.

# ============================================================================
# Hook I/O
# ============================================================================

def format_block(reason:str) -> str:
    """
    Stop the prompt before it reaches the model. The reason is shown to the user, not to the agent.
    """
    return json.dumps({
        "decision": "block",
        "reason": reason,
    })

def format_context(additional_context:str) -> str:
    """
    Append text to the prompt the model receives.
    """
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": additional_context,
        }
    })

# ============================================================================
# Prompt handling
# ============================================================================

def main(input_data:dict) -> str|None:
    prompt:str = input_data.get("prompt") or ""
    session_id:str = input_data.get("session_id") or ""

    if (command := MODE_COMMAND.match(prompt)) is not None:
        name:str|None = (command.group("name") or "").lower() or None
        if name is None or name == REPORT:
            # Reported through `Mode.of`, not raw: this is the mode the tool hooks will actually apply.
            return format_block(f"Mode is currently {Mode.of(read_mode(session_id)).value.upper()}.")
        if not session_id:
            return format_block("Cannot switch the mode: the harness gave no session id.")
        write_mode(session_id, name)
        return format_block(f"Mode is now {name.upper()} for this session.")

    if Mode.of(read_mode(session_id)) is Mode.AUTO:
        return format_context(AUTO_MODE_NOTE)


if __name__ == "__main__":
    input_data:dict = json.loads(sys.stdin.read())
    if (response := main(input_data)) is not None:
        print(response)
    # Nothing is printed for an ordinary prompt: on this event a bare stdout would itself be appended to the model's context.
