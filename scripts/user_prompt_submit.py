"""
Hook pre-processing the user prompts to carry the session "auto" mode:
- `auto on` / `auto off` changes the mode and never reaches the model,
- `auto` without any suffix toggles the mode (and never reaches the model),
- any other prompt gets a system note injected while the mode is on.

The mode is stored per session in `~/.claude/sessions/<session_id>.json`, so that the file hooks
can read it back and treat the session as unattended whatever the harness permission mode says.
"""

import json
import re
import sys

from utils.session import read_auto_mode, write_auto_mode

AUTO_MODE_NOTE = "**You are running in auto mode.**"
AUTO_COMMAND = re.compile(r"^\s*!?\s*auto(\s+(?P<state>on|off))?\s*$", re.IGNORECASE)

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

def toggle(prompt:str, session_id:str) -> bool|None:
    """
    The mode the prompt asks for, or None when it is an ordinary prompt.
    """
    match = AUTO_COMMAND.match(prompt)
    if match is None:
        return None
    if (state := match.group("state")) is None:
        return not read_auto_mode(session_id)
    return state.lower() == "on"


def main(input_data:dict) -> str|None:
    prompt:str = input_data.get("prompt") or ""
    session_id:str = input_data.get("session_id") or ""

    if (requested := toggle(prompt, session_id)) is not None:
        if not session_id:
            return format_block("Cannot switch the auto mode: the harness gave no session id.")
        write_auto_mode(session_id, requested)
        return format_block(f"Auto mode is now {'ON' if requested else 'OFF'} for this session.")

    if read_auto_mode(session_id):
        return format_context(AUTO_MODE_NOTE)


if __name__ == "__main__":
    input_data:dict = json.loads(sys.stdin.read())
    if (response := main(input_data)) is not None:
        print(response)
    # Nothing is printed for an ordinary prompt: on this event a bare stdout would itself be appended to the model's context.
