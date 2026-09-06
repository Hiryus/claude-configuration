"""
The per-session "auto" mode: set by the `auto` command, read back by everything that needs to know whether anyone is watching.
It lives in `~/.claude/sessions/<session_id>.json`, one JSON object per session, our flag under the `auto` key.
"""

import json
import re
from pathlib import Path

SESSIONS_DIR = Path.home() / ".claude" / "sessions"
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def read_auto_mode(session_id:str) -> bool:
    """
    True when the session was switched to auto mode.
    Tolerant by design: a missing, unreadable or corrupt file means "not in auto mode".
    """
    path = state_file(session_id)
    if path is None or not path.is_file():
        return False
    try:
        contents = path.read_text(encoding="utf-8")
        return json.loads(contents).get("auto") is True
    except (OSError, ValueError, AttributeError):
        return False

def state_file(session_id:str) -> Path|None:
    """
    Where the mode of one session lives. None when the id cannot be trusted as a file name.
    """
    if not session_id or not SESSION_ID.match(session_id):
        return None
    return SESSIONS_DIR / f"{session_id}.json"

def write_auto_mode(session_id:str, enabled:bool) -> None:
    """
    Record the mode of one session.
    The other keys of the file, if any, are kept to allow further information recording.
    """
    # Ensure the folder exists
    path = state_file(session_id)
    if path is None:
        raise ValueError(f"unusable session id: {session_id!r}")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Read the current file
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    # Add the information and write the file
    state["auto"] = enabled
    with open(path, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)
