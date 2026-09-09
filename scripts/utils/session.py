"""
The per-session mode: set by the `/mode` command, read back by everything that needs to know how much autonomy the session runs with.
It lives in `~/.claude/sessions/<session_id>.json`, one JSON object per session, our name under the `mode` key.

The file holds the raw name, not a `Mode` enum.
This module stays the storage layer and returns the setting written in the file as str (or possibly None).
"""

import json
import re
from pathlib import Path

SESSIONS_DIR = Path.home() / ".claude" / "sessions"
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def read_mode(session_id:str) -> str|None:
    """
    The mode name recorded for the session, or None when there is nothing to read.
    Tolerant by design: a missing, unreadable or corrupt file reads as "nothing recorded".
    """
    path = state_file(session_id)
    if path is None or not path.is_file():
        return None
    try:
        contents = path.read_text(encoding="utf-8")
        name = json.loads(contents).get("mode")
        return name if isinstance(name, str) else None
    except (OSError, ValueError, AttributeError):
        return None

def state_file(session_id:str) -> Path|None:
    """
    Where the mode of one session lives. None when the id cannot be trusted as a file name.
    """
    if not session_id or not SESSION_ID.match(session_id):
        return None
    return SESSIONS_DIR / f"{session_id}.json"

def write_mode(session_id:str, mode:str) -> None:
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
    state["mode"] = mode
    with open(path, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)
