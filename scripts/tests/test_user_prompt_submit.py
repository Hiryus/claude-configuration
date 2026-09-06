# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import json
from pathlib import Path

import pytest
import utils.session
from user_prompt_submit import AUTO_MODE_NOTE, main
from utils.session import read_auto_mode, write_auto_mode

SESSION = "6c194564-b08a-44dc-9661-8d05e07cb52d"

# ============================================================================
# Helpers
# ============================================================================

@pytest.fixture(autouse=True)
def sessions(tmp_path, monkeypatch) -> Path:
    """
    The state files go under `tmp_path`: the real `~/.claude/sessions` belongs to the harness and a
    test has no business writing there. Autouse, so that no test reaches it by forgetting to ask.
    """
    directory = tmp_path / "sessions"
    monkeypatch.setattr(utils.session, "SESSIONS_DIR", directory)
    return directory

def run(prompt:str, session_id:str = SESSION) -> dict:
    """
    The hook's answer, parsed. An ordinary prompt in manual mode answers nothing at all.
    """
    response = main({
        "hook_event_name": "UserPromptSubmit",
        "session_id": session_id,
        "cwd": "/proj",
        "prompt": prompt,
    })
    return json.loads(response) if response is not None else {}

def blocked(prompt:str, session_id:str = SESSION) -> str|None:
    """
    The reason shown to the user when the prompt is stopped, or None when it went through.
    """
    response = run(prompt, session_id)
    return response.get("reason") if response.get("decision") == "block" else None

def injected(prompt:str, session_id:str = SESSION) -> str|None:
    """
    The text appended to the prompt the model receives, or None when nothing was appended.
    """
    return run(prompt, session_id).get("hookSpecificOutput", {}).get("additionalContext")

# ============================================================================
# The auto command
# ============================================================================

def test_switching_on_stops_the_prompt_and_says_so():
    assert blocked("auto on") == "Auto mode is now ON for this session."

def test_switching_off_stops_the_prompt_and_says_so():
    write_auto_mode(SESSION, True)
    assert blocked("auto off") == "Auto mode is now OFF for this session."

def test_switching_on_records_the_mode():
    run("auto on")
    assert read_auto_mode(SESSION) is True

def test_switching_off_records_the_mode():
    write_auto_mode(SESSION, True)
    run("auto off")
    assert read_auto_mode(SESSION) is False

def test_the_mode_survives_between_prompts():
    run("auto on")
    assert injected("carry on") == AUTO_MODE_NOTE
    run("auto off")
    assert injected("carry on") is None

@pytest.mark.parametrize("prompt", ["auto on", "! auto on", "!auto on", "  !  AUTO   On  ", "Auto ON"])
def test_accepts_the_spellings_of_the_command(prompt):
    # The leading `!` is optional: typed first in the TUI it switches the input to bash mode, where
    # the harness never calls this hook at all.
    assert blocked(prompt) == "Auto mode is now ON for this session."

def test_bare_auto_toggles_the_mode():
    # Promised by the module docstring: "`auto` without any suffix toggles the mode".
    assert blocked("auto") == "Auto mode is now ON for this session."
    assert blocked("auto") == "Auto mode is now OFF for this session."

@pytest.mark.parametrize("prompt", [
    "auto on please",
    "please set auto on",
    "automatic on",
    "auto onn",
    "auto on off",
    "the `auto on` command",
])
def test_only_the_command_alone_counts(prompt):
    # A prompt that merely mentions the command is an ordinary prompt: swallowing it would lose work.
    assert blocked(prompt) is None

def test_a_command_is_never_answered_with_the_note():
    run("auto on")
    assert injected("auto off") is None

# ============================================================================
# Ordinary prompts
# ============================================================================

def test_says_nothing_while_the_mode_is_off():
    # On this event a bare stdout is itself appended to the context, so silence has to stay silent.
    assert run("what does this do?") == {}

def test_injects_the_note_while_the_mode_is_on():
    write_auto_mode(SESSION, True)
    assert injected("what does this do?") == AUTO_MODE_NOTE

def test_the_note_names_the_mode_and_where_the_rules_live():
    write_auto_mode(SESSION, True)
    text = injected("what does this do?")
    assert text is not None
    assert "auto mode" in text.lower()

def test_an_empty_prompt_is_an_ordinary_prompt():
    assert run("") == {}

def test_a_missing_prompt_is_an_ordinary_prompt():
    assert main({"hook_event_name": "UserPromptSubmit", "session_id": SESSION}) is None

# ============================================================================
# The session id
# ============================================================================
# The id itself -- what makes it usable as a file name, and what the state file does with it -- is
# tested in test_session.py. Here only what the hook answers when there is none.

def test_a_command_without_a_session_id_is_stopped_and_explained():
    reason = blocked("auto on", session_id="")
    assert reason is not None
    assert "no session id" in reason

def test_an_ordinary_prompt_without_a_session_id_goes_through():
    assert run("what does this do?", session_id="") == {}
