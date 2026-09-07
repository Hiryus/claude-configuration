# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import json
from pathlib import Path

import pytest
import utils.session
from user_prompt_submit import AUTO_MODE_NOTE, main
from utils.session import read_mode, write_mode

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
    The hook's answer, parsed. An ordinary prompt outside auto mode answers nothing at all.
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
# The mode command
# ============================================================================

@pytest.mark.parametrize("mode", ["manual", "edit", "auto"])
def test_switching_stops_the_prompt_and_says_so(mode):
    assert blocked(f"mode {mode}") == f"Mode is now {mode.upper()} for this session."

@pytest.mark.parametrize("mode", ["manual", "edit", "auto"])
def test_switching_records_the_mode(mode):
    run(f"mode {mode}")
    assert read_mode(SESSION) == mode

def test_the_mode_survives_between_prompts():
    run("mode auto")
    assert injected("carry on") == AUTO_MODE_NOTE
    run("mode edit")
    assert injected("carry on") is None

@pytest.mark.parametrize("prompt", [
    "mode auto please",
    "please set mode auto",
    "modes auto",
    "mode autoo",
    "mode auto edit",
    "mode config",
    "the `mode auto` command",
])
def test_only_the_command_alone_counts(prompt):
    # A prompt that merely mentions the command is an ordinary prompt: swallowing it would lose work.
    assert blocked(prompt) is None

def test_an_unknown_mode_name_is_not_the_command():
    # It must not be recorded either: an unrecognised name would read back as manual anyway.
    run("mode config")
    assert read_mode(SESSION) is None

def test_a_command_is_never_answered_with_the_note():
    run("mode auto")
    assert injected("mode manual") is None

# ============================================================================
# Reporting the mode
# ============================================================================

def test_bare_mode_reports_the_current_mode():
    write_mode(SESSION, "edit")
    assert blocked("mode") == "Mode is EDIT for this session."

def test_bare_mode_reports_manual_when_nothing_was_ever_set():
    assert blocked("mode") == "Mode is MANUAL for this session."

def test_bare_mode_reports_what_the_hooks_will_apply():
    # An unknown recorded name is manual for the tool hooks, so the bar-side answer says manual too.
    write_mode(SESSION, "config")
    assert blocked("mode") == "Mode is MANUAL for this session."

def test_reporting_changes_nothing():
    write_mode(SESSION, "auto")
    run("mode")
    assert read_mode(SESSION) == "auto"

# ============================================================================
# Ordinary prompts
# ============================================================================

@pytest.mark.parametrize("mode", ["manual", "edit"])
def test_says_nothing_outside_auto_mode(mode):
    # On this event a bare stdout is itself appended to the context, so silence has to stay silent.
    write_mode(SESSION, mode)
    assert run("what does this do?") == {}

def test_says_nothing_when_no_mode_was_recorded():
    assert run("what does this do?") == {}

def test_injects_the_note_while_the_mode_is_auto():
    write_mode(SESSION, "auto")
    assert injected("what does this do?") == AUTO_MODE_NOTE

def test_the_note_names_the_mode_and_where_the_rules_live():
    write_mode(SESSION, "auto")
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
    reason = blocked("mode auto", session_id="")
    assert reason is not None
    assert "no session id" in reason

def test_a_report_without_a_session_id_answers_manual():
    # Nothing can be recorded for that session, so nothing but manual can be applied to it.
    assert blocked("mode", session_id="") == "Mode is MANUAL for this session."

def test_an_ordinary_prompt_without_a_session_id_goes_through():
    assert run("what does this do?", session_id="") == {}
