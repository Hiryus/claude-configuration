# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import io
import json
import re
import sys
from pathlib import Path

import pytest
import utils.session
from statusline_command import main
from utils.session import write_auto_mode

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

def render(monkeypatch, capsys, **payload) -> str:
    """
    The rendered bar, escape codes and all. The payload is the harness JSON, one line on stdin.
    """
    defaults = {
        "session_id": SESSION,
        "workspace": {"current_dir": "/home/user/adventure"},
        "model": {"id": "claude-opus-5", "display_name": "Opus"},
        "context_window": {"context_window_size": 200_000, "total_input_tokens": 1_000},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({**defaults, **payload})))
    main()
    return capsys.readouterr().out

def segment(bar:str) -> str|None:
    """
    The `auto:` part of the bar, stripped of its colors, or None when the bar carries none.
    """
    plain = re.sub(r"\x1b\[[0-9;]*m", "", bar)
    for part in plain.split(" | "):
        if part.startswith("auto:"):
            return part
    return None

# ============================================================================
# The auto segment
# ============================================================================

def test_the_bar_says_off_while_the_mode_is_off(monkeypatch, capsys):
    assert segment(render(monkeypatch, capsys)) == "auto:off"

def test_the_bar_says_on_while_the_mode_is_on(monkeypatch, capsys):
    write_auto_mode(SESSION, True)
    assert segment(render(monkeypatch, capsys)) == "auto:on"

def test_the_bar_follows_the_state_file(monkeypatch, capsys):
    write_auto_mode(SESSION, True)
    assert segment(render(monkeypatch, capsys)) == "auto:on"
    write_auto_mode(SESSION, False)
    assert segment(render(monkeypatch, capsys)) == "auto:off"

def test_each_session_shows_its_own_mode(monkeypatch, capsys):
    write_auto_mode(SESSION, True)
    assert segment(render(monkeypatch, capsys, session_id="another-session")) == "auto:off"

def test_the_mode_is_colored_while_it_is_on(monkeypatch, capsys):
    # The one part of the bar meant to catch the eye: unattended is not the resting state.
    write_auto_mode(SESSION, True)
    assert "\x1b[38;5;208mon\x1b[0m" in render(monkeypatch, capsys)

# ============================================================================
# An unknown mode
# ============================================================================

def test_a_payload_without_a_session_id_says_nothing(monkeypatch, capsys):
    # Unknown is not off: the bar leaves the part out rather than claim someone is watching.
    assert segment(render(monkeypatch, capsys, session_id="")) is None

@pytest.mark.parametrize("session_id", ["../../evil", "a/b", "..", "id space"])
def test_an_id_that_is_not_a_safe_file_name_says_nothing(monkeypatch, capsys, session_id):
    assert segment(render(monkeypatch, capsys, session_id=session_id)) is None

def test_an_unreadable_state_file_says_off(sessions, monkeypatch, capsys):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text("not json", encoding="utf-8")
    assert segment(render(monkeypatch, capsys)) == "auto:off"

# ============================================================================
# The rest of the bar
# ============================================================================

def test_the_other_parts_are_left_alone(monkeypatch, capsys):
    write_auto_mode(SESSION, True)
    bar = render(monkeypatch, capsys)
    assert "repo:" in bar and "adventure" in bar
    assert "ctx:" in bar
    assert "claude-opus-5" in bar

def test_the_mode_comes_right_after_the_repo(monkeypatch, capsys):
    bar = render(monkeypatch, capsys)
    assert bar.index("auto:") > bar.index("repo:")
    assert bar.index("auto:") < bar.index("ctx:")

def test_an_empty_payload_still_renders(monkeypatch, capsys):
    # The bar is drawn on every keystroke: a missing key must never take the whole line down.
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    main()
    assert "repo:" in capsys.readouterr().out
