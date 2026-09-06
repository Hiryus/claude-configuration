# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import json
from pathlib import Path

import pytest
import utils.session
from utils.session import read_auto_mode, state_file, write_auto_mode

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

# ============================================================================
# The state file
# ============================================================================

def test_the_file_is_named_after_the_session(sessions):
    write_auto_mode(SESSION, True)
    assert json.loads((sessions / f"{SESSION}.json").read_text(encoding="utf-8")) == {"auto": True}

def test_the_directory_is_created_on_demand(sessions):
    assert not sessions.exists()
    write_auto_mode(SESSION, True)
    assert sessions.is_dir()

def test_writing_keeps_the_other_keys(sessions):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text('{"pid": 141269}', encoding="utf-8")
    write_auto_mode(SESSION, True)
    assert json.loads((sessions / f"{SESSION}.json").read_text(encoding="utf-8")) == {"pid": 141269, "auto": True}

@pytest.mark.parametrize("contents", ["", "not json", "[]", "null"])
def test_writing_replaces_a_file_it_cannot_read(sessions, contents):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text(contents, encoding="utf-8")
    write_auto_mode(SESSION, True)
    assert read_auto_mode(SESSION) is True

def test_writing_leaves_no_leftovers(sessions):
    # The write goes through a temporary file: it must not survive the rename.
    write_auto_mode(SESSION, True)
    assert [path.name for path in sessions.iterdir()] == [f"{SESSION}.json"]

def test_a_missing_file_reads_as_off():
    assert read_auto_mode(SESSION) is False

@pytest.mark.parametrize("contents", ["", "not json", "[]", "null", '"auto"', "{}", '{"auto": false}'])
def test_anything_but_a_recorded_on_reads_as_off(sessions, contents):
    # Tolerant on purpose: failing the other way would hand the agent an unattended session in silence.
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text(contents, encoding="utf-8")
    assert read_auto_mode(SESSION) is False

@pytest.mark.parametrize("contents", ['{"auto": "yes"}', '{"auto": 1}'])
def test_only_a_real_true_counts(sessions, contents):
    assert read_auto_mode(SESSION) is False

# ============================================================================
# The session id
# ============================================================================

@pytest.mark.parametrize("session_id", ["../../evil", "a/b", "..", "", "a" * 129, "id.json", "id space"])
def test_refuses_an_id_that_would_not_be_a_safe_file_name(session_id):
    # The id becomes a file name, so it is checked rather than trusted.
    assert state_file(session_id) is None

@pytest.mark.parametrize("session_id", [SESSION, "abc", "A-1_b"])
def test_accepts_a_plain_id(session_id):
    assert state_file(session_id) is not None

def test_an_unusable_id_writes_nothing(sessions):
    with pytest.raises(ValueError):
        write_auto_mode("../../evil", True)
    assert not sessions.exists()

def test_an_unusable_id_reads_as_off():
    assert read_auto_mode("../../evil") is False
