# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import json
from pathlib import Path

import pytest
import utils.session
from utils.session import read_mode, state_file, write_mode

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
    write_mode(SESSION, "auto")
    assert json.loads((sessions / f"{SESSION}.json").read_text(encoding="utf-8")) == {"mode": "auto"}

def test_the_directory_is_created_on_demand(sessions):
    assert not sessions.exists()
    write_mode(SESSION, "auto")
    assert sessions.is_dir()

def test_writing_keeps_the_other_keys(sessions):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text('{"pid": 141269}', encoding="utf-8")
    write_mode(SESSION, "auto")
    assert json.loads((sessions / f"{SESSION}.json").read_text(encoding="utf-8")) == {"pid": 141269, "mode": "auto"}

@pytest.mark.parametrize("contents", ["", "not json", "[]", "null"])
def test_writing_replaces_a_file_it_cannot_read(sessions, contents):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text(contents, encoding="utf-8")
    write_mode(SESSION, "auto")
    assert read_mode(SESSION) == "auto"

def test_writing_leaves_no_leftovers(sessions):
    # One session, one file: nothing else is left behind in the sessions directory.
    write_mode(SESSION, "auto")
    assert [path.name for path in sessions.iterdir()] == [f"{SESSION}.json"]

@pytest.mark.parametrize("mode", ["manual", "edit", "auto"])
def test_every_mode_makes_the_round_trip(mode):
    write_mode(SESSION, mode)
    assert read_mode(SESSION) == mode

def test_a_missing_file_reads_as_nothing():
    assert read_mode(SESSION) is None

@pytest.mark.parametrize("contents", ["", "not json", "[]", "null", '"mode"', "{}", '{"auto": true}'])
def test_anything_without_a_recorded_mode_reads_as_nothing(sessions, contents):
    # `{"auto": true}` is the previous format: it carries no mode, so it reads as nothing and the
    # session falls back to manual. Erring towards more validation, never less.
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text(contents, encoding="utf-8")
    assert read_mode(SESSION) is None

@pytest.mark.parametrize("contents", ['{"mode": 1}', '{"mode": true}', '{"mode": ["auto"]}'])
def test_only_a_name_counts(sessions, contents):
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text(contents, encoding="utf-8")
    assert read_mode(SESSION) is None

def test_an_unknown_name_is_read_back_as_is(sessions):
    # Storage does not judge the name; naming what it means is `Mode.of`'s job.
    sessions.mkdir(parents=True)
    (sessions / f"{SESSION}.json").write_text('{"mode": "config"}', encoding="utf-8")
    assert read_mode(SESSION) == "config"

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
        write_mode("../../evil", "auto")
    assert not sessions.exists()

def test_an_unusable_id_reads_as_nothing():
    assert read_mode("../../evil") is None
