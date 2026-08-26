# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import json
from pathlib import Path

import pytest
from pre_file_access import main

HOOK = "pre_file_access.py"
ROOT = "/proj"
FAKE_HOME = "/home/fakeuser"

# `project_root` defaults to the `cwd` argument, which reproduces the behavior from
# before cwd tracking exactly. `project_root=None` sends an empty environment, i.e.
# CLAUDE_PROJECT_DIR unset -- so the sentinel cannot be None itself.
SAME_AS_CWD = object()

# ============================================================================
# Helpers
# ============================================================================

def environment(cwd:object, project_root:object) -> dict[str, str]:
    """
    The environment the hook reads `CLAUDE_PROJECT_DIR` from.
    Anything that is not a string (the `None` of the "unset" cases) leaves it out.
    """
    root = cwd if project_root is SAME_AS_CWD else project_root
    return {"CLAUDE_PROJECT_DIR": root} if isinstance(root, str) else {}

def output(file_path:str, tool_name="Read", cwd=ROOT, mode="default", project_root=SAME_AS_CWD):
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "permission_mode": mode,
        "tool_input": {
            "file_path": file_path,
        },
    }, environ=environment(cwd, project_root))
    return json.loads(result).get("hookSpecificOutput", {})

def run(file_path:str, tool_name="Read", cwd=ROOT, mode="default", project_root=SAME_AS_CWD):
    return output(file_path, tool_name, cwd, mode, project_root).get("permissionDecision")

def reason(file_path:str, tool_name="Read", cwd=ROOT, mode="default", project_root=SAME_AS_CWD):
    return output(file_path, tool_name, cwd, mode, project_root).get("permissionDecisionReason")

# ============================================================================
# Modes
# ============================================================================

def test_auto_mode_turns_ask_into_deny():
    # Rule "Modes": no interactive validation in auto mode.
    assert run(file_path="/elsewhere/notes.txt") == "ask"
    assert run(file_path="/elsewhere/notes.txt", mode="bypassPermissions") == "deny"

def test_auto_mode_deny_explains_the_mode_and_keeps_the_ask_reason():
    denial = reason(file_path="/elsewhere/notes.txt", mode="bypassPermissions")
    assert "auto mode" in denial
    assert "outside the project" in denial

@pytest.mark.parametrize("mode", ["default", "plan", "acceptEdits"])
def test_other_modes_keep_asking(mode):
    assert run(file_path="/elsewhere/notes.txt", mode=mode) == "ask"

@pytest.mark.parametrize("tool_name", ["Read", "Write"])
def test_auto_mode_keeps_allow(tool_name):
    assert run(file_path="/proj/main.py", tool_name=tool_name, mode="bypassPermissions") == "allow"

def test_auto_mode_keeps_the_deny_reason():
    assert run(file_path="/proj/.env", mode="bypassPermissions") == "deny"
    assert "secret" in reason(file_path="/proj/.env", mode="bypassPermissions")

# ============================================================================
# Secrets
# ============================================================================

@pytest.mark.parametrize("file_path", ["/proj/.env", "/proj/config/.env.local", "/proj/server.pem", "/proj/id_rsa"])
def test_secret_files_denied(file_path):
    assert run(file_path=file_path) == "deny"

def test_env_example_is_not_secret():
    assert run(file_path="/proj/.env.example") == "allow"

@pytest.mark.parametrize("file_path", ["/proj/.env.prod", "/proj/.env.production", "/proj/.ENV.PRODUCTION"])
def test_production_env_files_denied(file_path):
    assert run(file_path=file_path) == "deny"

@pytest.mark.parametrize("file_path", [
    "/proj/server.PEM",
    "/proj/SERVER.Key",
    "/proj/store.JKS",
    "/proj/.NETRC",
    "/proj/ID_RSA",
    "/proj/.SSH/known_hosts",
])
def test_secret_files_denied_whatever_their_spelling(file_path):
    assert run(file_path=file_path) == "deny"

@pytest.mark.parametrize("suffix", [".example", ".sample", ".template", ".EXAMPLE"])
def test_template_suffixes_are_exempted(suffix):
    assert run(file_path=f"/proj/.ssh/config{suffix}") == "allow"

def test_dist_suffix_is_not_a_template():
    assert run(file_path="/proj/.ssh/config.dist") == "deny"

@pytest.mark.parametrize("relative", [".claude/.credentials.json", ".claude.json"])
def test_harness_credentials_read_denied(monkeypatch, relative):
    # Rule 1.1: the harness directory is readable (rule 1.4), except its tokens.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(file_path=str(Path(FAKE_HOME) / relative), tool_name="Read") == "deny"

def test_harness_credentials_write_denied_when_the_harness_is_the_project(monkeypatch):
    # Rule 1.1 beats rule 1.3's exception: working *on* the harness does not
    # make its tokens writable.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = Path(FAKE_HOME) / ".claude"
    assert run(file_path=str(harness / ".credentials.json"), tool_name="Write", cwd=str(harness), mode="acceptEdits") == "deny"

def test_harness_configuration_is_not_a_credentials_file(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(file_path=str(Path(FAKE_HOME) / ".claude" / "settings.json"), tool_name="Read") == "allow"

# ============================================================================
# Git files
# ============================================================================

@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_git_dir_writes_denied(tool):
    assert run(file_path="/proj/.git/config", tool_name=tool) == "deny"

def test_git_dir_read_allowed():
    assert run(file_path="/proj/.git/config", tool_name="Read") == "allow"

# ============================================================================
# Project location
# ============================================================================

def test_in_project_allowed():
    assert run(file_path="/proj/src/main.py") == "allow"

def test_outside_project_asks():
    assert run(file_path="/other/file.txt") == "ask"

def test_tmp_outside_project_allowed():
    assert run(file_path="/tmp/scratch.txt") == "allow"

def test_read_claude_dir_allowed(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    path = str(Path(FAKE_HOME) / ".claude" / "settings.json")
    assert run(file_path=path, tool_name="Read") == "allow"

@pytest.mark.parametrize("mode", ["default", "plan", "acceptEdits"])
def test_write_claude_dir_denied_from_another_project(monkeypatch, mode):
    # Rule 1.3: the harness is off-limits whatever the mode, since writing it
    # would let the agent lift its own restrictions.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    path = str(Path(FAKE_HOME) / ".claude" / "settings.json")
    assert run(file_path=path, tool_name="Write", mode=mode) == "deny"

def test_write_claude_subdir_denied_from_another_project(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    path = str(Path(FAKE_HOME) / ".claude" / "scripts" / "utils.py")
    assert run(file_path=path, tool_name="Write") == "deny"

def test_write_claude_dir_asks_when_it_is_the_project(monkeypatch):
    # Rule 1.3: working *on* the harness is the one case where writing it is
    # legitimate -- still an ask in manual mode.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = Path(FAKE_HOME) / ".claude"
    assert run(file_path=str(harness / "scripts" / "utils.py"), tool_name="Write", cwd=str(harness)) == "ask"

def test_write_claude_dir_allowed_when_it_is_the_project(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = Path(FAKE_HOME) / ".claude"
    assert run(file_path=str(harness / "scripts" / "utils.py"), tool_name="Write", cwd=str(harness), mode="acceptEdits") == "allow"

def test_write_claude_dir_denied_outside_a_project_nested_in_it(monkeypatch):
    # The project is a harness subdirectory: files above it are still harness
    # files, and off-limits.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = Path(FAKE_HOME) / ".claude"
    scripts = harness / "scripts"
    assert run(file_path=str(harness / "settings.json"), tool_name="Write", cwd=str(scripts), project_root=str(scripts)) == "deny"

def test_harness_as_project_is_decided_by_the_project_root_not_the_cwd(monkeypatch):
    # Rule 1.3's exception is about the *project* being the harness. The agent
    # moving into a subdirectory does not shrink the project down to it.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = Path(FAKE_HOME) / ".claude"
    target = str(harness / "settings.json")
    assert run(file_path=target, tool_name="Write", cwd=str(harness / "scripts"), project_root=str(harness), mode="acceptEdits") == "allow"

# ============================================================================
# Context: the project root and the current directory are two different things
# ============================================================================

def test_missing_project_root_denied():
    assert run(file_path="/proj/main.py", project_root=None) == "deny"
    assert "CLAUDE_PROJECT_DIR" in reason(file_path="/proj/main.py", project_root=None)

@pytest.mark.parametrize("cwd", ["", None])
def test_missing_cwd_denied(cwd):
    assert run(file_path="/proj/main.py", cwd=cwd) == "deny"

def test_relative_path_is_anchored_on_the_cwd():
    assert run(file_path="notes.txt", cwd="/proj/work", project_root="/proj") == "allow"
    assert run(file_path="../../elsewhere/notes.txt", cwd="/proj/work", project_root="/proj") == "ask"

def test_read_outside_claude_dir_still_asks(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    path = str(Path(FAKE_HOME) / "other" / "settings.json")
    assert run(file_path=path, tool_name="Read") == "ask"

# ============================================================================
# Robustness
# ============================================================================

def test_missing_file_path_denied_for_safety():
    result = main({
        "cwd": ROOT,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {},
    }, environ={"CLAUDE_PROJECT_DIR": ROOT})
    assert json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

# ============================================================================
# More secret / git / location edge cases
# ============================================================================

def test_secret_in_subdir_denied():
    assert run(file_path="/proj/sub/.env") == "deny"

def test_ssh_key_denied():
    assert run(file_path="~/.ssh/id_ed25519") == "deny"

def test_pem_example_is_not_secret():
    assert run(file_path="/proj/a.pem.example") == "allow"

@pytest.mark.parametrize("tool", ["MultiEdit", "NotebookEdit"])
def test_git_dir_other_writes_denied(tool):
    assert run(file_path="/proj/.git/config", tool_name=tool) == "deny"

# ============================================================================
# Glob patterns
# ============================================================================

@pytest.mark.parametrize("file_path", ["/proj/*", "/proj/.e*", "/proj/src/?.py"])
def test_glob_path_in_nonexistent_project_read_allowed(file_path):
    # ROOT ("/proj") doesn't exist on disk: nothing real could be disclosed,
    # so a read is allowed even though expansion can't be verified.
    assert run(file_path=file_path, tool_name="Read") == "allow"

@pytest.mark.parametrize("file_path", ["/proj/*", "/proj/.e*", "/proj/src/?.py"])
def test_glob_path_in_nonexistent_project_write_asks(file_path):
    assert run(file_path=file_path, tool_name="Write") == "ask"

# ============================================================================
# Glob patterns -- real expansion against the filesystem
# ============================================================================

def test_glob_matching_in_project_files_allowed(tmp_path):
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()
    assert run(file_path=str(tmp_path / "*.py"), cwd=str(tmp_path)) == "allow"

def test_glob_expanding_to_secret_file_denied(tmp_path):
    (tmp_path / ".env").touch()
    assert run(file_path=str(tmp_path / ".e*"), cwd=str(tmp_path)) == "deny"

def test_glob_secret_denied_among_benign_matches(tmp_path):
    # A write to a benign file is an ASK in default mode, the secret is a DENY.
    # The verdict is the most severe match, whatever the (arbitrary) order the
    # pattern expands in.
    (tmp_path / "app.yml").touch()
    (tmp_path / "app.key").touch()
    assert run(file_path=str(tmp_path / "app.*"), tool_name="Write", cwd=str(tmp_path)) == "deny"

def test_glob_expanding_into_git_dir_denied_for_write(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").touch()
    assert run(file_path=str(git_dir / "*"), tool_name="Write", cwd=str(tmp_path)) == "deny"

def test_glob_expanding_into_git_dir_read_allowed(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").touch()
    assert run(file_path=str(git_dir / "*"), tool_name="Read", cwd=str(tmp_path)) == "allow"

def test_glob_zero_matches_in_real_dir_falls_through_to_mode_check(tmp_path):
    # No files match, but the directory is real: no evidence of risk, so this
    # isn't gated as an unresolved glob -- ordinary mode-based rules apply.
    assert run(file_path=str(tmp_path / "*.xyz"), cwd=str(tmp_path)) == "allow"  # tool_name="Read"
    assert run(file_path=str(tmp_path / "*.xyz"), tool_name="Write", cwd=str(tmp_path)) == "ask"  # default mode

def test_glob_in_missing_subdirectory_allowed(tmp_path):
    # The subdirectory doesn't exist, but glob.glob() still returns a real,
    # trustworthy empty list -- nothing to disclose, so a read is allowed.
    assert run(file_path=str(tmp_path / "missing" / "*.py"), cwd=str(tmp_path)) == "allow"

@pytest.mark.parametrize("file_path_suffix", ["{a,b}.py", "!(a).py"])
def test_glob_brace_and_extglob_syntax_still_asks(tmp_path, file_path_suffix):
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()
    assert run(file_path=str(tmp_path / file_path_suffix), cwd=str(tmp_path)) == "ask"

# ============================================================================
# Glob patterns -- subdirectories and "**"
# ============================================================================

def test_glob_in_subdirectory_matches_real_files(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.py").touch()
    assert run(file_path=str(sub / "*.py"), cwd=str(tmp_path)) == "allow"

def test_glob_in_subdirectory_expanding_to_secret_denied(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".env").touch()
    assert run(file_path=str(sub / ".e*"), cwd=str(tmp_path)) == "deny"

def test_doublestar_matches_one_level_deep(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.py").touch()
    assert run(file_path=str(tmp_path / "**" / "*.py"), cwd=str(tmp_path)) == "allow"

def test_doublestar_does_not_recurse_into_secret_two_levels_deep(tmp_path):
    # Bash's "**" without globstar acts like a single "*": it doesn't cross
    # more than one extra directory level. A secret two levels down must
    # stay invisible to the expansion (zero real matches, not a false ALLOW
    # via under-matching, and not a DENY based on a file we never "saw").
    deep = tmp_path / "sub1" / "sub2"
    deep.mkdir(parents=True)
    (deep / ".env").touch()
    assert run(file_path=str(tmp_path / "**" / ".e*"), cwd=str(tmp_path)) == "allow"

def test_doublestar_in_missing_subdirectory_allowed(tmp_path):
    assert run(file_path=str(tmp_path / "missing" / "**" / "*.py"), cwd=str(tmp_path)) == "allow"
