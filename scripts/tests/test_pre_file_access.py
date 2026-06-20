# pyright: reportMissingImports=false

import json
import pytest

from pre_file_access import main

HOOK = "pre_file_access.py"
ROOT = "C:\\proj"

# ============================================================================
# Helpers
# ============================================================================

def run(file_path:str, tool_name="Read", cwd=ROOT):
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "file_path": file_path,
        },
    })
    return json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision")

# ============================================================================
# Secrets
# ============================================================================

@pytest.mark.parametrize("file_path", ["C:\\proj\\.env", "C:\\proj\\config\\.env.local", "C:\\proj\\server.pem", "C:\\proj\\id_rsa"])
def test_secret_files_denied(file_path):
    assert run(file_path=file_path) == "deny"

def test_env_example_is_not_secret():
    assert run(file_path="C:\\proj\\.env.example") == "allow"

# ============================================================================
# Git files
# ============================================================================

@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_git_dir_writes_denied(tool):
    assert run(file_path="C:\\proj\\.git\\config", tool_name=tool) == "deny"

def test_git_dir_read_allowed():
    assert run(file_path="C:\\proj\\.git\\config", tool_name="Read") == "allow"

# ============================================================================
# Project location
# ============================================================================

def test_in_project_allowed():
    assert run(file_path="C:\\proj\\src\\main.py") == "allow"

def test_outside_project_asks():
    assert run(file_path="C:\\other\file.txt") == "ask"

def test_tmp_outside_project_allowed():
    assert run(file_path="/tmp/scratch.txt") == "allow"

# ============================================================================
# Robustness
# ============================================================================

def test_missing_file_path_denied_for_safety():
    result = main({
        "cwd": ROOT,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {},
    })
    assert json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

# ============================================================================
# More secret / git / location edge cases
# ============================================================================

def test_secret_in_subdir_denied():
    assert run(file_path="C:\\proj\\sub\\.env") == "deny"

def test_ssh_key_denied():
    assert run(file_path="~\\.ssh\\id_ed25519") == "deny"

def test_pem_example_is_not_secret():
    assert run(file_path="C:\\proj\\a.pem.example") == "allow"

@pytest.mark.parametrize("tool", ["MultiEdit", "NotebookEdit"])
def test_git_dir_other_writes_denied(tool):
    assert run(file_path="C:\\proj\\.git\\config", tool_name=tool) == "deny"

# ============================================================================
# Glob patterns
# ============================================================================

@pytest.mark.parametrize("file_path", ["C:\\proj\\*", "C:\\proj\\.e*", "C:\\proj\\src\\?.py"])
def test_glob_path_in_nonexistent_project_read_allowed(file_path):
    # ROOT ("C:\proj") doesn't exist on disk: nothing real could be disclosed,
    # so a read is allowed even though expansion can't be verified.
    assert run(file_path=file_path, tool_name="Read") == "allow"

@pytest.mark.parametrize("file_path", ["C:\\proj\\*", "C:\\proj\\.e*", "C:\\proj\\src\\?.py"])
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
