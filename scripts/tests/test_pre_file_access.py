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
def test_glob_path_asks(file_path):
    assert run(file_path=file_path) == "ask"
