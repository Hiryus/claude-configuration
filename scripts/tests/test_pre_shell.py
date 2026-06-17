# pyright: reportMissingImports=false

import json
import pytest

from pre_shell import main

HOOK = "pre_shell.py"
ROOT = r"C:\proj"

# ============================================================================
# Helpers
# ============================================================================

def run(command:str, tool_name="Bash", cwd=ROOT):
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "command": command,
        },
    })
    return json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision")

# ============================================================================
# Tool gating
# ============================================================================

def test_non_bash_tool_denied():
    assert run(command="ls", tool_name="Powershell") == "deny"

# ============================================================================
# Read-only allow list
# ============================================================================

@pytest.mark.parametrize("cmd", ["ls", "pwd", "wc -l foo", "echo hi", "sort x"])
def test_readonly_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_assignment_only_allowed():
    assert run(command="FOO=bar") == "allow"

# ============================================================================
# Explicit denials
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "git push",
    "pip install x",
    "python script.py",
    "python -m http.server",
    "mypy .",
    "powershell -c ls",
    "cmd /c dir",
    "uv run mypy",
    "git -C /x status",
    "git -c foo=bar status",
    "cd /somewhere",
])
def test_denied_commands(cmd):
    assert run(command=cmd) == "deny"

# ============================================================================
# Secrets / .git via shell
# ============================================================================

def test_cat_secret_denied():
    assert run(command="cat .env") == "deny"

def test_redirect_into_secret_denied():
    assert run(command="echo x > .env") == "deny"

# ============================================================================
# File-access
# ============================================================================

def test_read_outside_project_asks():
    assert run(command="cat /etc/passwd") == "ask"

def test_write_outside_project_asks():
    assert run(command="echo x > /other/out.txt") == "ask"

def test_dev_null_redirect_allowed():
    assert run(command="echo x > /dev/null") == "allow"

# ============================================================================
# git
# ============================================================================

def test_redirect_into_git_denied():
    assert run(command="echo x > .git/config") == "deny"

@pytest.mark.parametrize("cmd", ["git status", "git diff", "git log", "git show"])
def test_git_readonly_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_git_unknown_subcommand_asks():
    assert run(command="git clone https://x") == "ask"

# ============================================================================
# uv
# ============================================================================

@pytest.mark.parametrize("cmd", ["uv sync", "uv run pytest", "uv run ruff check", "uv --version"])
def test_uv_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_uv_unknown_tool_asks():
    assert run(command="uv run black .") == "ask"

# ============================================================================
# find
# ============================================================================

def test_find_plain_allowed():
    assert run(command="find . -name x") == "allow"

def test_find_exec_asks():
    assert run(command="find . -exec rm {} ;") == "ask"

# ============================================================================
# Dynamic / unknown / unparseable commands
# ============================================================================

def test_dynamic_command_asks():
    assert run(command="cat $(echo .env)") == "ask"

def test_unknown_command_asks():
    assert run(command="frobnicate --hard") == "ask"

def test_unparseable_denied():
    assert run(command="echo 'unterminated") == "deny"
