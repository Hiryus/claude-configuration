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

@pytest.mark.parametrize("cmd", [
    "bash -c 'cat .env'", "sh -c x", "zsh", "dash -c x", "ksh -c x",
    "powershell.exe -c ls", "cmd.exe /c dir", "bash.exe -c x", "pwsh.exe -c x",
])
def test_nested_shells_denied(cmd):
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

# ============================================================================
# Secret access via every shell construct
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "echo $(cat .env)",      # command substitution
    "cat < .env",            # read redirect
    "echo x >> .env",        # append redirect
    "ls; cat .env",          # chained command
    "cat .env | grep x",     # pipe
    "cat foo/.env",          # secret in a subdirectory
    "cat a.txt .env",        # secret is not the first argument
    "cat ~/.ssh/id_rsa",     # ssh private key
])
def test_secret_access_denied(cmd):
    assert run(command=cmd) == "deny"

# ============================================================================
# find dangerous flags
# ============================================================================

@pytest.mark.parametrize("flag", ["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint"])
def test_find_dangerous_flags_ask(flag):
    assert run(command=f"find . {flag} x") == "ask"

@pytest.mark.parametrize("cmd", ["find /etc -name x", "find / -type f", "find .. -name y"])
def test_find_external_root_asks(cmd):
    assert run(command=cmd) == "ask"

def test_find_name_value_not_treated_as_path():
    # `id_rsa` is the value of -name, not a search root, so it must not trip
    # the secret check.
    assert run(command="find . -name id_rsa") == "allow"

# ============================================================================
# git --output / -o
# ============================================================================

def test_git_output_in_project_allowed():
    assert run(command="git diff --output=out.txt") == "allow"

def test_git_output_external_asks():
    assert run(command="git diff --output=/etc/x") == "ask"

def test_git_output_secret_denied():
    assert run(command="git diff --output=.env") == "deny"

def test_git_output_flag_without_value_does_not_crash():
    # BUG: a trailing `-o`/`--output` overruns command.args[idx + 1] and raises
    # IndexError; main() only catches ParseError, so the hook crashes instead of
    # failing closed. It should deny (no value to validate).
    assert run(command="git show -o") == "deny"

# ============================================================================
# uv run python --version
# ============================================================================

def test_uv_run_python_version_allowed():
    assert run(command="uv run python --version") == "allow"

# ============================================================================
# Case-sensitive command matching
# ============================================================================

@pytest.mark.parametrize("cmd", ["PIP install x", "Python evil.py", "GIT push"])
def test_uppercase_denied_commands_still_denied(cmd):
    # BUG: explicit denials match command.base case-sensitively, so on Windows
    # (case-insensitive executables) capitalized variants slip past the hard
    # block and only return `ask`.
    assert run(command=cmd) == "deny"

# ============================================================================
# Security bypasses (currently failing -- documenting holes to close)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "sort .env",            # prints the file
    "cut -d= -f2 .env",     # prints selected fields
    "diff .env /dev/null",  # prints the whole file as a diff
    "jq . .env",            # parses and prints the file
    "uniq .env",            # prints the file
])
def test_readonly_command_secret_disclosure_denied(cmd):
    # BYPASS: the diff/jq/sort/uniq and cut groups return ALLOW without running
    # check_access, so these "read-only" commands leak secret file contents.
    # Only the cat/grep/head/tail/less/more group checks its file references.
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "cat *",        # expands to every file, incl. .env
    "cat .e*",      # expands to .env
    "cat .en?",     # expands to .env
])
def test_glob_not_silently_allowed(cmd):
    # BYPASS: globs are expanded by the shell at runtime; the hook sees the
    # literal pattern, which never matches is_secret. An unexpandable pattern
    # cannot be verified statically and should not be auto-allowed.
    assert run(command=cmd) != "allow"

@pytest.mark.parametrize("cmd", [
    "ls /etc",                  # lists an external dir
    "sort /etc/passwd",         # reads an external file
    "find / -name id_rsa",      # traverses outside the project
])
def test_external_access_via_allowed_command_not_allowed(cmd):
    # BYPASS: ls/sort/find never check in_project on their path arguments.
    assert run(command=cmd) != "allow"

def test_trailing_dot_secret_not_allowed():
    # BYPASS: Windows strips a trailing dot, so `.env.` opens `.env`, but
    # is_secret sees the literal ".env." and misses it.
    assert run(command="cat .env.") != "allow"

