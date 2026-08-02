# pyright: reportMissingImports=false

import json
import pytest
import sys

from pathlib import Path

from pre_shell import main

HOOK = "pre_shell.py"
ROOT = "/proj"

# ============================================================================
# Helpers
# ============================================================================

def run(command:str, tool_name="Bash", cwd=ROOT, description="A meaningful description", mode="default"):
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "permission_mode": mode,
        "tool_input": {
            "command": command,
            "description": description,
        },
    })
    return json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision")

# ============================================================================
# Tool gating
# ============================================================================

def test_non_bash_tool_denied():
    assert run(command="ls", tool_name="Powershell") == "deny"

# ============================================================================
# Description quality
# ============================================================================

@pytest.mark.parametrize("description", ["Run shell command", "run shell command", "  Run shell command  ", ""])
def test_default_description_denied(description):
    assert run(command="ls", description=description) == "deny"

def test_missing_description_denied():
    result = main({
        "cwd": ROOT,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    })
    assert json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

def test_meaningful_description_allowed():
    assert run(command="ls", description="List files in the current directory") == "allow"

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
    "bash -c 'cat .env'",
    "ksh -c x",
    "sh -c x",
    "zsh", "dash -c x",
    "bash.exe -c x",
    "cmd.exe /c dir",
    "powershell.exe -c ls",
    "pwsh.exe -c x",
])
def test_nested_shells_denied(cmd):
    assert run(command=cmd) == "deny"

# ============================================================================
# Secrets / .git via shell
# ============================================================================

def test_cat_secret_denied():
    assert run(command="cat .env") == "deny"

def test_file_secret_denied():
    assert run(command="file .env") == "deny"

def test_file_allowed():
    assert run(command="file foo.txt") == "allow"

def test_file_outside_project_asks():
    assert run(command="file /etc/passwd") == "ask"

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

FAKE_HOME = "/home/fakeuser"

def test_read_claude_dir_tilde_allowed(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(command="cat ~/.claude/settings.json") == "allow"

def test_read_claude_dir_absolute_path_allowed(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    path = Path(FAKE_HOME) / ".claude" / "settings.json"
    assert run(command=f'cat "{path}"') == "allow"

def test_write_claude_dir_asks(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(command="echo x > ~/.claude/settings.json") == "ask"

def test_read_outside_claude_dir_still_asks(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(command="cat ~/other/settings.json") == "ask"

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

def test_git_push_asks():
    assert run(command="git push") == "ask"

@pytest.mark.parametrize("cmd", ["git push --force", "git push -f"])
def test_git_push_force_denied(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "git remote",
    "git remote -v",
    "git remote --verbose",
    "git remote show origin",
    "git remote get-url origin",
])
def test_git_remote_readonly_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "git remote add origin https://x",
    "git remote remove origin",
    "git remote rm origin",
    "git remote set-url origin https://x",
    "git remote rename origin upstream",
    "git remote prune origin",
    "git remote update",
    "git remote set-head origin main",
])
def test_git_remote_write_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", [
    "git remote --flag show prune",
    "git remote --flag=show prune",
    "git remote --verbose prune",
])
def test_git_remote_write_hidden_behind_flag_asks(cmd):
    assert run(command=cmd) == "ask"

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
# grep
# ============================================================================

def test_grep_pattern_not_treated_as_path():
    assert run(command="grep .env foo.txt") == "allow"

def test_grep_file_secret_denied():
    assert run(command="grep foo .env") == "deny"

def test_grep_file_outside_project_asks():
    assert run(command="grep foo /etc/passwd") == "ask"

def test_grep_e_pattern_not_treated_as_path():
    assert run(command="grep -e .env foo.txt") == "allow"

def test_grep_file_value_flag_checked():
    assert run(command="grep -f .env foo.txt") == "deny"

@pytest.mark.parametrize("cmd", ["grep -A 3 foo bar.txt", "grep -m 1 foo bar.txt"])
def test_grep_context_count_value_not_treated_as_path(cmd):
    assert run(command=cmd) == "allow"

# ============================================================================
# test
# ============================================================================

@pytest.mark.parametrize("cmd", ["test -f foo.txt", "test -e bar"])
def test_test_command_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_test_command_secret_denied():
    assert run(command="test -f .env") == "deny"

# ============================================================================
# sed
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "sed -n '100,170p'",
    "sed -n '5p'",
    "sed -n '$p'",
    "sed -n '10,$p'",
    "sed -n '5p;10,20p'",
    "sed --quiet '5p'",
    "sed -n '100,170p' foo.txt",
])
def test_sed_simple_line_print_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_sed_simple_print_secret_file_denied():
    assert run(command="sed -n '100,170p' .env") == "deny"

def test_sed_simple_print_external_file_asks():
    assert run(command="sed -n '100,170p' /etc/passwd") == "ask"

@pytest.mark.parametrize("cmd", [
    "sed 's/foo/bar/' file.txt",         # substitution -- can rewrite content
    "sed -n '1,5w out.txt'",             # write command
    "sed -n '1,5e ls'",                  # execute command
    "sed -i 's/a/b/' file.txt",          # in-place edit flag
    "sed -n '/foo/p'",                   # regex address, not a plain line range
])
def test_sed_non_simple_script_asks(cmd):
    assert run(command=cmd) == "ask"

def test_test_command_external_asks():
    assert run(command="test -e /etc/passwd") == "ask"

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
    # `id_rsa` is the value of -name, not a search root, so it must not trip the secret.
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

# ============================================================================
# .exe suffix stripping (base names ending in e/x, e.g. "node")
# ============================================================================

@pytest.mark.parametrize("cmd", ["node --version", "node.exe --version", "node -v", "node.exe -v"])
def test_node_version_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", ["npm --version", "npm.exe --version", "npm -v", "npm.exe -v"])
def test_npm_version_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", ["npm audit", "npm audit --json", "npm audit --production"])
def test_npm_audit_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", ["npm audit fix", "npm audit --fix", "npm audit fix --force"])
def test_npm_audit_fix_asks(cmd):
    assert run(command=cmd) == "ask"

def test_npm_prune_asks_in_default_mode():
    assert run(command="npm prune") == "ask"

@pytest.mark.parametrize("mode", ["acceptEdits", "auto", "bypassPermissions"])
def test_npm_prune_allowed_in_write_modes(mode):
    assert run(command="npm prune", mode=mode) == "allow"

def test_git_output_flag_without_value_does_not_crash():
    assert run(command="git show -o") == "deny"

# ============================================================================
# uv run python --version
# ============================================================================

def test_uv_run_python_version_allowed():
    assert run(command="uv run python --version") == "allow"

# ============================================================================
# Case-sensitive command matching
# ============================================================================

@pytest.mark.parametrize("cmd", ["PIP install x", "Python evil.py", "GIT push --force"])
def test_uppercase_denied_commands_still_denied(cmd):
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
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "cat *",        # expands to every file, incl. .env
    "cat .e*",      # expands to .env
    "cat .en?",     # expands to .env
])
def test_glob_read_in_nonexistent_project_allowed(cmd):
    # ROOT ("/proj") doesn't exist on disk: there's nothing real for a
    # read to disclose, regardless of what the pattern would expand to.
    assert run(command=cmd) == "allow"

def test_glob_write_in_nonexistent_project_still_asks():
    # Writes stay conservative even when the project doesn't exist: the
    # repo-missing exemption only ever applies to reads.
    assert run(command="echo hi > *.log") == "ask"

@pytest.mark.parametrize("cmd", [
    "ls /etc",                  # lists an external dir
    "sort /etc/passwd",         # reads an external file
    "find / -name id_rsa",      # traverses outside the project
])
def test_external_access_via_allowed_command_not_allowed(cmd):
    assert run(command=cmd) != "allow"

@pytest.mark.skipif(sys.platform != "win32", reason="trailing-dot stripping is a Windows-only filesystem quirk")
def test_trailing_dot_secret_not_allowed():
    # Windows strips a trailing dot, so `.env.` opens `.env`.
    assert run(command="cat .env.") != "allow"

# ============================================================================
# Glob patterns -- real expansion against the filesystem
# ============================================================================

def test_glob_matching_in_project_files_allowed(tmp_path):
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()
    assert run(command="cat *.py", cwd=str(tmp_path)) == "allow"

def test_glob_expanding_to_secret_file_denied(tmp_path):
    (tmp_path / ".env").touch()
    assert run(command="cat .e*", cwd=str(tmp_path)) == "deny"

def test_glob_in_subdirectory_matches_real_files(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.py").touch()
    assert run(command="cat sub/*.py", cwd=str(tmp_path)) == "allow"

def test_glob_in_subdirectory_expanding_to_secret_denied(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".env").touch()
    assert run(command="cat sub/.e*", cwd=str(tmp_path)) == "deny"

def test_doublestar_matches_one_level_deep(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.py").touch()
    assert run(command="cat **/*.py", cwd=str(tmp_path)) == "allow"

def test_doublestar_does_not_recurse_into_secret_two_levels_deep(tmp_path):
    # "**" without globstar acts like a single "*": a secret two levels down
    # must stay invisible to the expansion (zero real matches -> allow,
    # not a DENY based on a file the glob never actually "saw").
    deep = tmp_path / "sub1" / "sub2"
    deep.mkdir(parents=True)
    (deep / ".env").touch()
    assert run(command="cat **/.e*", cwd=str(tmp_path)) == "allow"

def test_glob_zero_matches_in_real_dir_allowed(tmp_path):
    assert run(command="cat *.xyz", cwd=str(tmp_path)) == "allow"

def test_glob_in_missing_subdirectory_allowed(tmp_path):
    # The subdirectory doesn't exist, but glob.glob() still returns a real,
    # trustworthy empty list -- nothing to disclose, so a read is allowed.
    assert run(command="cat missing/*.py", cwd=str(tmp_path)) == "allow"

def test_doublestar_in_missing_subdirectory_allowed(tmp_path):
    assert run(command="cat missing/**/*.py", cwd=str(tmp_path)) == "allow"

def test_glob_brace_syntax_still_asks(tmp_path):
    (tmp_path / "a.py").touch()
    (tmp_path / "b.py").touch()
    assert run(command="cat file{a,b}.py", cwd=str(tmp_path)) == "ask"

def test_glob_extglob_syntax_not_silently_allowed(tmp_path):
    # bash "!(...)" extglob syntax; the leading "!" is also history expansion
    # to a plain shell, so the parser may reject it outright (deny) rather
    # than reach the glob-uncertainty path (ask) -- either is acceptably safe.
    (tmp_path / "a.py").touch()
    assert run(command="cat !(a).py", cwd=str(tmp_path)) != "allow"

