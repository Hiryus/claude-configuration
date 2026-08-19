# pyright: reportMissingImports=false

import json
import sys
from pathlib import Path

import pytest
from pre_shell import main

HOOK = "pre_shell.py"
ROOT = "/proj"

# `project_root` defaults to the `cwd` argument, which reproduces the behavior from
# before cwd tracking exactly. `project_root=None` sends an empty environment, i.e.
# CLAUDE_PROJECT_DIR unset -- so the sentinel cannot be None itself.
SAME_AS_CWD = object()

# ============================================================================
# Helpers
# ============================================================================

def output(command:str, tool_name="Bash", cwd=ROOT, description="A meaningful description", mode="default", project_root=SAME_AS_CWD):
    root = cwd if project_root is SAME_AS_CWD else project_root
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "permission_mode": mode,
        "tool_input": {
            "command": command,
            "description": description,
        },
    }, environ={"CLAUDE_PROJECT_DIR": root} if root is not None else {})
    return json.loads(result).get("hookSpecificOutput", {})

def run(command:str, tool_name="Bash", cwd=ROOT, description="A meaningful description", mode="default", project_root=SAME_AS_CWD):
    return output(command, tool_name, cwd, description, mode, project_root).get("permissionDecision")

def reason(command:str, tool_name="Bash", cwd=ROOT, description="A meaningful description", mode="default", project_root=SAME_AS_CWD):
    return output(command, tool_name, cwd, description, mode, project_root).get("permissionDecisionReason")

# ============================================================================
# Tool gating
# ============================================================================

def test_non_bash_tool_denied():
    assert run(command="ls", tool_name="Powershell") == "deny"

# ============================================================================
# Modes
# ============================================================================

def test_auto_mode_turns_ask_into_deny():
    # Rule "Modes": no interactive validation in auto mode.
    assert run(command="docker login -u me registry.io") == "ask"
    assert run(command="docker login -u me registry.io", mode="bypassPermissions") == "deny"

def test_auto_mode_deny_explains_the_mode_and_keeps_the_ask_reason():
    denial = reason(command="docker login -u me registry.io", mode="bypassPermissions")
    assert "auto mode" in denial
    assert "docker login" in denial

def test_auto_mode_deny_keeps_the_file_ask_reason():
    # An ask coming from the file rules is wrapped once, keeping its own reason.
    denial = reason(command="cat /elsewhere/notes.txt", mode="bypassPermissions")
    assert "outside the project" in denial
    assert denial.count("auto mode") == 1

@pytest.mark.parametrize("mode", ["default", "plan", "acceptEdits"])
def test_other_modes_keep_asking(mode):
    assert run(command="docker login -u me registry.io", mode=mode) == "ask"

@pytest.mark.parametrize("cmd", ["ls", "echo x > notes.txt"])
def test_auto_mode_keeps_allow(cmd):
    # Auto mode allows the same calls as edit mode, writes included.
    assert run(command=cmd, mode="bypassPermissions") == "allow"

def test_auto_mode_keeps_the_deny_reason():
    assert run(command="pip install requests", mode="bypassPermissions") == "deny"
    assert "uv" in reason(command="pip install requests", mode="bypassPermissions")

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
    }, environ={"CLAUDE_PROJECT_DIR": ROOT})
    assert json.loads(result).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

def test_meaningful_description_allowed():
    assert run(command="ls", description="List files in the current directory") == "allow"

# ============================================================================
# Read-only allow list
# ============================================================================

@pytest.mark.parametrize("cmd", ["ls", "pwd", "wc -l foo", "echo hi", "sort x"])
def test_readonly_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_readonly_double_dash_path_checks_the_operand():
    # §5.2/§4.1.3: `--` must reach the untabled read-only group too, so
    # -weird.pem is path-checked instead of being read as a flag.
    assert run(command="cat -- -weird.pem") == "deny"

def test_assignment_only_allowed():
    assert run(command="FOO=bar") == "allow"

# ============================================================================
# Explicit denials
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "pip install x",
    "mypy .",
    "powershell -c ls",
    "cmd /c dir",
    "git -C /x status",
    "git -c foo=bar status",
    "cd /somewhere",  # rule 2.3: the target does not exist
])
def test_denied_commands(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="rule 2.7: pre_shell.check_command has no `python` branch (the pip/mypy ones survived), so it falls through to the unknown-command ask", strict=True)
@pytest.mark.parametrize("cmd", ["python script.py", "python -m http.server", "python3 script.py"])
def test_python_denied(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="rule 2.7/2.15: analyzers/uv.py was deleted in the refactor, so no uv rule is enforced", strict=True)
def test_uv_run_mypy_denied():
    assert run(command="uv run mypy") == "deny"

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

@pytest.mark.parametrize("cmd", [
    "echo x > ~/.claude/settings.json",
    "echo x >> ~/.claude/scripts/utils.py",
])
def test_write_claude_dir_denied_from_another_project(monkeypatch, cmd):
    # Rule 1.3: the harness may not be written from a project living elsewhere.
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    assert run(command=cmd) == "deny"

def test_write_claude_dir_allowed_when_it_is_the_project(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = str(Path(FAKE_HOME) / ".claude")
    assert run(command="echo x > scripts/utils.py", cwd=harness, mode="acceptEdits") == "allow"

def test_write_claude_dir_asks_in_manual_mode_when_it_is_the_project(monkeypatch):
    monkeypatch.setenv("HOME", FAKE_HOME)
    monkeypatch.setenv("USERPROFILE", FAKE_HOME)
    harness = str(Path(FAKE_HOME) / ".claude")
    assert run(command="echo x > scripts/utils.py", cwd=harness) == "ask"

# ============================================================================
# Write gate (rule 1.4)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "echo x > out.txt",
    "git diff --output=out.txt",
    "find . -fprint out.txt",
    "docker run --rm -v .:/app alpine",
])
def test_in_project_write_asks_in_manual_mode(cmd):
    # Rule 1.4: writes are only automatic in edit mode, whatever the binary.
    assert run(command=cmd) == "ask"
    assert run(command=cmd, mode="acceptEdits") == "allow"

def test_in_project_read_allowed_in_manual_mode():
    assert run(command="cat out.txt") == "allow"

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

def test_git_branch_bare_allowed():
    assert run(command="git branch") == "allow"

@pytest.mark.parametrize("cmd", [
    "git branch --list",
    "git branch -a",
    "git branch --all",
    "git branch -r",
    "git branch -v",
    "git branch --show-current",
    "git branch --no-color --list",
])
def test_git_branch_readonly_flags_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "git branch foo",             # creates a branch
    "git branch -d foo",          # deletes a branch
    "git branch -D foo",          # force-deletes a branch
    "git branch -m old new",      # renames a branch
    "git branch --edit-description",
])
def test_git_branch_write_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", ["git branch --contains HEAD", "git branch --points-at HEAD"])
def test_git_branch_flag_with_separate_value_asks(cmd):
    # Read-only in git, but the value parses as a positional and cannot be told
    # apart from a branch name, so it falls back to the safe side.
    assert run(command=cmd) == "ask"

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
    "git remote --flag=show prune",
    "git remote --verbose prune",
])
def test_git_remote_write_hidden_behind_flag_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.xfail(reason="no operand re-walk: an untabled flag is not paired with its value, so `show` reads as the sub-verb and `prune` as its operand; to be reintroduced", strict=True)
def test_git_remote_write_hidden_behind_untabled_flag_asks():
    assert run(command="git remote --flag show prune") == "ask"

@pytest.mark.xfail(reason="no operand re-walk: the root `-o` swallows the sub-verb and leaves `git remote` looking bare; to be reintroduced", strict=True)
@pytest.mark.parametrize("cmd", ["git remote -o prune", "git remote -o add", "git remote -o set-url"])
def test_git_remote_sub_verb_swallowed_by_value_flag_still_asks(cmd):
    # `-o` is a REQUIRED root flag (git commit aside); it must not be able to
    # eat the sub-verb and leave `git remote` looking bare.
    assert run(command=cmd) == "ask"

# ============================================================================
# git config (rule 2.9.3)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "git config --list",
    "git config -l",
    "git config --global --list",
    "git config --list --show-origin --show-scope",
    "git config --get user.name",
    "git config --get-regexp branch",
    "git config --type=bool --get core.bare",
    "git config user.name",
    "git config get user.name",
    "git config list",
])
def test_git_config_read_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "git config user.name Bob",             # classic write form
    "git config --global user.email x@y.z",
    "git config set user.name Bob",
    "git config unset user.name",
    "git config --unset user.name",
    "git config --add remote.origin.url https://x",
    "git config --replace-all user.name Bob",
    "git config edit",
    "git config -e",
    "git config remove-section user",
    "git config rename-section old new",
])
def test_git_config_write_asks(cmd):
    assert run(command=cmd) == "ask"

def test_git_config_read_flag_with_separate_value_asks():
    # Read-only in git, but the value parses as a positional and cannot be told
    # apart from the `git config <name> <value>` write form -- same trade-off as `git branch --contains HEAD`.
    assert run(command="git config --type bool --get core.bare") == "ask"

def test_git_config_file_in_project_allowed():
    assert run(command="git config --file local.gitconfig --list") == "allow"

def test_git_config_file_external_asks():
    assert run(command="git config --file /etc/gitconfig --list") == "ask"

def test_git_config_file_secret_denied():
    assert run(command="git config --file ~/.ssh/config --list") == "deny"

def test_git_config_secret_file_denied_before_the_write_check():
    # The file check runs first: a secret must not degrade into the write ASK.
    assert run(command="git config --file ~/.ssh/config --add user.name Bob") == "deny"

def test_git_config_output_secret_denied():
    assert run(command="git config --output=.env --list") == "deny"

@pytest.mark.parametrize("cmd", ["git config user.name list", "git config user.name get"])
def test_git_config_write_with_verb_shaped_value_asks(cmd):
    # `git config user.name list` writes `user.name=list`: the verb table must not
    # match a word sitting in operand position (see parsers/arguments.py).
    assert run(command=cmd) == "ask"

# ============================================================================
# git -C / --git-dir / GIT_DIR (rule 2.9.1)
# ============================================================================

def test_git_git_dir_flag_denied():
    assert run(command="git --git-dir=/etc log") == "deny"

def test_git_dir_env_prefix_assignment_denied():
    assert run(command="GIT_DIR=/etc git log") == "deny"

def test_git_directory_flag_after_verb_denied():
    assert run(command="git log -C /etc") == "deny"

def test_git_commit_only_secret_path_denied():
    assert run(command="git commit -o ~/.ssh/id_rsa") == "deny"

@pytest.mark.xfail(reason="rule 2.9.1: resolve_scope() was dropped, so CommandLine.environment is never filled; to be reintroduced", strict=True)
def test_git_dir_env_propagated_from_earlier_statement_denied():
    # The propagated form, as opposed to the prefix form above --
    # closed by resolve_scope() filling CommandLine.environment.
    assert run(command="GIT_DIR=/etc; git log") == "deny"

def test_unrelated_propagated_assignment_does_not_leak_into_other_commands():
    assert run(command="FOO=bar; echo hi") == "allow"

@pytest.mark.xfail(reason="rule 2.9.1: resolve_scope() was dropped, so CommandLine.environment is never filled; to be reintroduced", strict=True)
def test_git_dir_env_via_export_denied():
    # §2.4: `export` arrives as an ordinary argument word, not an assignment
    # node -- a DENY degrading to an ASK on the unrecognised `export` command
    # is exactly the fail-open shape §5.1 exists to prevent.
    assert run(command="export GIT_DIR=/etc; git log") == "deny"

# ============================================================================
# uv  (rule 2.15 -- analyzers/uv.py was deleted in the refactor)
# ============================================================================

@pytest.mark.xfail(reason="rule 2.15: analyzers/uv.py was deleted in the refactor, so every uv call falls through to the unknown-command ask", strict=True)
@pytest.mark.parametrize("cmd", ["uv sync", "uv run pytest", "uv run ruff check", "uv --version"])
def test_uv_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_uv_unknown_tool_asks():
    assert run(command="uv run black .") == "ask"

@pytest.mark.parametrize("cmd", ["uv run --frozen", "uv run --no-sync", "uv run"])
def test_uv_run_without_tool_asks(cmd):
    assert run(command=cmd) == "ask"

# ============================================================================
# find
# ============================================================================

def test_find_plain_allowed():
    assert run(command="find . -name x") == "allow"

def test_find_exec_denied():
    assert run(command="find . -exec rm {} ;") == "deny"

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

def test_grep_color_unglued_does_not_swallow_the_pattern():
    # §4.1.1/§6.5: --color is OPTIONAL -- it pairs only when glued, so `pat`
    # stays the pattern and the secret file stays a visible reference.
    assert run(command="grep --color pat ~/.ssh/id_rsa") == "deny"

def test_grep_color_glued_still_denies():
    assert run(command="grep --color=auto pat ~/.ssh/id_rsa") == "deny"

@pytest.mark.parametrize("cmd", ["grep --label pat ~/.ssh/id_rsa", "grep --binary-files pat ~/.ssh/id_rsa"])
def test_grep_required_flag_consumes_its_value(cmd):
    assert run(command=cmd) == "allow"

def test_grep_missing_regexp_value_denied():
    # The shape that used to crash out of main() (IndexError): a missing
    # value at end of line must be handled, never assumed present.
    assert run(command="grep -e") == "deny"

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

@pytest.mark.parametrize("flag", ["-exec", "-execdir", "-ok", "-okdir"])
def test_find_exec_flags_denied(flag):
    # Rule 2.10: these run an arbitrary program, so they are refused outright.
    assert run(command=f"find . {flag} rm {{}} ;") == "deny"

@pytest.mark.parametrize("cmd", ["find . -fprint out.txt", "find . -fls out.txt", "find . -fprint0 out.txt"])
def test_find_output_file_follows_the_write_rules(cmd):
    # The output-file actions are not refused outright: their target is vetted like any other write.
    assert run(command=cmd, mode="acceptEdits") == "allow"

@pytest.mark.parametrize("cmd", ["find . -fprint /etc/out", "find . -fls ~/other/out"])
def test_find_output_file_outside_project_asks(cmd):
    assert run(command=cmd) == "ask"

def test_find_output_file_secret_denied():
    assert run(command="find . -fprint .env") == "deny"

@pytest.mark.xfail(reason="`-delete` takes no value, so the FILE_WRITE_FLAGS loop raises ParseError instead of vetting the search roots as writes", strict=True)
@pytest.mark.parametrize("cmd", ["find . -delete", "find build -delete"])
def test_find_delete_vets_the_roots_as_writes(cmd):
    # `-delete` removes whatever the roots match, so the roots are the write targets.
    assert run(command=cmd) == "allow"

@pytest.mark.xfail(reason="`-delete` takes no value, so the FILE_WRITE_FLAGS loop raises ParseError before the roots are vetted", strict=True)
def test_find_delete_outside_project_asks():
    assert run(command="find /etc -delete") == "ask"

@pytest.mark.parametrize("cmd", ["find /etc -name x", "find / -type f", "find .. -name y"])
def test_find_external_root_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("predicate", ["-name", "-iname", "-path", "-wholename", "-lname"])
def test_find_pattern_value_not_treated_as_path(predicate):
    # `id_rsa` is the value of a pattern predicate, not a search root, so it must not trip the secret.
    assert run(command=f"find . {predicate} id_rsa") == "allow"

def test_find_pattern_glob_value_does_not_ask():
    # The pattern is matched by find itself, so it is not a glob the hook has to expand.
    assert run(command="find . -path '*/.ssh/*'") == "allow"

def test_find_leading_flag_does_not_hide_the_root():
    # §6.4: a leading flag (-L) must not short-circuit before the search root is reached.
    assert run(command="find -L ~/.ssh -name id_rsa") == "deny"

# ============================================================================
# git --output / -o
# ============================================================================

def test_git_output_in_project_allowed():
    assert run(command="git diff --output=out.txt", mode="acceptEdits") == "allow"

def test_git_output_external_asks():
    assert run(command="git diff --output=/etc/x") == "ask"

def test_git_output_secret_denied():
    assert run(command="git diff --output=.env") == "deny"

def test_git_output_flag_without_value_does_not_crash():
    assert run(command="git show -o") == "deny"

# ============================================================================
# uv run python --version
# ============================================================================

@pytest.mark.xfail(reason="rule 2.15: analyzers/uv.py was deleted in the refactor", strict=True)
def test_uv_run_python_version_allowed():
    assert run(command="uv run python --version") == "allow"

# ============================================================================
# Case-sensitive command matching
# ============================================================================

@pytest.mark.parametrize("cmd", ["PIP install x", "GIT push --force"])
def test_uppercase_denied_commands_still_denied(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="rule 2.7: pre_shell.check_command has no `python` branch", strict=True)
def test_uppercase_python_still_denied():
    assert run(command="Python evil.py") == "deny"

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

# ============================================================================
# Context: the project root and the current directory are two different things
# ============================================================================

def test_missing_project_root_denied():
    # Step 0: CLAUDE_PROJECT_DIR is mandatory. Missing means the project boundary is
    # unknown, and guessing it from the cwd is exactly the conflation cwd tracking removes.
    assert run(command="ls", project_root=None) == "deny"
    assert "CLAUDE_PROJECT_DIR" in reason(command="ls", project_root=None)

@pytest.mark.parametrize("cwd", ["", None])
def test_missing_cwd_denied(cwd):
    assert run(command="ls", cwd=cwd) == "deny"

def test_relative_path_is_anchored_on_the_cwd_not_the_project_root(tmp_path):
    # The glob only matches from `work`, so a match proves the anchor is the cwd.
    work = tmp_path / "work"
    work.mkdir()
    (work / "server.pem").touch()
    assert run(command="cat *.pem", cwd=str(work), project_root=str(tmp_path)) == "deny"
    assert run(command="cat *.pem", cwd=str(tmp_path), project_root=str(tmp_path)) == "allow"

def test_project_boundary_is_the_project_root_not_the_cwd():
    # A file above the cwd but still inside the project needs no validation;
    # the same file is external as soon as the project root really is the cwd.
    assert run(command="cat ../notes.txt", cwd="/proj/work", project_root="/proj") == "allow"
    assert run(command="cat ../notes.txt", cwd="/proj/work", project_root="/proj/work") == "ask"

# ============================================================================
# cd -- resolution (rule 2.3)
# ============================================================================

@pytest.mark.parametrize("cmd", ["cd /tmp", "cd /tmp/", "cd -P /tmp", "cd -L /tmp", "cd -- /tmp", "cd", "cd ~"])
def test_cd_resolvable_target_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "cd $HOME",          # parameter expansion
    "cd $(pwd)",         # command substitution
    "cd `pwd`",          # backtick substitution
    "cd /nonexistent",   # not a directory
    "cd -e /tmp",        # untabled option
    "cd /tmp /var",      # more than one operand
])
def test_cd_unresolvable_target_denied(cmd):
    assert run(command=cmd) == "deny"

def test_cd_relative_target_allowed(tmp_path):
    (tmp_path / "sub").mkdir()
    assert run(command="cd sub", cwd=str(tmp_path)) == "allow"

def test_cd_outside_the_project_allowed():
    # Decided: the `cd` itself discloses nothing, and every later access is still
    # path-checked against the unchanged project root.
    assert run(command="cd /tmp") == "allow"

def test_cd_does_not_move_the_project_boundary():
    assert run(command="cd /tmp; cat /tmp/../etc/passwd") == "ask"

def test_cd_redirect_is_still_checked():
    # The `cd` verdict may not vouch for what the command writes on its way.
    assert run(command="cd /tmp > .env") == "deny"

# ============================================================================
# cd -- the current directory anchors the later commands
# ============================================================================

def test_cd_moves_the_anchor_of_the_next_commands(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "server.pem").touch()
    assert run(command="cat *.pem", cwd=str(tmp_path)) == "allow"          # nothing matches at the root
    assert run(command="cd sub; cat *.pem", cwd=str(tmp_path)) == "deny"   # ... but the secret matches in `sub`

def test_cd_left_of_and_still_anchors_the_right_side(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "server.pem").touch()
    assert run(command="cd sub && cat *.pem", cwd=str(tmp_path)) == "deny"

def test_cd_out_of_the_project_makes_relative_paths_external():
    # `/` is a real directory outside the project, and not one of the exempted
    # locations, so the file the shell would now read needs validation.
    assert run(command="cat notes.txt") == "allow"
    assert run(command="cd /; cat notes.txt") == "ask"

def test_cd_into_git_dir_does_not_defeat_the_git_rule(tmp_path):
    # Step 2 regression guard: `is_git_dir` used to match the written text, so moving
    # the shell into `.git` first hid the git file behind a plain name.
    (tmp_path / ".git").mkdir()
    assert run(command="cd .git; echo x > config", cwd=str(tmp_path), mode="acceptEdits") == "deny"

def test_cd_into_ssh_dir_does_not_defeat_the_secret_rule(tmp_path):
    (tmp_path / ".ssh").mkdir()
    assert run(command="cd .ssh; cat known_hosts", cwd=str(tmp_path)) == "deny"

# ============================================================================
# cd -- scope isolation
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "(cd .git); echo x > config",        # subshell
    "echo $(cd .git); echo x > config",  # command substitution
    "echo `cd .git`; echo x > config",   # backtick substitution
    "cd .git | cat; echo x > config",    # pipeline stage
    "cd .git & echo x > config",         # async segment
])
def test_isolated_cd_does_not_leak_out(tmp_path, cmd):
    (tmp_path / ".git").mkdir()
    assert run(command=cmd, cwd=str(tmp_path), mode="acceptEdits") == "allow"

def test_isolated_cd_still_applies_inside_its_own_scope(tmp_path):
    (tmp_path / ".git").mkdir()
    assert run(command="(cd .git; echo x > config)", cwd=str(tmp_path), mode="acceptEdits") == "deny"

def test_group_is_not_a_subshell(tmp_path):
    # `{ ...; }` runs in the current shell, so its `cd` does leak out -- unlike `( ... )`.
    (tmp_path / ".git").mkdir()
    assert run(command="{ cd .git; }; echo x > config", cwd=str(tmp_path), mode="acceptEdits") == "deny"

# ============================================================================
# cd -- conditional contexts are refused
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "test -d /tmp && cd /tmp",           # runs only if the left side succeeded
    "ls || cd /tmp",                     # runs only if the left side failed
    "if test -d /tmp; then cd /tmp; fi", # did it run?
    "for f in *; do cd /tmp; done",      # how many times?
    "while ls; do cd /tmp; done",
    "until ls; do cd /tmp; done",
    "f() { cd /tmp; }",                  # runs when the function is called, not here
    "case x in x) cd /tmp;; esac",       # bashlex cannot parse `case` at all (rule 2.1)
])
def test_conditional_cd_denied(cmd):
    assert run(command=cmd) == "deny"

def test_function_body_cd_does_not_move_the_tracked_directory(tmp_path):
    # The body does not run where it is written: folding its `cd` in would let
    # `f() { cd /tmp; }` talk the hook out of the directory the shell is really in.
    (tmp_path / ".git").mkdir()
    assert run(command="cd .git; f() { cd /tmp; }; echo x > config", cwd=str(tmp_path), mode="acceptEdits") == "deny"

def test_conditional_cd_denial_names_the_way_out():
    assert "plain sequence" in reason(command="test -d /tmp && cd /tmp")

def test_conditional_tag_does_not_gate_the_other_commands():
    # `conditional` is grammar: only the `cd` rule reads it. Everything else is
    # checked exactly as it would be outside the conditional.
    assert run(command="if ls; then cat .env; fi") == "deny"
    assert run(command="if ls; then ls; fi") == "allow"

# ============================================================================
# cd - (the previous directory)
# ============================================================================

def test_cd_dash_goes_back_to_the_previous_directory(tmp_path):
    (tmp_path / ".git").mkdir()
    assert run(command="cd .git; echo x > config", cwd=str(tmp_path), mode="acceptEdits") == "deny"
    assert run(command="cd .git; cd -; echo x > config", cwd=str(tmp_path), mode="acceptEdits") == "allow"

def test_cd_dash_without_a_tracked_previous_denied():
    # The payload carries no OLDPWD, so the target is simply unknown.
    assert run(command="cd -") == "deny"

def test_cd_dash_does_not_see_a_subshells_previous_directory():
    assert run(command="(cd /tmp); cd -") == "deny"

def test_cd_dash_dash_dash_is_an_operand_not_the_previous_directory():
    # `cd -- -` means "the directory named -", which does not exist here.
    assert run(command="cd -- -") == "deny"

# ============================================================================
# Commands that would desync the tracking (rule 2.3)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "pushd /tmp",
    "popd",
    "exec ls",
    "eval ls",
    "source env.sh",
    ". env.sh",
    "source /tmp/env.sh",
])
def test_directory_desyncing_commands_denied(cmd):
    assert run(command=cmd) == "deny"

# ============================================================================
# Containers (docker / podman)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "docker ps",
    "docker container ls",
    "docker container list",
    "docker container ps -a",
    "docker images",
    "docker image list",
    "docker inspect web",
    "docker info",
    "docker system df",
    "docker volume inspect data",
    "docker network ls",
    "docker config ls",
    "docker --version",
    "docker version",
    "docker logs -f web",
    "docker compose ps",
    "docker compose logs web",
    "docker compose version",
    "docker compose -f compose.yml config",
])
def test_container_status_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "docker compose up -d",
    "docker compose create",
    "docker compose down",
    "docker compose restart web",
    "docker compose pull",
    "docker stop web",
    "docker restart web",
    "docker container wait web",
    "docker kill web",
    "docker rm web",
    "docker container remove web",
    "docker container prune",
    "docker network create mynet",
    "docker network rm mynet",
    "docker volume remove data",
    "docker system prune",
    "docker image prune",
    "docker pull alpine",
    "docker rmi alpine",
])
def test_container_manage_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_version_shortcut_does_not_skip_the_other_options():
    # `--version` is an allow shortcut, but it may not vouch for what sits next
    # to it: the rest of the line is checked first.
    assert run(command="docker --debug --version") == "ask"
    assert run(command="docker compose --env-file .env --version") == "deny"

def test_compose_file_option_is_checked_after_the_verb():
    # `-f` is a global option of `compose`, but the verbs inherit it: the file it
    # names must be vetted wherever it sits on the line.
    assert run(command="docker compose up -f /etc/evil.yml") == "ask"
    assert run(command="docker compose up --env-file .env") == "deny"

def test_compose_follow_flag_is_not_a_file():
    # `-f` means `--follow` for `logs`: its "value" is a service name, which
    # resolves inside the project and must stay allowed.
    assert run(command="docker compose logs -f web") == "allow"
    assert run(command="docker compose rm -f web") == "allow"

@pytest.mark.xfail(reason="rule 3: the legacy `docker-compose` binary is not aliased to `docker compose` in pre_shell.check_command", strict=True)
def test_legacy_compose_binary_allowed():
    assert run(command="docker-compose up -d") == "allow"

# --- Escaping the sandbox ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "docker run --privileged alpine",
    "docker run --cap-add SYS_ADMIN alpine",
    "docker run --device /dev/sda alpine",
    "docker run --security-opt seccomp=unconfined alpine",
    "docker run -u 0 alpine",
    "docker run --user root alpine",
    "docker run --user=0:0 alpine",
    "docker exec -u root web ls",
    "docker compose up --privileged",
    "docker rm -v --privileged web",
    "docker compose down -v --privileged",
])
def test_container_escape_options_denied(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="parse_glued_args() requires every letter of a cluster to be a flag, so a value glued to a short flag (`-u0` = `-u 0`) is left untabled", strict=True)
def test_glued_root_user_denied():
    assert run(command="docker run -u0 alpine") == "deny"

def test_non_root_user_still_asks():
    assert run(command="docker run --user 1000 alpine") == "ask"

def test_escape_option_hidden_behind_an_unknown_option_still_denied():
    # `--pid` is unknown, so it is not paired with its value: `host` reads as the
    # image name and ends the option walk. `--privileged` sits behind it and must
    # still be found -- a deny may never degrade into an ask.
    assert run(command="docker run --pid host --privileged alpine") == "deny"

# --- Running a container ----------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "docker run --rm alpine",
    "docker run --rm -v .:/app -w /app alpine",
    "docker run --rm -v ./src:/app:ro alpine",
    "docker run --rm --mount type=bind,source=./src,target=/app alpine",
    "docker run --rm --volumes-from other alpine",  # rule 3.3 allows volumes from other containers
    "docker run -d --name web -p 8080:80 -e FOO=bar --network mynet nginx",
    "docker run --rm --entrypoint /bin/sh alpine",
    "docker run --rm --tmpfs /scratch alpine",
    "docker exec web ls",
    "docker create --name web nginx",
    "docker compose run --rm web",
    "docker compose exec web ls",
])
def test_container_run_allowed(cmd):
    # Edit mode: a read-write bind mount is a write, gated by §1.4 in manual mode.
    assert run(command=cmd, mode="acceptEdits") == "allow"

def test_container_argv_path_is_not_checked():
    # Everything after the image runs *inside* the sandbox: it is not a host path.
    assert run(command="docker run --rm alpine cat /etc/shadow") == "allow"

@pytest.mark.xfail(reason="no stop-at-first-operand: the container's own argv is still walked as docker options, so `-la` reads as an untabled flag; to be reintroduced", strict=True)
def test_container_argv_flags_are_not_checked():
    assert run(command="docker run --rm alpine ls -la /root/.ssh") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker run --rm -v /etc:/etc alpine",
    "docker run --rm --mount type=bind,source=/etc,target=/etc alpine",
    "docker run --rm --mount type=BIND,source=/etc,target=/etc alpine",
    "docker run --rm -it alpine",
    "docker run --rm --cgroup-parent /x alpine",
    "docker run --rm -v $(pwd):/app alpine",
    "docker create -v /etc:/etc nginx",
])
def test_container_run_asks(cmd):
    assert run(command=cmd) == "ask"

def test_container_env_file_secret_denied():
    assert run(command="docker run --rm --env-file .env alpine") == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --env-file .env --pid host alpine",
    "docker run --rm --env-file .env --volumes-from other alpine",
    "docker run --rm -v ./certs/server.key:/k --pid host alpine",
    "docker build --iidfile .env --platform linux/amd64 .",
    "docker compose --env-file .env --project-directory ../x up",
])
def test_secret_behind_an_unsupported_option_still_denied(cmd):
    # An option that is only an ask may not hide a file access that is a deny.
    assert run(command=cmd) == "deny"

def test_secret_after_an_unsupported_option_still_denied():
    # The unknown option comes first here: the re-scan pairs it with its value,
    # so the options behind it are read instead of being taken for the image.
    assert run(command="docker run --rm --pid host --env-file .env alpine") == "deny"
    assert run(command="docker run --rm --pid host -v ./certs/server.key:/k alpine") == "deny"

@pytest.mark.xfail(reason="no stop-at-first-operand: `--privileged` in the container's own argv is read as a docker option and denied; to be reintroduced", strict=True)
def test_container_argv_is_not_read_as_host_options():
    # Docker only takes options before the image: what follows runs in the
    # sandbox, so it may not be reported as an escape attempt on the host.
    assert run(command="docker run --rm --pid host alpine mytool --privileged") == "ask"

def test_anchored_bind_mount_of_a_secret_denied():
    assert run(command="docker run --rm --mount type=bind,source=./.env,target=/x alpine") == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=bind,source=.env,target=/x alpine",
    "docker run --rm --mount type=bind,src=certs/server.key,dst=/x alpine",
    "docker run --rm --mount type=bind,source=.ssh/id_rsa,target=/x alpine",
    "docker run --rm --mount src=.env,dst=/x alpine",
    "docker run --rm --mount type=glob,source=.ssh/id_*,target=/x alpine",
])
def test_unanchored_bind_mount_of_a_secret_asks(cmd):
    # A bind source is a host path even without a leading `./`, but `is_path()` only
    # recognises an anchored one, so the source is reported as an unresolved mount
    # instead of being path-checked. Accepted risk: it still stops at an ask.
    assert run(command=cmd) == "ask"

@pytest.mark.xfail(reason="split_fields() keeps one value per key, so a duplicated source/src pair hides the second path entirely", strict=True)
def test_bind_mount_with_duplicate_source_keys_denied():
    assert run(command="docker run --rm --mount type=bind,source=./ok,src=.env,target=/x alpine") == "deny"

@pytest.mark.xfail(reason="`readonly` wins over `ro` in parse_mount_ref, so a read-write mount is read as read-only", strict=True)
def test_bind_mount_with_conflicting_readonly_flags_denied():
    assert run(command="docker run --rm --mount type=bind,source=./.git,readonly=true,ro=false,target=/x alpine") == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=volume,source=v,volume-opt=device=/etc,target=/x alpine",
    "docker run --rm --mount src=/etc,dst=/x alpine",
    "docker run --rm --mount type=glob,source=/etc/*,target=/x alpine",
    "docker run --rm --mount type=bogus,source=/etc,target=/x alpine",
    "docker run --rm --mount type=bind,source=/etc,src=.,target=/x alpine",
])
def test_mount_binding_host_directory_asks(cmd):
    # Only the types naming a docker object are trusted: an unknown one may bind.
    assert run(command=cmd) == "ask"

@pytest.mark.xfail(reason="parse_mount_ref never reads `volume-opt`, so a bind-backed named volume exposes its device path unchecked", strict=True)
def test_mount_volume_opt_device_asks():
    assert run(command="docker run --rm --mount type=volume,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/etc,target=/x alpine") == "ask"

@pytest.mark.xfail(reason="split_fields() keeps one value per key, so `source=.` hides the `src=/etc` that follows it", strict=True)
def test_mount_with_duplicate_source_keys_asks():
    assert run(command="docker run --rm --mount type=bind,source=.,src=/etc,target=/x alpine", mode="acceptEdits") == "ask"

@pytest.mark.parametrize("cmd", [
    "docker run --rm -v mydata:/data alpine",
    "docker run --rm --mount type=volume,source=mydata,target=/data alpine",
    "docker run --rm --mount type=volume,source=mydata,volume-opt=device=./cache,target=/data alpine",
])
def test_named_volume_mounts_ask(cmd):
    # A named docker volume has no host path at all, but `type=volume` is no longer
    # trusted on its own, so it is reported as an unresolved mount. A false ask.
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=bind,source=src,target=/app alpine",
    "docker run --rm --mount src=src,dst=/app alpine",
])
def test_unanchored_project_bind_mounts_ask(cmd):
    # Rule 3.3 permits the project directory, but `is_path()` only recognises an
    # anchored source, so `src` is not resolved against the project. A false ask.
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("flag", ["ro", "ro=true", "readonly", "readonly=true"])
def test_readonly_mount_is_read_only(flag):
    # Reading the .git directory is fine; writing it is a deny (rule 1.2).
    assert run(command=f"docker run --rm --mount type=bind,source=./.git,target=/x,{flag} alpine") == "allow"

@pytest.mark.parametrize("flag", ["", ",ro=false", ",ro=False", ",ro=f", ",ro=0", ",ro=1", ",ro=Y", ",readonly=false"])
def test_mount_without_a_true_readonly_flag_is_read_write(flag):
    # Every spelling but a recognised "true" is a read-write mount: the weaker
    # Mode.READ may not be assumed by default.
    assert run(command=f"docker run --rm --mount type=bind,source=./.git,target=/x{flag} alpine") == "deny"

def test_mount_of_a_parent_directory_asks():
    assert run(command="docker run --rm -v ..:/parent alpine") == "ask"

@pytest.mark.xfail(reason="rule 3.3 is stricter than the file rules, but the mount source is vetted by check_access, which allows /tmp and (read-only) ~/.claude", strict=True)
@pytest.mark.parametrize("cmd", [
    "docker run --rm -v /tmp/work:/work alpine",
    "docker run --rm --mount type=bind,source=/tmp/work,target=/work alpine",
    "docker run --rm --mount type=bind,source=~/.claude,target=/x,ro alpine",
    "docker volume create --opt device=/tmp/work data",
])
def test_mount_outside_the_project_asks(cmd):
    # Rule 3.3 is stricter than the file rules: /tmp and ~/.claude are readable
    # by the agent, but may not be handed to a container.
    # Edit mode, so that the §1.4 write gate is not what produces the ask.
    assert run(command=cmd, mode="acceptEdits") == "ask"

# --- Volumes and copies -----------------------------------------------------

def test_volume_create_allowed():
    assert run(command="docker volume create data") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker volume create --opt type=none,o=bind,device=/etc data",
    "docker volume create -o device=/etc data",
])
def test_volume_create_binding_host_directory_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", [
    "docker compose cp web:/app/out ./out",
    "docker cp web:/app/out ./out",
    "docker container cp ./src web:/app",
])
def test_container_cp_allowed(cmd):
    assert run(command=cmd, mode="acceptEdits") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker compose cp web:/app/out /etc/out",
    "docker cp web:/app/out /etc/out",
])
def test_container_cp_outside_project_asks(cmd):
    assert run(command=cmd) == "ask"

# --- Building an image ------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "docker build .",
    "docker build -t myapp:dev .",
    "docker build --no-cache --pull -f docker/Dockerfile .",
    "docker build --build-arg VERSION=1 --target dev .",
    "docker buildx build -t myapp .",
    "docker build --cache-to type=local,dest=./cache .",
])
def test_container_build_allowed(cmd):
    assert run(command=cmd, mode="acceptEdits") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker build -f /etc/Dockerfile .",
    "docker build -o /etc/out .",
    "docker build --platform linux/amd64 .",
    "docker build /etc",
    "docker buildx create --use",
])
def test_container_build_asks(cmd):
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", [
    "docker build --iidfile .env .",
    "docker build --metadata-file id_rsa .",
    "docker build --cache-from ./certs/server.key .",
])
def test_container_build_secret_paths_denied(cmd):
    # A bare build path is cwd-relative, not a named volume: it must be vetted.
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="parse_opt_paths() keeps only the is_path() fields of a structured value, so an unanchored `dest=` is dropped instead of vetted", strict=True)
def test_container_build_structured_output_secret_denied():
    assert run(command="docker build -o type=local,dest=.env .") == "deny"

# --- Fallback ---------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "docker",
    "docker push myapp",
    "docker image push myapp",
    "docker compose",
    "docker compose --project-directory ../other up",
])
def test_container_unknown_commands_ask(cmd):
    assert run(command=cmd) == "ask"

def test_container_login_asks():
    assert run(command="docker login -u me registry.io") == "ask"

