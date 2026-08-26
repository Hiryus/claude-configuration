# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

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

def environment(cwd:object, project_root:object) -> dict[str, str]:
    """
    The environment the hook reads `CLAUDE_PROJECT_DIR` from.
    Anything that is not a string (the `None` of the "unset" cases) leaves it out.
    """
    root = cwd if project_root is SAME_AS_CWD else project_root
    return {"CLAUDE_PROJECT_DIR": root} if isinstance(root, str) else {}

def output(command:str, tool_name="Bash", cwd=ROOT, description="A meaningful description", mode="default", project_root=SAME_AS_CWD):
    result = main({
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "permission_mode": mode,
        "tool_input": {
            "command": command,
            "description": description,
        },
    }, environ=environment(cwd, project_root))
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

@pytest.mark.parametrize("cmd", ["ls", "pwd", "wc -l foo", "echo hi", "cut -d: -f1 x"])
def test_readonly_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", [
    "uniq",                 # §2.8: `uniq [INPUT [OUTPUT]]` writes its second operand
    "uniq -c in.txt",
    "uniq in.txt out.txt",
    "sort",                 # §2.8: `sort -o FILE` writes its output
    "sort in.txt",
    "sort -o out.txt in.txt",
])
def test_writing_filters_not_in_the_allow_list(cmd):
    assert run(command=cmd) == "ask"

def test_readonly_double_dash_path_checks_the_operand():
    # §5.2/§4.1.3: `--` must reach the untabled read-only group too, so
    # -weird.pem is path-checked instead of being read as a flag.
    assert run(command="cat -- -weird.pem") == "deny"

def test_assignment_only_allowed():
    assert run(command="FOO=bar") == "allow"

@pytest.mark.parametrize(("cmd", "mode", "decision"), [
    ("FOO=bar > .env", "default", "deny"),                    # 1.1: truncates a secret
    ("FOO=bar > /proj/.git/config", "acceptEdits", "deny"),   # 1.2: truncates a git file
    ("FOO=bar > /elsewhere/x.txt", "default", "ask"),         # 1.4: outside the project
    ("FOO=bar > notes.txt", "default", "ask"),                # 1.4: a write in manual mode
    ("FOO=bar > notes.txt", "acceptEdits", "allow"),
])
def test_assignment_redirect_is_still_checked(cmd, mode, decision):
    # An assignment is harmless on its own, but `>` truncates its target all the same,
    # so rule 2.5 applies to it like to any other command.
    assert run(command=cmd, mode=mode) == decision

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
    "cd /somewhere && ls",  # rule 2.3: a `cd` may not share the call
])
def test_denied_commands(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.xfail(reason="rule 2.7: pre_shell.check_command has no `python` branch (the pip/mypy ones survived), so it falls through to the unknown-command ask", strict=True)
@pytest.mark.parametrize("cmd", ["python script.py", "python -m http.server", "python3 script.py"])
def test_python_denied(cmd):
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

def test_cat_harness_credentials_denied():
    # 1.1: the harness is readable, its tokens are not.
    assert run(command="cat ~/.claude/.credentials.json") == "deny"

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
    "cut -d= -f2 .env",     # prints selected fields
    "head -1 .env",         # prints the first line
    "diff .env /dev/null",  # prints the whole file as a diff
    "jq . .env",            # parses and prints the file
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
    "cat /etc/passwd",          # reads an external file
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
# cd -- allowed only on its own (rule 2.3)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "cd /tmp",
    "cd /tmp/",
    "cd -P /tmp",
    "cd -- /tmp",
    "cd",                # $HOME
    "cd ~",
    "cd -",              # the shell knows where it lands, and reports it back
    "cd $HOME",          # parameter expansion: the hook does not need to resolve it
    "cd /nonexistent",   # bash fails and stays put -- the next payload says so
])
def test_lone_cd_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_cd_relative_target_allowed(tmp_path):
    (tmp_path / "sub").mkdir()
    assert run(command="cd sub", cwd=str(tmp_path)) == "allow"

def test_cd_outside_the_project_allowed():
    # The `cd` itself discloses nothing, and every later access is still
    # path-checked against the unchanged project root.
    assert run(command="cd /tmp") == "allow"

def test_cd_redirect_is_still_checked():
    # The `cd` verdict may not vouch for what the command writes on its way.
    assert run(command="cd /tmp > .env") == "deny"

@pytest.mark.parametrize("cmd", [
    "cd /tmp; ls",                    # the `ls` would be checked against the old directory
    "cd /tmp && ls",
    "ls; cd /tmp",
    "ls && cd /tmp",
    "cd /tmp; cd /var",
    "CDPATH=/ ; cd /tmp",             # an assignment is a command too
    "echo $(cd /tmp)",                # a substitution holds a command of its own
    "echo `cd /tmp`",
    "cd $(pwd)",                      # ... on the target side too
    "{ ls; cd /tmp; }",
    "(cd /tmp); ls",
    "cd /tmp | cat",
    "cd /tmp & ls",
])
def test_cd_alongside_another_command_denied(cmd):
    assert run(command=cmd) == "deny"

def test_cd_does_not_move_the_project_boundary():
    # A relative path, so the assertion really depends on the perimeter: wherever a
    # previous `cd` left the shell, the project is still `CLAUDE_PROJECT_DIR`.
    # `/` is a real directory outside the project and not one of the exempted locations.
    assert run(command="cat notes.txt", cwd="/", project_root="/proj") == "ask"
    assert run(command="cat notes.txt", cwd="/proj", project_root="/proj") == "allow"

# ============================================================================
# The payload cwd anchors the whole call
# ============================================================================

def test_paths_are_anchored_on_the_reported_cwd(tmp_path):
    # What a previous lone `cd` did is visible only through the payload `cwd`.
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "server.pem").touch()
    assert run(command="cat *.pem", cwd=str(tmp_path)) == "allow"  # nothing matches at the root
    assert run(command="cat *.pem", cwd=str(sub)) == "deny"        # ... but the secret matches in `sub`

def test_cwd_inside_git_dir_does_not_defeat_the_git_rule(tmp_path):
    # The predicates run on standardized paths, so a cwd already inside `.git`
    # cannot hide a git file behind a plain name.
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    assert run(command="echo x > config", cwd=str(git_dir), mode="acceptEdits") == "deny"

def test_cwd_inside_ssh_dir_does_not_defeat_the_secret_rule(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    assert run(command="cat known_hosts", cwd=str(ssh_dir)) == "deny"

# ============================================================================
# cd -- whether it runs is the shell's business, not the hook's
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "test -d /tmp && cd /tmp",           # the `test` shares the call
    "ls || cd /tmp",
    "if test -d /tmp; then cd /tmp; fi",
    "while ls; do cd /tmp; done",
    "until ls; do cd /tmp; done",
    "case x in x) cd /tmp;; esac",       # bashlex cannot parse `case` at all (rule 2.1)
])
def test_cd_sharing_the_call_with_a_test_denied(cmd):
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "for f in *; do cd /tmp; done",  # may run zero, one or many times
    "f() { cd /tmp; }",              # only runs when the function is called
])
def test_cd_that_may_not_run_is_still_allowed_alone(cmd):
    # The hook does not predict the shell: it holds no `cd` target to be wrong about,
    # and wherever the shell ends up, the next payload reports it.
    assert run(command=cmd) == "allow"

def test_commands_inside_a_body_are_checked_like_any_other():
    # Descending into an `if`/`for` body is what matters; how often it runs is not.
    assert run(command="if ls; then cat .env; fi") == "deny"
    assert run(command="if ls; then ls; fi") == "allow"

# ============================================================================
# pushd / popd -- the same rule as cd (2.3)
# ============================================================================

@pytest.mark.parametrize("cmd", ["pushd /tmp", "popd"])
def test_lone_directory_stack_move_allowed(cmd):
    # The stack is the shell's business: the hook does not follow it, it just reads
    # the directory the harness reports once the call is over.
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("cmd", ["pushd /tmp; ls", "ls && popd", "pushd /tmp; popd"])
def test_directory_stack_move_alongside_another_command_denied(cmd):
    assert run(command=cmd) == "deny"

# ============================================================================
# Shell nesting (2.6)
# ============================================================================

@pytest.mark.parametrize("cmd", [
    "exec ls",
    "eval ls",
    "source env.sh",
    ". env.sh",
    "source /tmp/env.sh",
])
def test_shell_nesting_commands_denied(cmd):
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
    "docker compose --dry-run up",  # rule 3.1: a simulated command can never do more than the bare one
    "docker compose up --dry-run",
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
    # `--pid` is tabled, so `host` is its value, not the image: `--privileged` is
    # still before the operand. A deny may never degrade into an ask.
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
    "docker run --rm -i alpine",
    "docker exec -i web ls",
    "docker compose run --dry-run web",  # rule 3.1: the verbs inherit the global options
    "docker compose --dry-run run web",
])
def test_container_run_allowed(cmd):
    # Edit mode: a read-write bind mount is a write, gated by §1.4 in manual mode.
    assert run(command=cmd, mode="acceptEdits") == "allow"

def test_only_the_tty_flag_gates_the_interactive_cluster():
    # `-i` is on the §3.3 list, `-t` is not: only the latter is named in the reason.
    assert "'-t'" in reason(command="docker run --rm -it alpine")
    assert "'-i'" not in reason(command="docker run --rm -it alpine")

def test_container_argv_path_is_not_checked():
    # Everything after the image runs *inside* the sandbox: it is not a host path.
    assert run(command="docker run --rm alpine cat /etc/shadow") == "allow"

def test_container_argv_flags_are_not_checked():
    assert run(command="docker run --rm alpine ls -la /root/.ssh") == "allow"

@pytest.mark.parametrize("cmd", [
    'docker exec seat-front grep -rl "x" /var/www 2>&1 | head',  # the reported bug: fd-dup + pipe
    "docker container exec web ls -la",                          # the `container` spelling too
    "docker compose run --rm web pytest --cov",                  # a compose service argv
    "docker exec -- web ls -la",                                 # the operand may sit behind a `--`
    "docker exec web grep -- foo",                               # ... and the argv may carry its own
])
def test_container_argv_options_are_not_checked(cmd):
    assert run(command=cmd) == "allow"

def test_container_argv_does_not_hide_a_docker_option():
    # A space-separated value may not move the boundary: `always` is `--pull`'s, not the image.
    assert run(command="docker run --rm --pull always -v /etc:/etc alpine ls") == "ask"

def test_untabled_option_before_the_operand_disables_the_strip():
    # `-u0` is untabled, so it is not paired with its value: `alpine` may be that value rather than
    # the image. The boundary is unknown, so the whole line stays under option parsing.
    assert run(command="docker run -u0 -v ./certs/server.key:/k alpine cmd") == "deny"

def test_flag_shaped_value_before_the_operand_disables_the_strip():
    # `--name` swallows `-v`, so `./x:/y` reads as the image -- docker reads it the same way, but
    # such a line is almost always a typo: it is checked whole rather than newly allowed.
    assert run(command="docker run --rm --name -v ./x:/y --privileged alpine") == "deny"

def test_negative_value_before_the_operand_keeps_the_strip():
    # `-1` is `--stop-timeout`'s value, not a flag: the boundary is still the image, so the argv
    # is dropped. Reading it as flag-shaped would put the whole line back under option parsing.
    assert run(command="docker run --rm --stop-timeout -1 alpine mytool --privileged") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker run --rm -v /etc:/etc alpine",
    "docker run --rm --mount type=bind,source=/etc,target=/etc alpine",
    "docker run --rm --mount type=BIND,source=/etc,target=/etc alpine",
    "docker run --rm -it alpine",  # `-i` is allowed, `-t`/`--tty` is not: the cluster still asks
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
    # The unsupported option comes first here: it is tabled, so it is paired with its
    # value and the options behind it are read instead of being taken for the image.
    assert run(command="docker run --rm --pid host --env-file .env alpine") == "deny"
    assert run(command="docker run --rm --pid host -v ./certs/server.key:/k alpine") == "deny"

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

