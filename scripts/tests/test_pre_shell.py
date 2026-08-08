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

@pytest.mark.parametrize("cmd", ["uv run --frozen", "uv run --no-sync", "uv run"])
def test_uv_run_without_tool_asks(cmd):
    assert run(command=cmd) == "ask"

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

def test_podman_mirrors_docker():
    assert run(command="podman compose up -d") == "allow"
    assert run(command="podman run --privileged alpine") == "deny"

def test_legacy_compose_binary_allowed():
    assert run(command="docker-compose up -d") == "allow"
    assert run(command="podman-compose logs web") == "allow"

# --- Escaping the sandbox ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "docker run --privileged alpine",
    "docker run --cap-add SYS_ADMIN alpine",
    "docker run --device /dev/sda alpine",
    "docker run --security-opt seccomp=unconfined alpine",
    "docker run -u 0 alpine",
    "docker run -u0 alpine",
    "docker run --user root alpine",
    "docker run --user=0:0 alpine",
    "docker exec -u root web ls",
    "docker compose up --privileged",
])
def test_container_escape_options_denied(cmd):
    assert run(command=cmd) == "deny"

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
    "docker run --rm -v mydata:/data alpine",
    "docker run --rm --mount type=bind,source=./src,target=/app alpine",
    "docker run --rm --mount type=volume,source=mydata,target=/data alpine",
    "docker run -d --name web -p 8080:80 -e FOO=bar --network mynet nginx",
    "docker run --rm --entrypoint /bin/sh alpine",
    "docker run --rm --tmpfs /scratch alpine",
    "docker exec web ls",
    "docker create --name web nginx",
    "docker compose run --rm web",
    "docker compose exec web ls",
])
def test_container_run_allowed(cmd):
    assert run(command=cmd) == "allow"

def test_container_argv_is_not_checked():
    # Everything after the image runs *inside* the sandbox: it is neither a
    # docker option nor a host path.
    assert run(command="docker run --rm alpine cat /etc/shadow") == "allow"
    assert run(command="docker run --rm alpine ls -la /root/.ssh") == "allow"

@pytest.mark.parametrize("cmd", [
    "docker run --rm -v /etc:/etc alpine",
    "docker run --rm --mount type=bind,source=/etc,target=/etc alpine",
    "docker run --rm --mount type=BIND,source=/etc,target=/etc alpine",
    "docker run --rm --volumes-from other alpine",
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

def test_container_argv_is_not_read_as_host_options():
    # Docker only takes options before the image: what follows runs in the
    # sandbox, so it may not be reported as an escape attempt on the host.
    assert run(command="docker run --rm --pid host alpine mytool --privileged") == "ask"

@pytest.mark.parametrize("cmd", [
    "docker rm -v --privileged web",
    "docker compose down -v --privileged",
])
def test_escape_option_behind_a_valueless_flag_denied(cmd):
    # `-v` takes no value for these verbs: it may not swallow the option after it.
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=bind,source=.env,target=/x alpine",
    "docker run --rm --mount type=bind,source=./.env,target=/x alpine",
    "docker run --rm --mount type=bind,src=certs/server.key,dst=/x alpine",
    "docker run --rm --mount type=bind,source=.ssh/id_rsa,target=/x alpine",
    "docker run --rm --mount src=.env,dst=/x alpine",
    "docker run --rm --mount type=glob,source=.ssh/id_*,target=/x alpine",
    "docker run --rm --mount type=bind,source=./ok,src=.env,target=/x alpine",
    "docker run --rm --mount type=bind,source=./.git,readonly=true,ro=false,target=/x alpine",
])
def test_bind_mount_of_a_secret_denied(cmd):
    # A bind source is a host path even without a leading `./`: unlike the `-v`
    # syntax, a bare name is never a docker-managed volume name.
    assert run(command=cmd) == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=volume,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/etc,target=/x alpine",
    "docker run --rm --mount type=volume,source=v,volume-opt=device=/etc,target=/x alpine",
    "docker run --rm --mount src=/etc,dst=/x alpine",
    "docker run --rm --mount type=glob,source=/etc/*,target=/x alpine",
    "docker run --rm --mount type=bogus,source=/etc,target=/x alpine",
    "docker run --rm --mount type=bind,source=.,src=/etc,target=/x alpine",
    "docker run --rm --mount type=bind,source=/etc,src=.,target=/x alpine",
])
def test_mount_binding_host_directory_asks(cmd):
    # Only the types naming a docker object are trusted: an unknown one may bind.
    assert run(command=cmd) == "ask"

@pytest.mark.parametrize("cmd", [
    "docker run --rm --mount type=volume,source=mydata,target=/data alpine",
    "docker run --rm --mount type=volume,source=mydata,volume-opt=device=./cache,target=/data alpine",
    "docker run --rm --mount type=bind,source=src,target=/app alpine",
    "docker run --rm --mount src=src,dst=/app alpine",
])
def test_project_and_named_volume_mounts_allowed(cmd):
    assert run(command=cmd) == "allow"

@pytest.mark.parametrize("flag", ["ro", "ro=true", "ro=1", "ro=Y", "readonly", "readonly=true"])
def test_readonly_mount_is_read_only(flag):
    # Reading the .git directory is fine; writing it is a deny (rule 1.2).
    assert run(command=f"docker run --rm --mount type=bind,source=./.git,target=/x,{flag} alpine") == "allow"

@pytest.mark.parametrize("flag", ["", ",ro=false", ",ro=False", ",ro=f", ",ro=0", ",readonly=false"])
def test_mount_without_a_true_readonly_flag_is_read_write(flag):
    # Every spelling but a recognised "true" is a read-write mount: the weaker
    # Mode.READ may not be assumed by default.
    assert run(command=f"docker run --rm --mount type=bind,source=./.git,target=/x{flag} alpine") == "deny"

@pytest.mark.parametrize("cmd", [
    "docker run --rm -v /tmp/work:/work alpine",
    "docker run --rm --mount type=bind,source=/tmp/work,target=/work alpine",
    "docker run --rm --mount type=bind,source=~/.claude,target=/x,ro alpine",
    "docker run --rm -v ..:/parent alpine",
    "docker volume create --opt device=/tmp/work data",
])
def test_mount_outside_the_project_asks(cmd):
    # Rule 3.3 is stricter than the file rules: /tmp and ~/.claude are readable
    # by the agent, but may not be handed to a container.
    assert run(command=cmd) == "ask"

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
    assert run(command=cmd) == "allow"

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
    assert run(command=cmd) == "allow"

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
    "docker build -o type=local,dest=.env .",
    "docker build --cache-from ./certs/server.key .",
])
def test_container_build_secret_paths_denied(cmd):
    # A bare build path is cwd-relative, not a named volume: it must be vetted.
    assert run(command=cmd) == "deny"

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

