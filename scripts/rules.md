**Status**: reversed engieneered from code - needs cleanup and to add reasons.

This file describes the rules we want to implement to control the tool calls.
- If two rules contradict each other, **specific** rules take precedence over **generic** ones, then **deny** rules takes precedence over the others.
- In most cases, rules either define `allow` or `deny` behaviors.
  Everything else falls back to `ask`.

In **auto mode**, any `ask` is converted to a `deny`, so any rule below that depends on the mode (`acceptEdits`, `auto`, `bypassPermissions`) to grant an explicit `allow` is what keeps that operation from being silently dropped in auto mode.

## File rules

### 1. No credentials access

The agent is **denied** to **access** (read and write) files containing credentials, whatever their location, including:
- Files with the `.pem`/`.key`/`.p12`/`.pfx`/`.keystore`/`.jks`, `.htpasswd`/`.netrc`/`.npmrc`/`.pgpass` extensions,
- The dotenv (`.env`/`.env.local`/`.env.production`) and usual ssh key (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`) files,
- Any files under `.ssh/`.

Template files (`.example`, `.sample`, `.template` suffix) are exempted from this rule.

**Reason**: Tools results are streamed to an untrusted third party service for LLM inferance while secrets should never be shared anywhere.

### 2. No direct git modifications

The agent is **denied** to **write** file in any `.git` directory locations, including subfolders.

**Reason**: Modifying git files directly is dangerous and error-prone. git state should only be changed through the git cli.

### 3. No harness modifications

The agent is **denied** to **write** file in its harness directory (`~/.claude`).

**Reason**: Modifying the harness files would allow the agent to lift its own restrictions.  

### 4. Allowed folders

The agent is **allowed** to **read** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The harness directory (`~/.claude`),
- The current project.

In **edit mode**, the agent is **allowed** to **write** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The current project.

**Reason**: The agent aim is to update the project. This is
It sometimes also uses temporary files for tests or downloads and read the harness configuration.

## Bash rules

- A command line that does not carry a meaningful `description` explaining why the command is needed is **denied**.
- The command line is parsed into individual commands (handling pipes, `&&`, subshells, command substitutions, etc.).
  Each below rule is then checked against these individual commands. The overall decision for the line is the worst (**deny** > **ask** > **allow**) across all of the sub-commands.
  If parsing the command line fails outright, the whole request is **denied** rather than falling back to ask.
- A bare variable assignment (`FOO=bar`) is **allowed**.
- All files accessed follow the [File rules](#file-rules), including:
  * Files defined as input or output in the binary options (ex: `--output <path>`),
  * `>`, `>>`, `>|`, `&>`, `&>>` redirects counting as _write_ operations,
  * `<`, `<>`, `<<<` redirects counting as _read_ operations,
  * fd-dups like `2>&1` and `/dev/null` are ignored.
- A path that looks like a glob pattern (`*`, `?`, `[`, `{`, `(`) is expanded against the real filesystem when possible.
  Each match is checked with the [File rules](#file-rules).
- If any path is built from a substitution or expansion (`$(...)`, `` `...` ``, `$VAR`, arithmetic, ...), the whole command is considered "dynamic", resulting in **ask**, since its real target can't be verified statically. The following exceptions apply:
  * A leading `~` is expanded to the user home.
- Further specific rules apply to various known binaries (see below). Unless explicited otherwise, substitution or expansion (`$(...)`, `` `...` ``, `$VAR`, arithmetic, ...) always result in **ask** since the command is not parsable out of context (exception are detailed for some commandes).

### Alternative binaries

- The `pip` and `pip3` commands are **denied** in favor of `uv`.
- The `python` and `python3` commands are **denied** in favor of `uv` (or `uvx`).
  Running python from a virtual environment (venv) is also denied.
- The `mypy` command is **denied** in favor of `ty` (`uv run ty`).
  Running mypy via the `uv` command is also denied.
- The `gh` command is **denied** in favor of the github MCP.

### Common binaries

- Spawning a new shell (`bash`, `sh`, `zsh`, `cmd`, `powershell`, etc.) is **denied**.
- For the `find` binary, the `-delete`, `-exec`, `-execdir`, `-fls`, `-fprint`, `-fprint0`, `-fprintf`, `-ok`, and `-okdir` options are **denied** modulo . Otherwise the leading search-root arguments are checked against [File rules](#file-rules).
- The `echo`, `printf`, `pwd`, `sleep`, and `tr` binaries are **allowed** since they only print information and do not access any file.
  Simple variable substitutions (`$VAR` or `${VAR}`) are allowed as argument.
- The `cat`, `cmp`, `cut`, `diff`, `file`, `head`, `jq`, `less`, `ls`, `more`, `sort`, `tail`, `test`, `uniq`, and `wc` binaries are allowed/ask/denied based on the path(s) they read using the [File rules](#file-rules).
- For the `grep` binary, positional arguments are treated as _read_ accesses, minus the search pattern itself. The `-f`/`--file` argument value is a _read_ access too. The [File rules](#file-rules) apply to both.
- For the `sed` binary, `-n`/`--quiet`/`--silent` options are **allowed**. Anything else is deemed "too complex to verify" (**ask**).

### git specific rules

- Any `git` command accessing a file outside the current repository is **denied**.
  Reason: 
- The `-C` option is **denied**.
- `git push` on main is **denied**.
- `git push` with the option `-f`/`--force` is **denied**.
- `git push` is **allowed** on `feat/` and `fix/` branches (assuming no `-f`/`--force` option).
- `git branch` is **allowed** with a fixed set of read-only flags (`--show-current`, `-v`, `--merged`, `--contains`, `--list`...).
- `git commit` is **allowed** except when the `--output`/`-o` option is supplied, in which case the [File rules](#file-rules) apply.
- `git remote` is **allowed** for read-only options (`git remote show`, `git remote get-url`, etc.).
- `git add`, `git check-ignore`, `git diff`, `git grep`, `git hash-object`, `git log`, `git ls-files`, `git ls-tree`, `git merge-base`, `git rev-parse`, `git show`, `git status` are **allowed**.

| `git -C ... ` | Always denied -- already at the repo root.
| `git -c ...` | Always denied -- can inject arbitrary config/code.

/!\ env variables
--git-dir
https://git-scm.com/cheat-sheet

### node specific rules

| `node --version`/`-v`| Allowed.|
| `node --check <file>` | File is a read, checked normally. |
| any other `node` usage | Asks. |

### npm specific rules

| `npm --version`/`-v`, `npm ls`, `npm outdated`, `npm view` | Allowed. |
| `npm audit` | Allowed; `npm audit fix` asks. |
| `npm prune` | Allowed only in `acceptEdits`/`auto`/`bypassPermissions` mode (it modifies `node_modules`); otherwise asks. |
| any other `npm` | Asks. |

### podman specific rules

| `podman compose logs`, `podman compose ps`, `podman inspect`, `podman logs`, `podman port`, `podman ps`, `podman --version` | Allowed. |
| any other `podman` usage | Asks. |
| `uv sync`, `uv --version` | Allowed. |

### uv specific rules

| `uv run basedpyright/pyright/pytest/ruff/ty` | Allowed. |
| `uv run python --version` | Allowed. |
| any other `uv` usage | Asks. |
