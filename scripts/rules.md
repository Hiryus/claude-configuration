**Status**: reversed engieneered from code - needs cleanup and to add reasons.

This file describes the rules we want to implement to control the tool calls.

In most cases, rules either define `allow` or `deny` behaviors.
Everything else falls back to `ask`.

In **auto mode**, any `ask` is converted to a `deny`, so any rule below that depends on the mode (`acceptEdits`, `auto`, `bypassPermissions`) to grant an explicit `allow` is what keeps that operation from being silently dropped in auto mode.

## File rules

- The agent is **denied** to _access_ (read and write) files containing credentials, whatever their location, including:
  * Files with the `.pem`/`.key`/`.p12`/`.pfx`/`.keystore`/`.jks`, `.htpasswd`/`.netrc`/`.npmrc`/`.pgpass` extensions,
  * The dotenv (`.env`/`.env.local`/`.env.production`) and usual ssh key (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`) files,
  * Any files under `.ssh/`.
  Template files (`.example`, `.sample`, `.template` suffix) are exempted from this rule.
- The agent is **denied** to _wite_ file in the following locations, including subfolders:
  * Any `.git` directory,
  * The harness directory (`~/.claude`).
- The agent is **allowed** to _read_ file in the following locations, including subfolders (with exceptions listed above):
  * The current project,
  * The temporary directories (`/tmp`, `/var/tmp`, etc.),
  * The harness directory (`~/.claude`).
- In **edit mode**, the agent is **allowed** to _write_ files in the following locations, including subfolders (with exceptions listed above):
  * The current project,
  * The temporary directories (`/tmp`, `/var/tmp`, etc.).

## Bash rules

- A command line that does not carry a meaningful `description` explaining why the command is needed is **denied**.
- The command line is parsed into individual commands (handling pipes, `&&`, subshells, command substitutions, etc.). Each below rule is then checked against these individual commands. The overall decision for the line is the worst (`deny` > `ask` > `allow`) across all of its commands.
- A bare variable assignment (`FOO=bar`) is **allowed**.
- 
via a redirect (`>`, `>>`, `>|`, `&>`, `&>>` count as a write; `<`, `<>`, `<<<` count as a read -- fd-dups like `2>&1` and `/dev/null` targets are ignored
Each match is checked with the [File rules](#file-rules).
- A path that looks like a glob pattern (`*`, `?`, `[`, `{`, `(`) is expanded against the real filesystem when possible. Each match is checked with the [File rules](#file-rules).

If any command's program, argument, or redirect target is built from a substitution or expansion (`$(...)`, `` `...` ``, `$VAR`, arithmetic, ...) -- other than a leading `~` -- the whole command is "dynamic" and asks, since its real target can't be verified statically. 

A command can reference a path either via a redirect (`>`, `>>`, `>|`, `&>`, `&>>` count as a write; `<`, `<>`, `<<<` count as a read -- fd-dups like `2>&1` and `/dev/null` targets are ignored) or via the arguments a given command is known to read/write (see the per-command list below). Every such reference is checked, in order:


### Toolchain rules (deny with a preferred alternative)

These are unconditional: use the other tool instead.

| Command                                                         | Instead use                                                    |
| --------------------------------------------------------------- | -------------------------------------------------------------- |
| `cd`                                                            | pass paths directly; changing directory breaks path validation |
| `pip`, `pip2`, `pip3`, ...                                      | `uv add`, `uv sync`, `uvx`                                     |
| `mypy` (direct or via `uv run mypy`)                            | `uv run ty`                                                    |
| `python`, `python3`                                             | `uv run python` (or `uvx` if the command used `-m`)            |
| any `.../.venv/.../python`                                      | `uv run python` or `uvx`                                       |
| `bash`, `sh`, `zsh`, `dash`, `ksh`, `cmd`, `powershell`, `pwsh` | run the command directly via the Bash tool                     |
| `composer`, `php`                                               | a podman container                                             |
| `gh`                                                            | the GitHub MCP tools                                           |

### Per-command allow-list

Everything not covered below (e.g. `awk`) is unknown and always asks (any redirected files are mentioned in the prompt).

| Command                                                                                                                                                              | Rule                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pwd`, `echo`, `printf`, `sleep`, `tr`                                                                                                                               | Always allowed -- they touch no files.                                                                                                                                                                                                                                              |
| `cat`, `file`, `head`, `tail`, `less`, `more`, `cut`, `diff`, `jq`, `ls`, `sort`, `test`, `uniq`, `wc`, `cmp`                                                        | Positional arguments are treated as reads and run through the file-access checks.                                                                                                                                                                                                   |
| `grep`                                                                                                                                                               | Positional arguments are treated as reads, minus the search pattern itself and the values of flags that don't take a file (`-e`/`--regexp` pattern, `-A`/`-B`/`-C`/`-m`/... value); `-f`/`--file` value is a read (grep reads patterns from it). Then the file-access checks apply. |
| `sed`                                                                                                                                                                | Only allowed with `-n`/`--quiet`/`--silent` and a script made solely of `addr[,addr]p` print commands (no `s`, `w`, `e`, `r`, ...) -- anything else asks as "too complex to verify read-only". If it passes, remaining positional args are reads, checked normally.                 |
| `find`                                                                                                                                                               | Asks if it uses `-delete`, `-exec`, `-execdir`, `-fls`, `-fprint`, `-fprint0`, `-fprintf`, `-ok`, or `-okdir`. Otherwise the leading search-root arguments are reads, checked normally.                                                                                             |
| `git -C ...`                                                                                                                                                         | Always denied -- already at the repo root.                                                                                                                                                                                                                                          |
| `git -c ...`                                                                                                                                                         | Always denied -- can inject arbitrary config/code.                                                                                                                                                                                                                                  |
| `git branch`                                                                                                                                                         | Allowed only with a fixed set of read-only flags (`--show-current`, `-v`, `--merged`, `--contains`, `--list`, ...); anything else asks. Note the allow-list contains the literal string `--sort=<key>`, so a real `--sort=name` flag doesn't match it and falls through to ask.     |
| `git push`                                                                                                                                                           | Asks; `-f`/`--force` is always denied.                                                                                                                                                                                                                                              |
| `git remote` (no subcommand), `git remote show`, `git remote get-url`                                                                                                | Allowed. Any other `git remote` subcommand asks.                                                                                                                                                                                                                                    |
| `git add`, `git commit`                                                                                                                                              | Non-flag arguments are reads, checked normally; `--output`/`-o` (any subcommand) registers a write, checked normally.                                                                                                                                                               |
| `git check-ignore`, `git diff`, `git grep`, `git hash-object`, `git log`, `git ls-files`, `git ls-tree`, `git merge-base`, `git rev-parse`, `git show`, `git status` | Allowed (after the write/read checks above).                                                                                                                                                                                                                                        |
| any other `git` subcommand                                                                                                                                           | Asks.                                                                                                                                                                                                                                                                               |
| `node --version`/`-v`                                                                                                                                                | Allowed.                                                                                                                                                                                                                                                                            |
| `node --check <file>`                                                                                                                                                | File is a read, checked normally.                                                                                                                                                                                                                                                   |
| any other `node` usage                                                                                                                                               | Asks.                                                                                                                                                                                                                                                                               |
| `npm --version`/`-v`, `npm ls`, `npm outdated`, `npm view`                                                                                                           | Allowed.                                                                                                                                                                                                                                                                            |
| `npm audit`                                                                                                                                                          | Allowed; `npm audit fix` asks.                                                                                                                                                                                                                                                      |
| `npm prune`                                                                                                                                                          | Allowed only in `acceptEdits`/`auto`/`bypassPermissions` mode (it modifies `node_modules`); otherwise asks.                                                                                                                                                                         |
| any other `npm` usage                                                                                                                                                | Asks.                                                                                                                                                                                                                                                                               |
| `podman compose logs`, `podman compose ps`, `podman inspect`, `podman logs`, `podman port`, `podman ps`, `podman --version`                                          | Allowed.                                                                                                                                                                                                                                                                            |
| any other `podman` usage                                                                                                                                             | Asks.                                                                                                                                                                                                                                                                               |
| `uv sync`, `uv --version`                                                                                                                                            | Allowed.                                                                                                                                                                                                                                                                            |
| `uv run mypy`                                                                                                                                                        | Always denied (use `uv run ty`).                                                                                                                                                                                                                                                    |
| `uv run basedpyright/pyright/pytest/ruff/ty`                                                                                                                         | Allowed.                                                                                                                                                                                                                                                                            |
| `uv run python --version`                                                                                                                                            | Allowed.                                                                                                                                                                                                                                                                            |
| any other `uv` usage                                                                                                                                                 | Asks.                                                                                                                                                                                                                                                                               |

If parsing the command line fails outright, the whole request is denied ("unparseable command") rather than falling back to ask.
