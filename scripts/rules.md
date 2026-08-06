**Status**: reversed engieneered from code - needs cleanup and to add reasons.

This file describes the rules we want to implement to control the tool calls.
- If two rules contradict each other, **specific** rules take precedence over **generic** ones, then **deny** rules takes precedence over the others.
- In most cases, rules either define `allow` or `deny` behaviors.
  Everything else falls back to `ask`.

> In **auto mode**, any `ask` is converted to a `deny`, so any rule below that depends on the mode (`acceptEdits`, `auto`, `bypassPermissions`) to grant an explicit `allow` is what keeps that operation from being silently dropped in auto mode.


## 1. File rules

### 1.1. No credentials access

The agent is **denied** to **access** (read and write) files containing credentials, whatever their location, including:
- Files with the `.pem`/`.key`/`.p12`/`.pfx`/`.keystore`/`.jks`, `.htpasswd`/`.netrc`/`.npmrc`/`.pgpass` extensions,
- The dotenv (`.env`/`.env.local`/`.env.production`) and usual ssh key (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`) files,
- _TODO: add harness credentials files._
- Any files under `.ssh/`.

Template files (`.example`, `.sample`, `.template` suffix) are exempted from this rule.

**Reason**: Tools results are streamed to an untrusted third party service for LLM inferance while secrets should never be shared anywhere.

### 1.2. No git file modifications

The agent is **denied** to **write** file in any `.git` directory locations, including subfolders.

**Reason**: Modifying git files directly is dangerous and error-prone. git state should only be changed through the git cli.

### 1.3. No harness modifications

The agent is **denied** to **write** file in its harness directory (`~/.claude`).

**Reason**: Modifying the harness files would allow the agent to lift its own restrictions.  

### 1.4. Allowed folders

The agent is **allowed** to **read** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The harness directory (`~/.claude`),
- The current project.

In **edit mode**, the agent is **allowed** to **write** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The current project.

**Reason**: The agent aim is to update the project.
It sometimes also uses temporary files for tests or downloads and may need to read the harness configuration.
Restricting the agent access to the project folder and temporary files allows it to carry its tasks without introducing major risk for the system.


## 2. Bash rules

For bash invocations, the command line is parsed into individual sub-commands (handling pipes, `&&`, subshells, command substitutions, etc.).
Each individual sub-commands is then checked against the rules.

The overall decision for the whole command line is the worst decision across all of the sub-commands (**deny** > **ask** > **allow**).

> When a command is not allowed automatically, the recommendation is to execute it inside a container, mounting the repository as a shared volume when needed (cf. [Containers rules](##containers-rules)).

### 2.1. Only valid commands

If parsing the command line fails outright, the whole request is **denied**.

**Reason**: First, correctly parsing the command is required to validate it. Second, if the command cannot be aprsed, it is probably wrong in the first place and will be rejected by the bash binary. Lastly, wrong commands may mess up the terminal UI.

### 2.2. Intent declaration

A command line that does not carry a meaningful `description` explaining the intent behind that call (why the command is needed) is **denied**.

**Reason**: Clear intent is important for the user to understand the objective in order to validate if the command is adapted to the task and if the impact is proportional to the goal.

### 2.3. Tracking current directory

The `cd` command is **allowed** if the path is resolvable by the hook (ex: absolute or relative path, including simple and safe expansions like `~/`). It is **denied** if the path is NOT resolvable by the hook (ex: substitution or expansion like `$(...)`, `` `...` ``, `$VAR`, arithmetic, ...).

**Reason**: Knowing the current workign directory is required to validate file access in case of relative path.
For any sub-command, the hook must know with certainty the current working directory.

### 2.4. Variable assignment

Bare variable assignments (`FOO=bar`) are **allowed**.

**Reason**: Variable assignments are harmless on their own. They are tracked by the hook for potential impact on other commands (ex: `GIT_DIR` read by the `git` command).

### 2.5. Filesystem access

All files accessed follow the [File rules](##file-rules), including:
- Files defined as input or output by the binary options (ex: `--output <path>`),
- `>`, `>>`, `>|`, `&>`, `&>>` redirects counting as _write_ operations,
- `<`, `<>`, `<<<` redirects counting as _read_ operations,
- fd-dups like `2>&1` and `/dev/null` are ignored.

A path that looks like a glob pattern (`*`, `?`, `[`, `{`, `(`) is expanded against the real filesystem.
Each match is checked with the [File rules](##file-rules).

If any path is built from a substitution or expansion (`$(...)`, `` `...` ``, `$VAR`, arithmetic, ...), the whole command is considered "dynamic", resulting in **ask**, since its real target can't be verified statically.
The following exceptions apply:
- A leading `~` is expanded to the user home.

The overall decision is the worst decision across all matched file (**deny** > **ask** > **allow**).

**Reason**: The agent could bypass the [File rules](##file-rules) with a bash command. Files accessed from the command line must be checked too.

NB: The files rules are not bullet-proof since a rogue agent could still write and execute python code, for example, to read a secret.
But it nudge it in the right direction and avoid to copy the secret in clear text in the LLM messages.
Also, the agent will only be able to bypass the access rules only inside the project folder since code execution is sandboxed in a container.

### 2.6. Sub-shells

Spawning a new shell (`bash`, `sh`, `zsh`, `cmd`, `powershell`, etc.) is **denied**.

**Reason**: Nesting shells is hard to read, debug, and parse while not being required at all most of the time.

### 2.7. Alternative binaries

The `pip` and `pip3` commands are **denied** in favor of `uv`.

The `python` and `python3` commands are **denied** in favor of `uv` (or `uvx`).
Running python from a virtual environment (venv) is also denied.

The `mypy` command is **denied** in favor of `ty` (`uv run ty`).
Running mypy via the `uv` command is also denied.

The `gh` command is **denied** in favor of the github MCP.

**Reason**: This rule is not a security constraint, but more a way to force the agent to respect our standard tools.

### 2.8. Read-only binaries

The `cut`, `echo`, `printf`, `pwd`, `sleep`, `tr`, and `uniq`, binaries are **allowed**
Simple variable substitutions (`$VAR` or `${VAR}`) are **allowed** as argument.

**Reason:** They only print or format information and do not access any file.

For the `cat`, `cmp`, `diff`, `file`, `head`, `jq`, `less`, `ls`, `more`, `sort`, `tail`, `test`, and `wc` binaries, the [File rules](##file-rules) apply.

For the `grep` binary, positional arguments are treated as _read_ accesses, minus the search pattern itself.
The `-f`/`--file` argument value is a _read_ access too.
The [File rules](##file-rules) apply to both.

**Reason:** These commands are similar to a `Read` tool call.


### 2.9. Specific git rules

Git gets specific treatment because it is an important interface for coding and is preferable to do outside a container (especially since `fetch`, `pull`, and `push` commands require credentials that are not in the container).

#### 2.8.1. Git directory

Any `git` command accessing a file outside the current repository is **denied**. This includes:
- Usage of the `-C` option,
- Usage of the `--git-dir` option,
- Defining the `GIT_DIR` environment variable.

**Reason**: The agent should only ever modify the project repository.
Modifying another project is unacceptable and reading files with git could also leak sensitive data.

#### 2.8.2. History security

The following branches are accessible:
- `git push` on the `main` and `master` branches is **denied**.
- It is **allowed** on `feat/` and `fix/` branches (assuming no `-f`/`--force` option).
- Using another branch is an **ask**.

Additionnaly `git push` with the option `-f`/`--force` is **denied** and `git reset` with the `--hard` option is **denied**.

**Reason**: Only maintainers should ever push to the default branch. Allowing an agent to do so is a big gamble. Instead, the agent should create feature and fix branches.
Additionnaly, for defence in depth, the commands that rewrite history are fobidden to ensure a revert action is always possible.

#### 2.8.3. Configuration

Reading git configuration (via the `git config` or `git -c`) is **allowed**.

Writing git configuration (via the same options) is **ask**.

**Reason**: Reading git configuration is usefull for the agent, but modifying it must never happen without the user's consent.

NB: Writing the git configuration files directly is forbidden by the [File rules](##file-rules).

#### 2.8.4. Usual commands

The `git add`, `git checkout`, and `git switch` commands are **allowed**.

The `git commit` command is **allowed**, except when the `--output`/`-o` option is supplied, in which case the [File rules](##file-rules) apply.

The `git reset` command is **allowed** as long as the option `--hard` is not used.

For the `git mv` and `git rm` commands, the [File rules](##file-rules) apply.

**Reason**: The agent is allowed to update the project, and it is actually its main objective.
These commands can update the files, but the history will always keep the previous contents.

#### 2.8.4. Read-only commands

The following commands are **allowed**:
- `git branch` with a fixed set of read-only flags (`--show-current`, `-v`, `--merged`, `--contains`, `--list`...).
- `git remote` for read-only options (`git remote show`, `git remote get-url`, etc.).
- `git check-ignore`, `git diff`, `git grep`, `git hash-object`, `git log`, `git ls-files`, `git ls-tree`, `git rev-parse`, `git show`, `git status`.

**Reason**: Most of these commands are used very often and pose no threat to the system.
Deleting or modifying a branch or a remote is **ask**.

### 2.10. Specific find rules

The `-delete`, `-exec`, `-execdir`, `-fls`, `-fprint`, `-fprint0`, `-fprintf`, `-ok`, and `-okdir` options are **denied** with the `find` command.

Otherwise, the leading search-root arguments are checked against the [File rules](##file-rules).

**Reason:** Find is a standard tool to search files, but it can also execute arbitrary code or change the filesystem with speicifc options.
THe objective is to limit its capabilities to only read files in the authorized perimeter.

### 2.11. Specific node rules

The `node --version`/`node -v` commands are **allowed**.

The `node --check <file>` command is checked against the [File rules](##file-rules).

Any other `node` usage is **ask**.

**Reason:** The `node` command is mostly used to execute javascript code, which should oviously be denied by default.
However, it is also often used by an agent to check if node exists. This is fine and can become annoying for the user to validate every time.
Allowing the agent to format/lint a file in its perimeter is also a good idea.

### 2.12. Specific npm rules

THe following read-only commands are always **allowed**:
- `npm --version` / `npm -v`,
- `npm ls`, `npm outdated`, `npm view`,
- `npm audit` without the `fix` suffix.

In **edit mode**, `npm prune` is also **allowed**.

**Reason:** The `npm` command can be very powerful (or dangerous). But it is also used regularly for good automaton (including security audits).
The aim, here, is to allow usual _and_ safe commands.

### 2.13. Specific podman rules

See [Containers rules](##containers-rules).

### 2.14. Specific sed rules

The `sed` command is **allowed** with a subset of options: `-n`/`--quiet`/`--silent`.

**Reason:** The `sed` command is mostly used to either read or modify sections of a text, but it has also very powerful options (including code execution). Thus it cannot be allowed globaly.
- The aim is to allow simple read operations without coding a complex parser.
- In the future, we may also allow to update a string or a file in **edit mode**.
- Any other option is deemed "too complex to verify" and trigger an **ask**.

### 2.15. Specific uv rules

TODO: copy strategy from npm.
+ allow `uv run python --version`
+ allow `uv run basedpyright/pyright/ruff/ty` (not `pytest`) - need edit mode?

## 3. Containers rules

Using containers is a good way to isolate dangerous or complex commands to ensure that:
- They don't change the host system,
- They don't access data outside a set perimeter.

Thus, agents are requested to run commands in a container when they are nto automatically **allowed**.

### 3.1 Status commands

The following commands are **allowed**:
- `docker inspect`, `docker logs`, `docker port`, `docker ps`, `docker --version`,
- `docker compose logs`, `docker compose ps`,
- `podman inspect`, `podman logs`, `podman port`, `podman ps`, `podman --version`,
- `podman compose logs`, `podman compose ps`.

**Reason:** These commands are required to get the current status and debug potential errors.
They are harmless (except maybe if there is sensitive data in the logs).

### 3.1 Running a container

The following options are specifically **denied**:
--cap-add
--device
--privileged
--security-opt
--user root / -u 0

The `docker run` and `podman run` commands are **allowed** with the following restrictions:
--volume/-v, --mount, --volumes-from, --tmpfs
:rw :z/:Z --mount type=bind,src=...,dst=...,readonly
- 
Anything else is an **ask**.

**Reason:** The aim here is to allow the agent to run any command in any container, but to only be able to bind the project volume to ensure the untrusted command cannot change the host outside the project.

### 3.1 Buildig an image

The `docker build` and `podman build` commands are **allowed** with the following restrictions:
- 
Anything else is an **ask**.

**Reason:** Building and testing docker images are a normal part of the development process. It may also be useful for running complex command/programs isolated in a container.
