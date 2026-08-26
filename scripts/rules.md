This file describes the rules we want to implement to control the tool calls.
- If two rules contradict each other, **specific** rules take precedence over **generic** ones, then **deny** rules take precedence over the others.
- Any behavior not listed falls back to `ask` (`deny` in **auto mode**).


## Modes

Every call runs in exactly one mode, derived from the harness permission mode:
- In **manual** mode, only reads are automatically **allowed** based on the [File rules](#1-file-rules).
  This mode corresponds to the `default` and `plan` permission modes from claude code.
- In **edit** mode, reads and writes are automatically **allowed** based on the [File rules](#1-file-rules).
  This mode corresponds to the `acceptEdits` permission mode from claude code.
- The **auto** mode **allows** the same calls as the **edit** mode, but also transforms any **ask** into a **deny**, effectively forbidding interractive validations.
  This mode corresponds to any permission mode from claude code that does not already fall into the other two modes.


## 1. File rules

### 1.1. No credentials access

The agent is **denied** to **access** (read and write) files containing credentials, whatever their location, including:
- Files with the `.pem`/`.key`/`.p12`/`.pfx`/`.keystore`/`.jks`, `.htpasswd`/`.netrc`/`.npmrc`/`.pgpass` extensions/names,
- The dotenv (`.env`/`.env.local`/`.env.production`) and usual ssh key (`id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`) files,
- The harness credentials files (`.credentials.json` holding the OAuth tokens, `.claude.json` holding the account identity and the MCP servers environment, and `~/.claude/sessions/*.key` files),
- Any files under `.ssh/`.

Template files (`.example`, `.sample`, `.template` suffix) are exempted from this rule.

**Reason**: Tool results are streamed to an untrusted third party service for LLM inference while secrets should never be shared anywhere.

NB: The harness _configuration_ files (`settings.json`, `.mcp.json`, ...) are not covered: the agent legitimately reads them (cf. §1.4) and they are not supposed to hold secrets.

### 1.2. No git file modifications

The agent is **denied** to **write** files in any `.git` directory locations, including subfolders.

**Reason**: Modifying git files directly is dangerous and error-prone. git state should only be changed through the git cli.

### 1.3. No harness modifications

The agent is **denied** to **write** files in its harness directory (`~/.claude`).

**Reason**: Modifying the harness files would allow the agent to lift its own restrictions.  

When the project directory _is_ the harness directory, **write** are **ask** in **manual** mode and **allowed** in the other modes.

### 1.4. Allowed folders

The agent is **allowed** to **read** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The harness directory (`~/.claude`),
- The current project.

In **edit mode**, the agent is **allowed** to **write** files in the following locations, including subfolders (with exceptions listed above):
- The temporary directories (`/tmp`, `/var/tmp`, etc.),
- The current project (including the harness if it is the project directory - cf. §1.3).

**Reason**: The agent aim is to update the project.
It sometimes also uses temporary files for tests or downloads and may need to read the harness configuration.
Restricting the agent access to the project folder and temporary files allows it to carry its tasks without introducing major risk for the system.


## 2. Bash rules

For bash invocations, the command line is parsed into individual sub-commands (handling pipes, `&&`, subshells, command substitutions, etc.).
Each individual sub-command is then checked against the rules.

The overall decision for the whole command line is the worst decision across all of the sub-commands (**deny** > **ask** > **allow**).

> When a command is not allowed automatically, the recommendation is to execute it inside a container, mounting the repository as a shared volume when needed (cf. [Containers rules](#3-containers-rules)).

### 2.1. Only valid commands

If parsing the command line fails outright, the whole request is **denied**.

**Reason**: First, correctly parsing the command is required to validate it. Second, if the command cannot be parsed, it is probably wrong in the first place and will be rejected by the bash binary. Lastly, wrong commands may mess up the terminal UI.

### 2.2. Intent declaration

A command line that does not carry a meaningful `description` explaining the intent behind that call (why the command is needed) is **denied**.

**Reason**: Clear intent is important for the user to understand the objective in order to validate if the command is adapted to the task and if the impact is proportional to the goal.

### 2.3. Current directory

The `cd`, `pushd`, and `popd` commands are **allowed** only when they are the single command of the bash call (they are **denied** as soon as anything else shares the call).
The hook makes no attempt to guess or track the target directory. It only defines the current directory as the one the harness reports in the call payload.

Moving outside the project is **allowed**: the move itself discloses little, and every later access is still checked against the unchanged project directory.

Redirects still follow the [File rules](#1-file-rules) (ex: `cd /tmp > .env` is **denied**).

**Reason**: Knowing the current working directory is required to validate file access in case of relative path.
Simulating the shell's moves is both complex and unreliable (symlink canonicalization, subshell isolation, `$OLDPWD`, targets directory deleted or unaccessible...).
Trusting the payload and keeping the `cd` alone gives the same guarantee for a fraction of the code.

NB: The current directory and the project directory are two different things: the first anchors relative paths and follows the agent's `cd` calls, the second is the perimeter of the [File rules](#1-file-rules) and never moves.

### 2.4. Variable assignment

Bare variable assignments (`FOO=bar`) are **allowed**.

**Reason**: Variable assignments are harmless on their own. They are tracked by the hook for potential impact on other commands (ex: `GIT_DIR` read by the `git` command).

### 2.5. Filesystem access

All files accessed follow the [File rules](#1-file-rules), including:
- Files defined as input or output by the binary options (ex: `--output <path>`),
- `>`, `>>`, `>|`, `&>`, `&>>` redirects counting as _write_ operations,
- `<`, `<>`, `<<<` redirects counting as _read_ operations,
- fd-dups like `2>&1` and `/dev/null` are ignored.

A path that looks like a glob pattern (`*`, `?`, `[`, `{`, `(`) is expanded against the real filesystem.
Each match is checked with the [File rules](#1-file-rules).

If any path is built from a substitution or expansion (`$(...)`, `` `...` ``, `$VAR`, arithmetic, ...), the whole command is considered "dynamic", resulting in **ask**, since its real target can't be verified statically.
The following exceptions apply:
- A leading `~` is expanded to the user home.

The overall decision is the worst decision across all matched files (**deny** > **ask** > **allow**).

**Reason**: The agent could bypass the [File rules](#1-file-rules) with a bash command. Files accessed from the command line must be checked too.

NB: The files rules are not bullet-proof since a rogue agent could still write and execute python code, for example, to read a secret.
But it nudges it in the right direction and avoids copying the secret in clear text in the LLM messages.
Also, the agent will only be able to bypass the access rules inside the project folder since code execution is sandboxed in a container.

### 2.6. Sub-shells

Spawning a new shell (`bash`, `sh`, `zsh`, `cmd`, `powershell`, etc.) is **denied**.

The `exec`, `eval`, `source` and `.` commands are also **denied**.

**Reason**: Nesting shells is hard to read, debug, and parse while not being required at all most of the time.

### 2.7. Alternative binaries

The `gh` command is **denied** in favor of the github MCP.

**Reason**: This rule is not a security constraint, but more a way to force the agent to respect our standard tools.

### 2.8. Read-only binaries

The `echo`, `printf`, `pwd`, `sleep`, and `tr` binaries are **allowed**.
Simple variable substitutions (`$VAR` or `${VAR}`) are **allowed** as argument to these commands.

**Reason:** They only print or format information and do not access any file.

For the `cat`, `cmp`, `cut`, `diff`, `file`, `head`, `jq`, `less`, `ls`, `more`, `tail`, `test`, and `wc` binaries, the [File rules](#1-file-rules) apply.

For the `grep` binary, positional arguments are treated as _read_ accesses, minus the search pattern itself.
The `-f`/`--file` argument value is a _read_ access too.
The [File rules](#1-file-rules) apply to both.

**Reason:** These commands are similar to a `Read` tool call.


### 2.9. Specific git rules

Git gets specific treatment because it is an important interface for coding and is preferable to do outside a container (especially since `fetch`, `pull`, and `push` commands require credentials that are not in the container).

#### 2.9.1. Git directory

Any `git` command accessing a file outside the current repository is **denied**. This includes:
- Usage of the `-C` option,
- Usage of the `--git-dir` option,
- Defining the `GIT_DIR` environment variable.

**Reason**: The agent should only ever modify the project repository.
Modifying another project is unacceptable and reading files with git could also leak sensitive data.

#### 2.9.2. History security

The following branch rules apply:
- Pushing on the `main` and `master` branches is **denied**.
- Pushing is **allowed** on `feat/` and `fix/` branches (assuming no `-f`/`--force` option).
- Using another branch is an **ask**.

Additionally, `git push` with the option `-f`/`--force`, and `git reset` with the `--hard` option are **denied**.

**Reason**: Only maintainers should ever push to the default branch. Allowing an agent to do so is a big gamble. Instead, the agent should create feature and fix branches.
Additionally, for defence in depth, the commands that rewrite history are forbidden to ensure a revert action is always possible.

#### 2.9.3. Configuration

Reading git configuration (via the `git config`) is **allowed**.

Writing git configuration (via the same option or `git -c`) is **ask**.

**Reason**: Reading git configuration is useful for the agent, but modifying it must never happen without the user's consent.

NB: Writing the git configuration files directly is forbidden by the [File rules](#1-file-rules).

#### 2.9.4. Usual commands

The `git add`, `git checkout`, and `git switch` commands are **allowed**.

The `git commit` command is **allowed**, except when the `--only`/`-o` option is supplied, in which case the [File rules](#1-file-rules) apply.

The `git reset` command is **allowed** as long as the option `--hard` is not used.

For the `git mv` and `git rm` commands, the [File rules](#1-file-rules) apply.

**Reason**: The agent is allowed to update the project, and it is actually its main objective.
These commands can update the files, but the history will always keep the previous contents (assuming they were committed).

#### 2.9.5. Read-only commands

The following commands are **allowed**:
- `git branch` with a fixed set of read-only flags (`--show-current`, `-v`, `--merged`, `--contains`, `--list`...).
- `git remote` for read-only options (`git remote show`, `git remote get-url`, etc.).
- `git check-ignore`, `git diff`, `git grep`, `git log`, `git ls-files`, `git ls-tree`, `git rev-parse`, `git show`, `git status`.

**Reason**: Most of these commands are used very often and pose no threat to the system.
Deleting or modifying a branch or a remote is **ask**.

### 2.10. Specific find rules

The `-delete`, `-exec`, `-execdir`, `-fls`, `-fprint`, `-fprint0`, `-fprintf`, `-ok`, and `-okdir` options are **denied** with the `find` command.

Otherwise, the leading search-root arguments are checked against the [File rules](#1-file-rules).

**Reason:** Find is a standard tool to search files, but it can also execute arbitrary code or change the filesystem with specific options.
The objective is to limit its capabilities to only read files in the authorized perimeter.

### 2.11. Specific node rules

The `node --version`/`node -v` commands are **allowed**.

The `node --check <file>` command is checked against the [File rules](#1-file-rules).

Any other `node` usage is **ask**.

**Reason:** The `node` command is mostly used to execute javascript code, which should obviously be denied by default.
However, it is also often used by an agent to check if node exists. This is fine and can become annoying for the user to validate every time.
Allowing the agent to format/lint a file in its perimeter is also a good idea.

### 2.12. Specific npm rules

The following read-only commands are always **allowed**:
- `npm --version` / `npm -v`,
- `npm ls`, `npm outdated`, `npm view`,
- `npm audit` without the `fix` subcommand.

In **edit mode**, `npm prune` is also **allowed**.

**Reason:** The `npm` command can be very powerful (or dangerous). But it is also used regularly for good automation (including security audits).
The aim, here, is to allow usual _and_ safe commands.

### 2.13. Specific docker/podman rules

See [Containers rules](#3-containers-rules).

### 2.14. Specific sed rules

The `sed` command is **allowed** with a subset of options: `-n`/`--quiet`/`--silent`.

**Reason:** The `sed` command is mostly used to either read or modify sections of a text, but it has also very powerful options (including code execution). Thus it cannot be allowed globally.
- The aim is to allow simple read operations without coding a complex parser.
- In the future, we may also allow to update a string or a file in **edit mode**.
- Any other option is deemed "too complex to verify" and triggers an **ask**.

## 3. Containers rules

Using containers is a good way to isolate dangerous or complex commands to ensure that:
- They don't change the host system,
- They don't access data outside a set perimeter.

Thus, agents are requested to run commands in a container when they are not automatically **allowed**.

> The rules below only mention the docker version of each command for concision, but the podman equivalent is also allowed/denied at the same time.
> The legacy `docker-compose`/`podman-compose` binaries are treated as `docker compose`.

### 3.1. Global commands

The following global `compose` options (`docker compose -f compose.yml up`) are **allowed**:
`--ansi`,
`--dry-run`,
`--env-file` (path is subject to the [File rules](#1-file-rules)),
`-f`/`--file` (path is subject to the [File rules](#1-file-rules)),
`--parallel`,
`--profile`,
`--progress`,
`-p`/`--project-name`.

Any other global option (including `--project-directory`) is an **ask**.

**Reason**: These options are needed to target the right compose project, and their files can be verified.
- `--dry-run` only simulates the command, so it is usually safe and can never do more than the "no dry-run" command anyway.
- `--project-directory` is excluded because it re-anchors every relative path of the compose file (build contexts, volumes).

### 3.2. Status commands

The following commands are **allowed** for both `docker` and `podman`:
- `docker compose config`,
- `docker compose logs`,
- `docker compose ls`/`docker compose ps`,
- `docker compose images`,
- `docker compose port`,
- `docker compose stats`,
- `docker compose top`,
- `docker compose version`,
- `docker compose volumes`,
- `docker config inspect`,
- `docker config ls`/`docker config list`,
- `docker container inspect`,
- `docker container logs`/`docker logs`,
- `docker container list`/`docker container ls`/`docker container ps`/`docker ps`,
- `docker container port`/`docker port`,
- `docker container stats`/`docker stats`,
- `docker container top`/`docker top`,
- `docker inspect`,
- `docker image inspect`,
- `docker image ls`/`docker image list`/`docker images`,
- `docker network inspect`,
- `docker network list`/`docker network ls`,
- `docker system df`,
- `docker system info`/`docker info`,
- `docker version`/`docker --version`,
- `docker volume inspect`,
- `docker volume ls`/`docker volume list`.

**Reason:** These commands are required to get the current status and debug potential errors.
They are harmless (except maybe if there is sensitive data in the logs).

### 3.3. Running a container

The following options are specifically **denied**:
- `--cap-add`,
- `--device`,
- `--privileged`,
- `--security-opt`,
- `--user root / -u 0`.

**Reason:** These options (may) allow to escape the sandboxed container into the host.

The following commands are **allowed** (as long as they don't use one of the above options):
- `docker compose create`,
- `docker compose down`,
- `docker compose kill`,
- `docker compose pause`,
- `docker compose restart`,
- `docker compose rm`,
- `docker compose start`,
- `docker compose stop`,
- `docker compose unpause`,
- `docker compose up`,
- `docker compose wait`,
- `docker container kill`/`docker kill`,
- `docker container pause`/`docker pause`,
- `docker container prune`,
- `docker container remove`/`docker container rm`/`docker rm`,
- `docker container restart`/`docker restart`,
- `docker container start`/`docker start`,
- `docker container stop`/`docker stop`,
- `docker container unpause`/`docker unpause`,
- `docker container wait`/`docker wait`,
- `docker network connect`,
- `docker network create`,
- `docker network disconnect`,
- `docker network remove`/`docker network rm`,
- `docker volume remove`/`docker volume rm`,
- `docker network prune`,
- `docker system prune`,
- `docker volume prune`.

**Reason:** These commands can modify containers, images, and other docker objects, but will not corrupt the host system. Some of them are also widely and regularly used in a normal development lifecycle.

The `docker compose exec`, `docker compose run`, `docker container create`/`docker create`, `docker container exec`/`docker exec`, `docker container run`/`docker run` commands are **allowed** but only the project directory and volumes from other containers can be mounted as a volume (`--volume`/`-v`, `--mount`, `--volumes-from` options) and only with the following options (any other option - except the ones denied above - is **ask**):
- `-d`/`--detach`,
- `--dry-run` (compose only, cf. §3.1),
- `--entrypoint`,
- `-e`/`--env`,
- `--env-file`,
- `--expose`,
- `--health-cmd`,
- `--health-interval`,
- `--health-retries`,
- `--health-start-interval`,
- `--health-start-period`,
- `--health-timeout`,
- `--help`,
- `-i`/`--interactive`,
- `--name`,
- `--network`,
- `--network-alias`,
- `--no-healthcheck`,
- `-p`, `--publish`,
- `-P`, `--publish-all`,
- `--pull`,
- `-q`/`--quiet`,
- `--read-only`,
- `--restart`,
- `--rm`,
- `--stop-timeout`,
- `--tmpfs`,
- `-w`/`--workdir`.

The `docker volume create` command is **allowed** as long as it only references the project directory.

The `docker compose cp` and `docker container cp`/`docker cp` commands are **allowed** as long as they only reference files compatible with the [File rules](#1-file-rules).
The container side of the copy (`service:/path`) is not checked: it is inside the sandbox.

**Reason:** The aim here is to allow the agent to run any command in any _isolated_ container, allowing to bind only the project directory to ensure the untrusted command cannot change the host outside of the project files.

NB: everything after the container/service/image name is the container's own argv: it runs inside the sandbox. These options are not checked.

### 3.4. Building an image

The `docker build` and `docker buildx` commands are **allowed**, as long as they only reference files inside the project, and with the following options (any other option is **ask**):
- `--build-arg`,
- `--build-context` (path is subject to the [File rules](#1-file-rules)),
- `--cache-from` (path is subject to the [File rules](#1-file-rules)),
- `--cache-to` (path is subject to the [File rules](#1-file-rules)),
- `-f`/`--file` (path is subject to the [File rules](#1-file-rules)),
- `--iidfile` (path is subject to the [File rules](#1-file-rules)),
- `--label`,
- `--metadata-file` (path is subject to the [File rules](#1-file-rules)),
- `--no-cache`,
- `--no-cache-filter`,
- `-o`/`--output` (path is subject to the [File rules](#1-file-rules)),
- `--pull`,
- `-q`/`--quiet`,
- `--resource`,
- `-t`/`--tag`,
- `--target`.

The following commands are **allowed**:
- `docker compose pull`,
- `docker image pull`/`docker pull`,
- `docker image rm`/`docker image remove`/`docker rmi`,
- `docker image prune`.

**Reason:** Building and testing docker images are a normal part of the development process. It may also be useful for running complex command/programs isolated in a container.
