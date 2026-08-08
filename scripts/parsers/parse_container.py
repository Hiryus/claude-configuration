import re
from pathlib import Path

from model import Argument, Command, Decision, Mode, Reference
from utils import check_access, format_references, in_project, worst

# ============================================================================
# Command shape
# ============================================================================

# Objects introducing an `<object> <verb>` pair, ex: `docker container ls`.
OBJECTS = ["compose", "config", "container", "image", "network", "system", "volume"]

# Shortcuts: `docker <verb>` is an alias for `docker <object> <verb>`.
SHORTCUTS = {
    "cp": ("container", "cp"),
    "create": ("container", "create"),
    "exec": ("container", "exec"),
    "images": ("image", "ls"),
    "info": ("system", "info"),
    "kill": ("container", "kill"),
    "logs": ("container", "logs"),
    "pause": ("container", "pause"),
    "port": ("container", "port"),
    "ps": ("container", "ls"),
    "pull": ("image", "pull"),
    "restart": ("container", "restart"),
    "rm": ("container", "rm"),
    "rmi": ("image", "rm"),
    "run": ("container", "run"),
    "start": ("container", "start"),
    "stats": ("container", "stats"),
    "stop": ("container", "stop"),
    "top": ("container", "top"),
    "unpause": ("container", "unpause"),
    "wait": ("container", "wait"),
}

# Different spellings of the same verb, ex: `docker image list` == `docker image ls`.
VERB_ALIASES = {
    "list": "ls",
    "ps": "ls",
    "remove": "rm",
}

# ============================================================================
# Option tables
# ============================================================================

# Short options that may be glued to their value, ex: `-u0`, `-p8080:80`.
SHORT_VALUE_OPTS = ["-e", "-f", "-o", "-p", "-t", "-u", "-v", "-w"]

# Rule 3.1: global `compose` options. The verbs inherit them, so they may sit on
# either side (`docker compose -f x.yml up` == `docker compose up -f x.yml`);
# both positions get their paths vetted.
HEAD_OPTS = ["--ansi", "--env-file", "-f", "--file", "-p", "--parallel", "--profile", "--progress", "--project-name"]
HEAD_VALUE_OPTS = [*HEAD_OPTS, "--project-directory"]
HEAD_PATH_OPTS = ["--env-file", "-f", "--file"]

# Asking for the version, ex: `docker --version`, `docker -v`.
VERSION_OPTS = ["--version", "-v"]

# Options that (may) hand the container a way out of its sandbox.
DENIED_OPTS = ["--cap-add", "--device", "--privileged", "--security-opt"]
DENIED_VALUE_OPTS = ["--cap-add", "--device", "--security-opt", "-u", "--user"]
ROOT_USERS = ["0", "root"]

# `run`/`exec` options.
RUN_VALUE_OPTS = [
    "--entrypoint", "-e", "--env", "--env-file", "--expose", "--health-cmd",
    "--health-interval", "--health-retries", "--health-start-interval",
    "--health-start-period", "--health-timeout", "--name", "--network",
    "--network-alias", "-p", "--publish", "--pull", "--restart", "--stop-timeout",
    "--tmpfs", "-w", "--workdir", "-v", "--volume", "--mount", "--volumes-from",
    *DENIED_VALUE_OPTS,
]
RUN_FLAG_OPTS = [
    "-d", "--detach", "--help", "--no-healthcheck", "-P", "--publish-all",
    "-q", "--quiet", "--read-only", "--rm",
]
RUN_ALLOWED_OPTS = [x for x in RUN_VALUE_OPTS + RUN_FLAG_OPTS if x not in DENIED_VALUE_OPTS]

# `build`/`buildx build` options allowed by the rules.
BUILD_VALUE_OPTS = [
    "--build-arg", "--build-context", "--cache-from", "--cache-to", "-f", "--file",
    "--iidfile", "--label", "--metadata-file", "--no-cache-filter", "-o", "--output",
    "--resource", "-t", "--tag", "--target",
]
BUILD_FLAG_OPTS = ["--no-cache", "--pull", "-q", "--quiet"]
BUILD_ALLOWED_OPTS = BUILD_VALUE_OPTS + BUILD_FLAG_OPTS

# Build options naming a host file, and how the build touches it.
BUILD_READ_OPTS = ["--build-context", "--cache-from", "-f", "--file"]
BUILD_WRITE_OPTS = ["--cache-to", "--iidfile", "--metadata-file", "-o", "--output"]

# Used when the family imposes no option allow-list: only value pairing matters.
ANY_VALUE_OPTS = sorted(set(HEAD_VALUE_OPTS + RUN_VALUE_OPTS))

# ============================================================================
# Allow-lists, by canonical `(object, verb)` pair
# ============================================================================

# Rule 3.2: report on the current state, change nothing.
STATUS_COMMANDS = [
    ("", "inspect"), ("", "version"),
    ("compose", "config"), ("compose", "images"), ("compose", "logs"),
    ("compose", "ls"), ("compose", "port"), ("compose", "stats"),
    ("compose", "top"), ("compose", "version"), ("compose", "volumes"),
    ("config", "inspect"), ("config", "ls"),
    ("container", "inspect"), ("container", "logs"), ("container", "ls"),
    ("container", "port"), ("container", "stats"), ("container", "top"),
    ("image", "inspect"), ("image", "ls"),
    ("network", "inspect"), ("network", "ls"),
    ("system", "df"), ("system", "info"),
    ("volume", "inspect"), ("volume", "ls"),
]

# Rules 3.3 and 3.4: mutate docker objects, but never the host filesystem.
MANAGE_COMMANDS = [
    ("compose", "create"), ("compose", "down"), ("compose", "kill"), ("compose", "pause"),
    ("compose", "pull"), ("compose", "restart"), ("compose", "rm"),
    ("compose", "start"), ("compose", "stop"), ("compose", "unpause"),
    ("compose", "up"), ("compose", "wait"),
    ("container", "kill"), ("container", "pause"), ("container", "prune"),
    ("container", "restart"), ("container", "rm"), ("container", "start"),
    ("container", "stop"), ("container", "unpause"), ("container", "wait"),
    ("image", "prune"), ("image", "pull"), ("image", "rm"),
    ("network", "connect"), ("network", "create"), ("network", "disconnect"),
    ("network", "prune"), ("network", "rm"),
    ("system", "prune"),
    ("volume", "prune"), ("volume", "rm"),
]

# Rule 3.3: run a command in a container. Restricted options, project-only
# mounts. `create` is the same command as `run`, minus the start.
RUN_COMMANDS = [
    ("compose", "exec"), ("compose", "run"),
    ("container", "create"), ("container", "exec"), ("container", "run"),
]

# Rule 3.3: copy to/from a container. The host side follows the file rules.
COPY_COMMANDS = [("compose", "cp"), ("container", "cp")]

# ============================================================================
# Argument walking
# ============================================================================

def split_short(key: str) -> tuple[str, str] | None:
    """
    Split a short option glued to its value (`-u0` -> `-u`, `0`). Clusters of
    flags (`-it`) are left alone: none of them takes a value.
    """
    if len(key) > 2 and key.startswith("-") and not key.startswith("--") and key[:2] in SHORT_VALUE_OPTS:
        return (key[:2], key[2:])
    return None

def resolve_option(args: list[Argument], index: int, value_opts: list[str] | None) -> tuple[str, str | None, int]:
    """
    Read the option at `index` with its value, whether glued (`-v=x`, `-vx`) or
    given as the next word (`-v x`). Returns the index of the next argument.

    The next word is only taken as a value when it is not an option itself:
    `value_opts` is the union of several verbs' tables, so a flag that takes no
    value in the actual verb would otherwise swallow the option behind it
    (`docker rm -v --privileged web`). A `None` table pairs every option.
    """
    key, value = args[index].key or "", args[index].value
    if value is None and (glued := split_short(key)):
        key, value = glued
    if value is None and (value_opts is None or key in value_opts) and index + 1 < len(args) and args[index + 1].positional:
        value = args[index + 1].value
        index += 1
    return key, value, index + 1

def resolve_options(args: list[Argument], value_opts: list[str] | None, stop_at_positional: bool = False) -> tuple[list[tuple[str, str | None]], list[str]]:
    """
    Pair every option of `args` with its value and collect the positionals.

    With `stop_at_positional`, parsing ends on the first positional: for
    `run`/`exec` that word is the image (or service), and everything after it is
    the *container's* own argv. It runs inside the sandbox, so it is neither a
    docker option nor a host path and must not be checked as one.
    """
    options: list[tuple[str, str | None]] = []
    positionals: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.positional:
            positionals.append(arg.value or "")
            index += 1
            if stop_at_positional:
                break
            continue
        if arg.key == "--":
            positionals.extend(x.value or "" for x in args[index + 1:])
            break
        key, value, index = resolve_option(args, index, value_opts)
        options.append((key, value))
    return options, positionals

def split_head(args: list[Argument], legacy_compose: bool) -> tuple[list[tuple[str, str | None]], list[str], list[Argument]]:
    """
    Walk the leading arguments up to the `<object> <verb>` pair, resolving the
    options that come before it (`docker compose -f compose.yml up`).
    Returns the head options, the pair, and the arguments left to parse.
    """
    head: list[tuple[str, str | None]] = []
    positionals: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.positional:
            positionals.append(arg.value or "")
            index += 1
            expected = 1 if legacy_compose or positionals[0].lower() not in OBJECTS else 2
            if len(positionals) >= expected:
                break
            continue
        key, value, index = resolve_option(args, index, HEAD_VALUE_OPTS)
        head.append((key, value))
    return head, positionals, args[index:]

def normalize(positionals: list[str]) -> tuple[str, str]:
    """
    Reduce a command to its canonical `(object, verb)` pair, so that the aliases
    (`docker ps` == `docker container ls` == `docker container list`) collapse.
    """
    if not positionals:
        return ("", "")
    head = positionals[0].lower()
    if head in OBJECTS:
        verb = positionals[1].lower() if len(positionals) > 1 else ""
        return (head, VERB_ALIASES.get(verb, verb))
    if head in SHORTCUTS:
        return SHORTCUTS[head]
    return ("", VERB_ALIASES.get(head, head))

# ============================================================================
# Path extraction
# ============================================================================

DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")

def is_host_path(text: str) -> bool:
    """
    True for a bind-mount source. A bare name (`mydata`) is a docker-managed
    named volume: it exposes nothing of the host, so it is not a path.
    """
    if not text or "://" in text:
        return False
    return text in (".", "..") or text.startswith(("/", "./", "../", "~", ".\\", "..\\")) or bool(DRIVE_RE.match(text))

def split_volume(value: str) -> tuple[str, str]:
    """
    Split `src:dst[:opts]`, keeping a leading Windows drive letter attached.
    Returns ("", "") when there is no source, ex: `-v /data` (anonymous volume).
    """
    parts = value.split(":")
    if len(parts) >= 2 and len(parts[0]) == 1 and parts[0].isalpha():
        parts = [f"{parts[0]}:{parts[1]}", *parts[2:]]
    if len(parts) < 2:
        return ("", "")
    return (parts[0], parts[2] if len(parts) > 2 else "")

def parse_csv_pairs(value: str) -> list[tuple[str, str]]:
    """
    Parse the `k=v,k=v` syntax shared by `--mount`, `--cache-from`, `-o`, ...
    A bare token (`readonly`) is stored with an empty value. A key may repeat
    (`volume-opt=o=bind,volume-opt=device=/etc`), hence the pairs.
    """
    pairs = []
    for token in value.split(","):
        key, _, val = token.partition("=")
        pairs.append((key.strip().lower(), val.strip()))
    return pairs

def parse_csv(value: str) -> dict[str, str]:
    """
    Same, keyed by name: for the descriptors whose keys cannot repeat.
    """
    return dict(parse_csv_pairs(value))

# `--mount` types whose source names a docker object, not a host path.
SANDBOXED_MOUNT_TYPES = ["devpts", "image", "ramfs", "tmpfs", "volume"]

# Spellings the runtime reads as "true" for the `ro`/`readonly` mount fields.
# `--mount ...,ro` (no `=`) is stored with an empty value, so "" counts as true.
READONLY_VALUES = ["", "true", "1", "t", "y", "yes"]

def mount_mode(fields: dict[str, str]) -> Mode:
    """
    How a `--mount` exposes its source. Read-only is an allow-list: any other
    spelling (`ro=False`, `ro=f`, ...) is a read-write mount, which is both what
    the runtime does and the safe side -- Mode.READ is the weaker verdict.
    `ro` and `readonly` are the same field, so a mount is only read-only when
    every spelling used says so.
    """
    flags = [fields[name] for name in ("ro", "readonly") if name in fields]
    return Mode.READ if flags and all(flag.lower() in READONLY_VALUES for flag in flags) else Mode.WRITE

def mount_references(key: str, value: str) -> list[Reference]:
    """
    The host paths a `run`/`exec` option exposes to the container.
    """
    if key in ("-v", "--volume"):
        source, options = split_volume(value)
        if is_host_path(source):
            return [Reference(mode=Mode.READ if "ro" in options.split(",") else Mode.WRITE, text=source)]
        return []
    if key == "--mount":
        pairs = parse_csv_pairs(value)
        fields = dict(pairs)
        # `source` and `src` are the same field: the runtime keeps the last one,
        # so both values are vetted rather than guessing which one wins.
        sources = [fields[name] for name in ("source", "src") if fields.get(name)]
        mode = mount_mode(fields)
        # A bind source is always a host path, resolved against the cwd: a bare
        # name (`source=.env`) is a file here, not a named volume as with `-v`.
        # The types that expose nothing of the host are the allow-list: `glob`
        # binds too, an unknown or missing type is read as a bind (docker
        # defaults it to `volume`, podman to `bind`; only that way is safe).
        if fields.get("type", "bind").lower() not in SANDBOXED_MOUNT_TYPES:
            return [Reference(mode=mode, text=source) for source in sources]
        # A named volume can bind a host directory too, through its driver
        # options (`type=volume,volume-opt=o=bind,volume-opt=device=/etc`).
        references = []
        for name, option in pairs:
            option_key, _, option_value = option.partition("=")
            if name == "volume-opt" and option_key.strip().lower() == "device" and option_value.strip():
                references.append(Reference(mode=mode, text=option_value.strip()))
        return references
    return []

def is_path_value(text: str) -> bool:
    """
    Unlike a volume source, a build path is a plain path: a bare name is
    cwd-relative, not a named volume. Only a URL or `-` (stdin) is not a file.
    """
    return bool(text) and text != "-" and "://" not in text

def build_references(key: str, value: str) -> list[Reference]:
    """
    The host paths a `build` option reads from or writes to. The value may be a
    plain path (`-f Dockerfile`), a named context (`--build-context ctx=./dir`)
    or a CSV descriptor (`--cache-to type=local,dest=./cache`).
    """
    if key not in BUILD_READ_OPTS + BUILD_WRITE_OPTS:
        return []  # ex: `--tag`, `--target`, `--build-arg`: no file involved
    mode = Mode.READ if key in BUILD_READ_OPTS else Mode.WRITE
    if key == "--build-context":
        path = value.partition("=")[2] if "=" in value else value
        return [Reference(mode=mode, text=path)] if is_path_value(path) else []
    if "=" in value:
        fields = parse_csv(value)
        paths = [fields.get(name, "") for name in ("src", "source", "dest", "destination")]
        return [Reference(mode=mode, text=path) for path in paths if is_path_value(path)]
    return [Reference(mode=mode, text=value)] if is_path_value(value) else []

# ============================================================================
# Checks
# ============================================================================

def check_denied_options(options: list[tuple[str, str | None]], label: str) -> tuple[Decision, str] | None:
    for key, value in options:
        if key in DENIED_OPTS:
            return (Decision.DENY, f"Do not use `{key}` with `{label}`: it lets the container escape its sandbox.")
        if key in ("-u", "--user") and (value or "").split(":")[0].lower() in ROOT_USERS:
            return (Decision.DENY, f"Do not run `{label}` as root: it lets the container escape its sandbox.")
    return None

def check_mounts(mounts: list[Reference], project_root: Path, label: str) -> tuple[Decision, str] | None:
    """
    Rule 3.3: only the project directory may be mounted. This is stricter than
    the file rules on purpose -- `/tmp` and `~/.claude` are readable by the
    agent, but handing them to an untrusted container is another matter.
    """
    if outside := [x.text for x in mounts if not in_project(x.text, project_root)]:
        return (Decision.ASK, f"`{label}` mounts {format_references(outside)} outside the project.")
    return None

def allowed(command: Command, references: list[Reference], project_root: Path, label: str) -> tuple[Decision, str]:
    """
    Allow the command unless one of the host paths it touches is off-limits.
    """
    decision, reason = check_access(command, references, project_root)
    if decision is Decision.ALLOW:
        return (Decision.ALLOW, f"The `{label}` command is allowed.")
    return (decision, reason)

def check_run(command: Command, args: list[Argument], project_root: Path, label: str) -> tuple[Decision, str]:
    """
    Rule 3.3: an isolated container may run anything, as long as the only host
    directory it can reach is the project one.
    """
    options, _ = resolve_options(args, RUN_VALUE_OPTS, stop_at_positional=True)
    if any(key not in RUN_ALLOWED_OPTS for key, _ in options):
        # An unknown option is not paired with its value, so that value reads as
        # the image name and ends the walk, hiding every word behind it. Re-read
        # the line pairing every option, so that neither an escape option nor a
        # file can hide there. Docker only takes options before the image, so
        # stopping at the first positional still leaves the container argv out.
        options, _ = resolve_options(args, None, stop_at_positional=True)
    if denial := check_denied_options(options, label):
        return denial
    references = []  # files the host reads for the container, ex: `--env-file`
    mounts = []      # host paths the container itself can reach
    pending = None
    for key, value in options:
        if key not in RUN_ALLOWED_OPTS:
            pending = pending or (Decision.ASK, f"The `{key}` option of `{label}` is not allowed by default.")
            continue
        if key == "--volumes-from":
            pending = pending or (Decision.ASK, f"`{label}` reuses the volumes of another container; cannot verify what they expose.")
            continue
        if key == "--env-file" and value:
            references.append(Reference(mode=Mode.READ, text=value))
            continue
        mounts += mount_references(key, value or "")
    # The file rules still apply to the mounts (a secret is a deny, not an ask),
    # but they are not enough: rule 3.3 narrows them down to the project.
    verdict = allowed(command, references + mounts, project_root, label)
    if outside := check_mounts(mounts, project_root, label):
        verdict = worst(outside, verdict)
    return worst(pending, verdict) if pending else verdict

def check_build(command: Command, args: list[Argument], project_root: Path, label: str) -> tuple[Decision, str]:
    """
    Rule 3.4: build from the project only, with the options whose paths can be
    vetted. The build context is the positional argument.
    """
    options, positionals = resolve_options(args, BUILD_VALUE_OPTS)
    if denial := check_denied_options(options, label):
        return denial
    references = []
    pending = None
    for key, value in options:
        if key not in BUILD_ALLOWED_OPTS:
            # Keep walking: the files named by the other options must still be
            # vetted, so an unknown option cannot turn a deny into an ask.
            pending = pending or (Decision.ASK, f"The `{key}` option of `{label}` is not allowed by default.")
            continue
        references += build_references(key, value or "")
    # A context may also be a URL or `-` (stdin): neither is a host path.
    references += [Reference(mode=Mode.READ, text=x) for x in positionals if x != "-" and "://" not in x]
    verdict = allowed(command, references, project_root, label)
    return worst(pending, verdict) if pending else verdict

def check_volume_create(command: Command, args: list[Argument], project_root: Path, label: str) -> tuple[Decision, str]:
    """
    Rule 3.3: creating a volume is harmless, unless it binds a host directory
    (`--opt device=/etc`) outside the project.
    """
    options, _ = resolve_options(args, [*ANY_VALUE_OPTS, "-o", "--opt", "-d", "--driver"])
    if denial := check_denied_options(options, label):
        return denial
    mounts = []
    for key, value in options:
        if key in ("-o", "--opt") and (device := parse_csv(value or "").get("device")):
            mounts.append(Reference(mode=Mode.WRITE, text=device))
    verdict = allowed(command, mounts, project_root, label)
    # The volume is a mount waiting to happen: rule 3.3 applies to it too.
    return worst(outside, verdict) if (outside := check_mounts(mounts, project_root, label)) else verdict

def check_copy(command: Command, args: list[Argument], project_root: Path, label: str) -> tuple[Decision, str]:
    """
    Rule 3.3: copy to/from a container, as long as the host side of the copy is
    accessible. A `service:/path` argument is the container side, not a host path.
    """
    options, positionals = resolve_options(args, [*ANY_VALUE_OPTS, "--index"])
    if denial := check_denied_options(options, label):
        return denial
    references = []
    for position, path in enumerate(positionals[:2]):
        if ":" in path and not is_host_path(path):
            continue  # container side, sandboxed
        references.append(Reference(mode=Mode.READ if position == 0 else Mode.WRITE, text=path))
    return allowed(command, references, project_root, label)

def check_container(command: Command, project_root: Path) -> tuple[Decision, str]:
    """
    `docker` and `podman` share one allow-list, keyed on the canonical
    `(object, verb)` pair: reporting commands are free, the ones that only
    reshuffle docker objects too, and the ones that run or build a container are
    restricted to the options and the host paths that can be vetted statically.
    """
    suffix = command.base.partition("-")[2]
    head, positionals, args = split_head(command.args, legacy_compose=suffix == "compose")
    label = " ".join([command.base, *positionals[:2]])
    if denial := check_denied_options(head, label):
        return denial

    pair = normalize(["compose", *positionals] if suffix == "compose" else positionals)

    # Global `compose` options are shared by every verb: vet them once, upfront.
    references = []
    pending = None
    for key, value in head:
        if key in VERSION_OPTS:
            continue  # not an option of the command: handled right below
        if key not in HEAD_OPTS:
            # Pending, not returned: the files named by the other global options
            # are still vetted, so an unknown one cannot mask a deny.
            pending = pending or (Decision.ASK, f"The `{key}` option of `{label}` is not allowed by default.")
            continue
        if key in HEAD_PATH_OPTS and value:
            references.append(Reference(mode=Mode.READ, text=value))
    decision, reason = check_access(command, references, project_root)
    if pending:
        return worst(pending, (decision, reason))
    if decision is not Decision.ALLOW:
        return (decision, reason)

    # `--version` replaces the verb altogether, ex: `docker --version`. It is an
    # allow shortcut, so it only applies once the rest of the line is cleared.
    if not pair[1] and any(key in VERSION_OPTS for key, _ in head):
        return (Decision.ALLOW, f"The `{label} --version` command is allowed.")

    if not positionals:
        return (Decision.ASK, f"The `{command.base}` command is not allowed by default.")
    if pair in RUN_COMMANDS:
        return check_run(command, args, project_root, label)
    if pair == ("", "build"):
        return check_build(command, args, project_root, label)
    if pair == ("", "buildx"):
        # Only `buildx build` is a build; `buildx create`, `buildx use`, ... are not.
        if args and args[0].positional and (args[0].value or "").lower() == "build":
            return check_build(command, args[1:], project_root, f"{label} build")
        return (Decision.ASK, f"The `{label}` command is not allowed by default.")
    if pair == ("volume", "create"):
        return check_volume_create(command, args, project_root, label)
    if pair in COPY_COMMANDS:
        return check_copy(command, args, project_root, label)
    if pair in STATUS_COMMANDS + MANAGE_COMMANDS:
        options, _ = resolve_options(args, ANY_VALUE_OPTS)
        if denial := check_denied_options(options, label):
            return denial
        # The verbs inherit the global `compose` options, so a file may be named
        # on either side of the verb (`docker compose up -f other.yml`): vet both.
        references = []
        if pair[0] == "compose":
            references = [Reference(mode=Mode.READ, text=value) for key, value in options if key in HEAD_PATH_OPTS and value]
        return allowed(command, references, project_root, label)
    return (Decision.ASK, f"The `{label}` command is not allowed by default.")
