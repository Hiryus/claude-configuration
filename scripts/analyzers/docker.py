import re

from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, CommandLine, Invocation, Reference
from parsers import docker
from utils.format import format_references

# Options that (may) let the container escape into the host.
ROOT_USERS = ["root", "0"]
UNSAFE_FLAGS = ["cap-add", "device", "privileged", "security-opt"]

# Base options re-targeting the client: another daemon, another config directory, another TLS identity.
DAEMON_FLAGS = ["config", "context", "host", "tls", "tlscacert", "tlscert", "tlskey", "tlsverify"]

# Global compose options. `--project-directory` re-anchors every relative path of the
# compose file (build contexts, volumes), and the others are simply not listed.
COMPOSE_FLAGS = ["ansi", "env-file", "file", "parallel", "profile", "progress", "project-name"]
COMPOSE_UNSAFE_FLAGS = ["all-resources", "compatibility", "dry-run", "project-directory"]

# Commands allowed as-is. They only report a status or act on docker objects, never on the host filesystem.
# Both spellings are listed since the grammar keeps them distinct (`docker ps` is its own node, not an alias of `docker container ls`).
ALLOWED_COMMANDS = [
    # §3.2 status
    "docker compose config",
    "docker compose images",
    "docker compose logs",
    "docker compose ls",
    "docker compose port",
    "docker compose ps",
    "docker compose stats",
    "docker compose top",
    "docker compose version",
    "docker compose volumes",
    "docker config inspect",
    "docker config ls",
    "docker container inspect",
    "docker container logs",
    "docker container ls",
    "docker container port",
    "docker container stats",
    "docker container top",
    "docker image inspect",
    "docker image ls",
    "docker images",
    "docker info",
    "docker inspect",
    "docker logs",
    "docker network inspect",
    "docker network ls",
    "docker port",
    "docker ps",
    "docker stats",
    "docker system df",
    "docker system info",
    "docker top",
    "docker version",
    "docker volume inspect",
    "docker volume ls",
    # §3.3 lifecycle
    "docker compose create",
    "docker compose down",
    "docker compose kill",
    "docker compose pause",
    "docker compose restart",
    "docker compose rm",
    "docker compose start",
    "docker compose stop",
    "docker compose unpause",
    "docker compose up",
    "docker compose wait",
    "docker container kill",
    "docker container pause",
    "docker container prune",
    "docker container restart",
    "docker container rm",
    "docker container start",
    "docker container stop",
    "docker container unpause",
    "docker container wait",
    "docker kill",
    "docker network connect",
    "docker network create",
    "docker network disconnect",
    "docker network prune",
    "docker network rm",
    "docker pause",
    "docker restart",
    "docker rm",
    "docker start",
    "docker stop",
    "docker system prune",
    "docker unpause",
    "docker volume prune",
    "docker volume rm",
    "docker wait",
    # §3.4 images
    "docker compose pull",
    "docker image prune",
    "docker image pull",
    "docker image rm",
    "docker pull",
    "docker rmi",
]

# Commands that start a process in a container: allowed, but only with verified options and mounts.
RUN_COMMANDS = [
    "docker compose exec",
    "docker compose run",
    "docker container create",
    "docker container exec",
    "docker container run",
    "docker create",
    "docker exec",
    "docker run",
]
RUN_ALLOWED_FLAGS = [
    "detach",
    "entrypoint",
    "env",
    "env-file",
    "expose",
    "health-cmd",
    "health-interval",
    "health-retries",
    "health-start-interval",
    "health-start-period",
    "health-timeout",
    "help",
    "name",
    "network",
    "network-alias",
    "no-healthcheck",
    "publish",
    "publish-all",
    "pull",
    "quiet",
    "read-only",
    "restart",
    "rm",
    "stop-timeout",
    "tmpfs",
    "workdir",
]

# Mounting is allowed, but only for the project directory, so every source is checked.
MOUNT_FLAGS = ["mount", "volume", "volumes-from"]

# Building an image.
BUILD_COMMANDS = ["docker build", "docker builder build", "docker buildx build", "docker image build"]
BUILD_READ_FLAGS = ["build-context", "cache-from", "file"]
BUILD_WRITE_FLAGS = ["cache-to", "iidfile", "metadata-file", "output"]
BUILD_ALLOWED_FLAGS = BUILD_READ_FLAGS + BUILD_WRITE_FLAGS + ["build-arg", "help", "label", "no-cache", "no-cache-filter", "pull", "quiet", "resource", "tag", "target"]

# Copying files in and out of a container.
COPY_COMMANDS = ["docker compose cp", "docker container cp", "docker cp"]


# ============================================================================
# Utility functions
# ============================================================================


def is_flag(text:str|None) -> bool:
    """
    A flag-shaped word, as opposed to a value that merely starts with a dash: the negative numbers
    docker takes are ordinary values (`--memory-swap -1`, `--oom-score-adj -500`).
    """
    return bool(text) and bool(re.match(r"^-\D", text or ""))


def is_path(text:str) -> bool:
    """
    A host path, as opposed to a named volume: docker only reads a mount source as a path when it is
    explicitly anchored (`.`, `./x`, `/x`, `~/x`, `C:\\x`); a bare `data:/data` is a named volume.
    """
    if text in (".", ".."):
        return True
    return text.startswith(("/", "./", "../", "~", ".\\", "..\\", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", text))


def split_fields(value:str) -> dict[str, str]:
    """
    The `key=value,key=value` shape shared by `--mount`, `--opt`, `--cache-from`, ...
    A bare field (`readonly`) maps to an empty value.
    """
    fields:dict[str, str] = {}
    for field in value.split(","):
        key, _, text = field.partition("=")
        fields[key] = text
    return fields


def split_mount(spec:str) -> list[str]:
    """
    Split `source:target[:options]` on its separators, keeping a Windows drive letter with its path.
    """
    parts:list[str] = []
    for part in spec.split(":"):
        if parts and len(parts[-1]) == 1 and parts[-1].isalpha() and part.startswith(("/", "\\")):
            parts[-1] += f":{part}"
        else:
            parts.append(part)
    return parts


def strip_container_argv(invocation:Invocation) -> Invocation:
    """
    Strip the command running inside the container for `docker exec` and `docker run`.

    Docker stops reading its own options at the container/image operand, so everything behind it is the container's argv.
    The boundary is the first operand, and nothing is stripped when it cannot be trusted:
    - An untabled option is not paired with its value, so that value reads as the operand and the real one hides behind it.
    - A tabled option that swallowed a flag-shaped value is docker's own reading too, but it is almost always a typo, so the line keeps being checked whole rather than newly allowed.
    """
    index = next((i for i, x in enumerate(invocation.arguments) if x.positional), None)
    if index is None:
        return invocation
    if any(not x.known or is_flag(x.value) for x in invocation.arguments[:index]):
        return invocation
    return Invocation(cmd_parts=invocation.cmd_parts, arguments=invocation.arguments[:index + 1])


# ============================================================================
# Parsing functions
# ============================================================================

def parse_copy_ref(invocation:Invocation) -> list[Reference]:
    """
    `cp SOURCE DESTINATION`, either side being a container path (`service:/app`) that is not checked.
    """
    references = []
    operands = [x.value for x in invocation.positionals if x.value is not None]
    for index, operand in enumerate(operands[:2]):
        parts = split_mount(operand)
        if len(parts) > 1 and not is_path(parts[0]):
            continue  # container side: inside the sandbox
        access = Access.READ if index == 0 else Access.WRITE
        references.append(Reference(access=access, text=parts[0]))
    return references


def parse_mount_ref(invocation:Invocation) -> tuple[list[Reference], list[str]]:
    """
    The host paths a container mounts, plus the named volumes that cannot be resolved: those are not the project directory, so they need validation.
    The volumes from other containers (`--volumes-from`) are allowed.
    """
    references:list[Reference] = []
    unverified:list[str] = []

    for spec in invocation.values("volume"):
        parts = split_mount(spec)
        if len(parts) == 1:
            continue  # anonymous volume (`-v /data`): container side only
        if not is_path(parts[0]):
            unverified.append(spec)
        else:
            access = Access.READ if "ro" in parts[2:] else Access.WRITE
            references.append(Reference(access=access, text=parts[0]))

    for spec in invocation.values("mount"):
        fields = split_fields(spec)
        source = fields.get("source") or fields.get("src")
        if source is None or fields.get("type") == "tmpfs":
            continue  # nothing of the host is exposed
        if not is_path(source):
            unverified.append(spec)
        else:
            readonly = fields.get("readonly", fields.get("ro"))
            access = Access.READ if readonly in ("", "true") else Access.WRITE
            references.append(Reference(access=access, text=source))

    return (references, unverified)


def parse_opt_paths(invocation:Invocation, names:list[str]) -> list[str]:
    """
    The local paths an option points at. A plain value is a path (`-f Dockerfile`); a structured one
    only yields its path-looking fields, so `--cache-to type=registry,ref=x` references no file while
    `--cache-to type=local,dest=./cache` does.
    """
    paths = []
    for value in invocation.values(*names):
        if "=" not in value:
            paths.append(value)
        else:
            paths.extend(x for x in split_fields(value).values() if is_path(x))
    return paths


# ============================================================================
# Main validate function
# ============================================================================


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    The `docker` command is allowed per subcommand path (`docker container ls`).
    - The sandbox-escaping options (`--privileged`, `--device`, ... and running as root) are denied everywhere.
    - Status and lifecycle commands are allowed as-is: they act on docker objects, not on the host.
    - The commands that reach the host filesystem (run/exec mounts, build, cp, volume create) are allowed only with tabled options and only for paths check_access validates.
      The container side of a mount or a copy is never checked: it is inside the sandbox.
    Everything else, including any untabled option on a restricted command, is an ask.
    """
    invocation = docker.parse(command)
    reasons:list[str] = [] # reasons to ask are collected, not returned on the spot.
    references = [Reference(access=Access.READ, text=x) for x in invocation.values("env-file")]

    if invocation.command in RUN_COMMANDS:
        invocation = strip_container_argv(invocation)

    if unsafe := [x.key for x in invocation.options if x.name in UNSAFE_FLAGS]:
        return (Decision.DENY, f"`{invocation.command}` uses the {unsafe} options: they may escape the container into the host.")
    if any(x.partition(":")[0] in ROOT_USERS for x in invocation.values("user")):
        return (Decision.DENY, "Do not run a container as root.")
    if invocation.has_arg(*DAEMON_FLAGS):
        reasons.append(f"`{invocation.command}` re-targets the client (daemon, config directory or TLS identity).")

    if "compose" in invocation.cmd_parts:
        references += [Reference(access=Access.READ, text=x) for x in invocation.values("file")]
        if unsafe := [x.key for x in invocation.options if x.name in COMPOSE_UNSAFE_FLAGS]:
            reasons.append(f"`{invocation.command}` uses the {unsafe} global options, which are not allowed by default.")

    # `docker --version` is the flag spelling of `docker version`, but it only vouches for itself:
    # anything else on the line (an untabled flag included, since it carries no name) still needs the user validation.
    if invocation.command == "docker" and invocation.has_arg("version"):
        if extra := [x.key or x.value for x in invocation.arguments if x.name != "version"]:
            reasons.append(f"`docker --version` requires the user validation when combined with the {extra} arguments.")
        else:
            return (Decision.ALLOW, "The `docker --version` command is allowed.")

    elif invocation.command in RUN_COMMANDS:
        mounts, unverified = parse_mount_ref(invocation)
        allowed = RUN_ALLOWED_FLAGS + MOUNT_FLAGS + (COMPOSE_FLAGS if "compose" in invocation.cmd_parts else [])
        if disallowed := [x.key for x in invocation.options if x.name not in allowed]:
            reasons.append(f"`{invocation.command}` requires the user validation when using the {disallowed} options.")
        if unverified:
            reasons.append(f"`{invocation.command}` mounts {format_references(unverified)}: only the project directory can be mounted by default.")
        references += mounts

    elif invocation.command in BUILD_COMMANDS:
        references += [Reference(access=Access.READ, text=x) for x in parse_opt_paths(invocation, BUILD_READ_FLAGS)]
        references += [Reference(access=Access.WRITE, text=x) for x in parse_opt_paths(invocation, BUILD_WRITE_FLAGS)]
        # The operand is the build context: a local directory (in rare cases it may be a repository/URL, but we want to validate this too).
        references += [Reference(access=Access.READ, text=x.value) for x in invocation.positionals if x.value is not None]
        if disallowed := [x.key for x in invocation.options if x.name not in BUILD_ALLOWED_FLAGS]:
            reasons.append(f"`{invocation.command}` requires the user validation when using the {disallowed} options.")

    elif invocation.command in COPY_COMMANDS:
        references += parse_copy_ref(invocation)
        if invocation.unknown:
            reasons += [f"`{invocation.command}` uses the {invocation.unknown} options, which are not in the grammar; cannot verify them."]

    elif invocation.command == "docker volume create":
        # A bind-mounted volume carries its host path in `--opt device=/path`.
        references += [Reference(access=Access.WRITE, text=x) for x in parse_opt_paths(invocation, ["opt"])]
        if invocation.unknown:
            reasons += [f"`{invocation.command}` uses the {invocation.unknown} options, which are not in the grammar; cannot verify them."]

    elif invocation.command in ALLOWED_COMMANDS:
        references += [Reference(access=Access.WRITE, text=x) for x in invocation.values("output")]
        if invocation.unknown:
            reasons += [f"`{invocation.command}` uses the {invocation.unknown} options, which are not in the grammar; cannot verify them."]

    else:
        reasons.append(f"The `{invocation.command}` command is not allowed by default.")

    decision, reason = check_access(command, references, context)
    if decision is Decision.DENY:
        return (decision, reason)
    elif decision is Decision.ASK:
        reasons += [reason]

    if any(reasons):
        return (Decision.ASK, " ".join(reasons))
    return (Decision.ALLOW, f"The `{invocation.command}` command is allowed.")





