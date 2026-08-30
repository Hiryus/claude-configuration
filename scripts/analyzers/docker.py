import re

from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, CommandLine, Invocation, Reference
from parsers import docker
from utils.format import format_references
from utils.parsing import is_flag

# Options that (may) let the container escape into the host.
ROOT_USERS = ["root", "0"]
UNSAFE_FLAGS = ["cap-add", "device", "privileged", "security-opt"]

# Base options re-targeting the client: another daemon, another config directory, another TLS identity.
DAEMON_FLAGS = ["config", "context", "host", "tls", "tlscacert", "tlscert", "tlskey", "tlsverify"]

# Global compose options.
COMPOSE_ALLOWED_FLAGS = ["ansi", "dry-run", "env-file", "file", "parallel", "profile", "progress", "project-name"]
COMPOSE_UNSAFE_FLAGS = ["all-resources", "compatibility", "project-directory"]

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

# Options allowed on commands that start a process in a container (`opaque_tail` grammar nodes).
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
    "interactive",
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


def is_path(text:str) -> bool:
    """
    A host path, as opposed to a named volume: docker only reads a mount source as a path when it is
    explicitly anchored (`.`, `./x`, `/x`, `~/x`, `C:\\x`); a bare `data:/data` is a named volume.
    """
    if text in (".", ".."):
        return True
    return text.startswith(("/", "./", "../", "~", ".\\", "..\\", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", text))


def split_fields(value:str) -> dict[str, list[str]]:
    """
    The `key=value,key=value` shape shared by `--mount`, `--opt`, `--cache-from`, ...
    A bare field (`readonly`) maps to an empty value.
    A key may repeat so every value is kept, in order, rather than the last one silently winning.
    """
    fields:dict[str, list[str]] = {}
    for field in value.split(","):
        key, _, text = field.partition("=")
        fields.setdefault(key, []).append(text)
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
    return Invocation(cmd_parts=invocation.cmd_parts, arguments=invocation.arguments[:index + 1], opaque_tail=invocation.opaque_tail)


# ============================================================================
# Parsing functions
# ============================================================================

def parse_copy_ref(invocation:Invocation) -> list[Reference]:
    """
    `cp SOURCE DESTINATION`, either side being a container path (`service:/app`) that is not checked.
    """
    references = []
    operands = [x for x in invocation.positionals if x.value is not None]
    for index, operand in enumerate(operands[:2]):
        access = Access.READ if index == 0 else Access.WRITE
        if (reference := Reference(access=access, text=operand.value or "", expansions=operand.expansions)).dynamic:
            references.append(reference)  # an expansion may hold either side of the copy
            continue
        parts = split_mount(operand.value or "")
        if len(parts) > 1 and not is_path(parts[0]):
            continue  # container side: inside the sandbox
        references.append(Reference(access=access, text=parts[0]))
    return references


def parse_mount_ref(invocation:Invocation) -> tuple[list[Reference], list[str]]:
    """
    The host paths a container mounts, plus the named volumes that cannot be resolved: those are not the project directory, so they need validation.
    The volumes from other containers (`--volumes-from`) are allowed.

    A spec built from an expansion is referenced whole, before any splitting: `-v $SPEC` has no
    separator for `split_mount` to find and `--mount $SPEC` no `source=` field, so the structural
    short-circuits below would otherwise read "nothing of the host is exposed" out of an unknown path.
    """
    references:list[Reference] = []
    unverified:list[str] = []

    for arg in invocation.values("volume"):
        spec = arg.value or ""
        if (reference := Reference(access=Access.WRITE, text=spec, expansions=arg.expansions)).dynamic:
            references.append(reference)
            continue
        parts = split_mount(spec)
        if len(parts) == 1:
            continue  # anonymous volume (`-v /data`): container side only
        if not is_path(parts[0]):
            unverified.append(spec)
        else:
            access = Access.READ if "ro" in parts[2:] else Access.WRITE
            references.append(Reference(access=access, text=parts[0]))

    for arg in invocation.values("mount"):
        spec = arg.value or ""
        if (reference := Reference(access=Access.WRITE, text=spec, expansions=arg.expansions)).dynamic:
            references.append(reference)
            continue
        fields = split_fields(spec)
        if fields.get("type") == ["tmpfs"]:
            continue  # nothing of the host is exposed

        flags = fields.get("readonly", []) + fields.get("ro", [])
        readonly = bool(flags) and all(x in ("", "true") for x in flags)
        access = Access.READ if readonly else Access.WRITE

        sources = fields.get("source", []) + fields.get("src", [])
        if len(sources) > 1:
            # `source`/`src` are aliases for the same field: docker uses exactly one, so a dommand declaring both is not "maybe a volume name".
            # Neither value can be dismissed by the is_path() heuristic below, and both are checked directly.
            references += [Reference(access=access, text=x) for x in sources]
        elif sources and not is_path(sources[0]):
            unverified.append(spec)
        elif sources:
            references.append(Reference(access=access, text=sources[0]))

        # A bind-backed named volume carries its real host path in `volume-opt=device=...`.
        for opt in fields.get("volume-opt", []):
            key, _, device = opt.partition("=")
            if key != "device":
                continue
            if is_path(device):
                references.append(Reference(access=access, text=device))
            else:
                unverified.append(spec)

    return (references, unverified)


def parse_opt_refs(invocation:Invocation, names:list[str], access:Access) -> list[Reference]:
    """
    The local paths an option points at. A plain value is a path (`-f Dockerfile`); a structured one
    only yields its path-looking fields, so `--cache-to type=registry,ref=x` references no file while
    `--cache-to type=local,dest=./cache` does.

    A value built from an expansion is referenced whole: the field the expansion landed in is unknown,
    and its text would not look like a path anyway (`--output dest=$X`).
    """
    references = []
    for arg in invocation.values(*names):
        value = arg.value or ""
        reference = Reference(access=access, text=value, expansions=arg.expansions)
        if reference.dynamic or "=" not in value:
            references.append(reference)
        else:
            references.extend(Reference(access=access, text=x) for values in split_fields(value).values() for x in values if is_path(x))
    return references


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
    references = invocation.references(Access.READ, "env-file")

    if invocation.opaque_tail:
        invocation = strip_container_argv(invocation)

    if unsafe := [x.key for x in invocation.options if x.name in UNSAFE_FLAGS]:
        return (Decision.DENY, f"`{invocation.command}` uses the {unsafe} options: they may escape the container into the host.")
    if any((x.value or "").partition(":")[0] in ROOT_USERS for x in invocation.values("user")):
        return (Decision.DENY, "Do not run a container as root.")
    if invocation.has_arg(*DAEMON_FLAGS):
        reasons.append(f"`{invocation.command}` re-targets the client (daemon, config directory or TLS identity).")

    if "compose" in invocation.cmd_parts:
        references += invocation.references(Access.READ, "file")
        if unsafe := [x.key for x in invocation.options if x.name in COMPOSE_UNSAFE_FLAGS]:
            reasons.append(f"`{invocation.command}` uses the {unsafe} global options, which are not allowed by default.")

    # `docker --version` is the flag spelling of `docker version`, but it only vouches for itself:
    # anything else on the line (an untabled flag included, since it carries no name) still needs the user validation.
    if invocation.command == "docker" and invocation.has_arg("version"):
        if extra := [x.key or x.value for x in invocation.arguments if x.name != "version"]:
            reasons.append(f"`docker --version` requires the user validation when combined with the {extra} arguments.")
        else:
            return (Decision.ALLOW, "The `docker --version` command is allowed.")

    elif invocation.opaque_tail:
        mounts, unverified = parse_mount_ref(invocation)
        allowed = RUN_ALLOWED_FLAGS + MOUNT_FLAGS + (COMPOSE_ALLOWED_FLAGS if "compose" in invocation.cmd_parts else [])
        if disallowed := [x.key for x in invocation.options if x.name not in allowed]:
            reasons.append(f"`{invocation.command}` requires the user validation when using the {disallowed} options.")
        if unverified:
            reasons.append(f"`{invocation.command}` mounts {format_references(unverified)}: only the project directory can be mounted by default.")
        references += mounts

    elif invocation.command in BUILD_COMMANDS:
        references += parse_opt_refs(invocation, BUILD_READ_FLAGS, Access.READ)
        references += parse_opt_refs(invocation, BUILD_WRITE_FLAGS, Access.WRITE)
        # The operand is the build context: a local directory (in rare cases it may be a repository/URL, but we want to validate this too).
        references += [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]
        if disallowed := [x.key for x in invocation.options if x.name not in BUILD_ALLOWED_FLAGS]:
            reasons.append(f"`{invocation.command}` requires the user validation when using the {disallowed} options.")

    elif invocation.command in COPY_COMMANDS:
        references += parse_copy_ref(invocation)
        if invocation.unknown:
            reasons += [f"`{invocation.command}` uses the {invocation.unknown} options, which are not in the grammar; cannot verify them."]

    elif invocation.command == "docker volume create":
        # A bind-mounted volume carries its host path in `--opt device=/path`.
        references += parse_opt_refs(invocation, ["opt"], Access.WRITE)
        if invocation.unknown:
            reasons += [f"`{invocation.command}` uses the {invocation.unknown} options, which are not in the grammar; cannot verify them."]

    elif invocation.command in ALLOWED_COMMANDS:
        references += invocation.references(Access.WRITE, "output")
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
