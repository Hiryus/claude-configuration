from generic import check_access
from models.analyzer import Context, Decision, Mode
from models.parsing import Access, CommandLine, Invocation, Reference
from parsers import git

ALLOWED_SUBCOMMANDS = [
    "add",
    "check-ignore",
    "commit",
    "diff",
    "fetch",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "merge-base",
    "rev-parse",
    "show",
    "status",
]

CONFIG_READONLY_ARGS = [
    "default",
    "file",
    "get",
    "includes",
    "list",
    "name-only",
    "null",
    "scope",
    "show-origin",
    "show-scope",
    "type",
]

CONFIG_READONLY_VERBS = [
    "get",
    "list",
]

BRANCH_READONLY_ARGS = [
    "all",
    "abbrev",
    "color",
    "column",
    "contains",
    "format",
    "list",
    "merged",
    "points-at",
    "remotes",
    "show-current",
    "sort",
    "verbose",
]


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    `git` is allow-listed per subcommand.
    - The `-C`, `--git-dir`, `-c` flags and a `GIT_DIR` variable are refused wherever they sit.
    - The history-rewriting subcommands need the user validation,
    - Any path git writes (`--output`), stages (`add`/`commit`), or restores in the index (`reset`) goes through check_access first.

    An untabled flag is NOT an ASK here: git has ~150 subcommands, so nearly every real line carries one (`-m`, `--list`, `-s`, ...).
    Such a flag stays visible as an operand, which is exactly what `add`/`commit` path-check.
    The `branch` and `config` verbs deviate: their tables list every read-only spelling, so anything untabled is a write and asks.
    """
    invocation = git.parse(command)
    verb = invocation.cmd_parts[1] if len(invocation.cmd_parts) > 1 else None

    # Deny GIT_DIR variable in the command and in the environment as it overrides the repository location.
    if any(x.name == "GIT_DIR" for x in command.assignments) or "GIT_DIR" in command.environment:
        return (Decision.DENY, "Do not change git directory.")
    # Also deny the related arguments.
    if invocation.has_arg("git-dir"):
        return (Decision.DENY, "Do not change git directory.")

    # `git -c` never _reads_ a config, it injects one for the run (`core.pager`, `alias.*`, `credential.helper` all execute a command), so it stays denied.
    # Reading is served by the `git config` verb below.
    if invocation.has_arg("config"):
        return (Decision.DENY, "Do not use `git -c` to inject config; it can run arbitrary code. Run the command directly.")

    if verb == "config":
        return validate_config(command, invocation, context)

    if verb == "branch":
        disallowed_args = [x for x in invocation.options if x.name not in BRANCH_READONLY_ARGS]
        if any(disallowed_args):
            return (Decision.ASK, f"`git branch` requires the user validation when using {[x.key for x in disallowed_args]} flags.")
        if any(invocation.positionals) and context.mode == Mode.MANUAL:
            return (Decision.ASK, "`git branch` requires the user validation when creating a new branch.")
        return (Decision.ALLOW, "`git branch` is allowed by default.")

    if verb == "push":
        if any(x.name == "force" for x in invocation.options):
            return (Decision.DENY, "`git push --force` is forbidden by the security policy: only the user is allowed to change history.")
        return (Decision.ASK, "`git push` requires the user validation.")

    if verb == "reset":
        # `--hard` throws away the working tree with no object left to recover it from, so it is denied like `push --force`.
        if any(x.name == "hard" for x in invocation.options):
            return (Decision.DENY, "`git reset --hard` is forbidden by the security policy: only the user is allowed to discard uncommitted work.")
        if any(references := [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]):
            decision, reason = check_access(command, references, context)
            if decision is not Decision.ALLOW:
                return (decision, reason)
        if context.mode == Mode.MANUAL:
            return (Decision.ASK, "`git reset` requires the user validation.")
        return (Decision.ALLOW, "`git reset` is allowed by default.")

    if verb == "remote":
        if invocation.command in ["git remote", "git remote get-url", "git remote show"]:
            return (Decision.ALLOW, f"The `{invocation.command}` command is allowed.")
        return (Decision.ASK, f"The `{invocation.command}` command is not allowed by default.")

    references = invocation.references(Access.WRITE, "output")
    if verb in ["add", "commit"]:
        references += [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]
    if any(references):
        decision, reason = check_access(command, references, context)
        if decision is not Decision.ALLOW:
            return (decision, reason)

    if verb in ALLOWED_SUBCOMMANDS:
        return (Decision.ALLOW, f"The `{invocation.command}` command is allowed.")
    return (Decision.ASK, f"The `{invocation.command}` command is not allowed by default.")


def validate_config(command:CommandLine, invocation:Invocation, context:Context) -> tuple[Decision, str]:
    """
    Reading the git config is allowed, writing it asks.
    Anything that is not provably a read is a write: a write verb (`set`, `unset`, `edit`, ...), an untabled flag (`--add`, `--unset`, `--replace-all`, ...), or a second operand (`git config <name> <value>`).
    Only an explicit `--file` goes through check_access: the implicit config files (`~/.gitconfig`, `.git/config`) sit outside the project and would turn every read into an ASK.
    """
    references = invocation.references(Access.READ, "file")
    references += invocation.references(Access.WRITE, "output")
    if any(references):
        decision, reason = check_access(command, references, context)
        if decision is not Decision.ALLOW:
            return (decision, reason)

    disallowed_args = [x for x in invocation.options if x.name not in CONFIG_READONLY_ARGS]
    if any(disallowed_args):
        return (Decision.ASK, f"`git config` requires the user validation when using {[x.key for x in disallowed_args]} flags.")
    if len(invocation.cmd_parts) > 2 and invocation.cmd_parts[2] not in CONFIG_READONLY_VERBS:
        return (Decision.ASK, f"The `{invocation.command}` command writes the git configuration and requires the user validation.")
    if len(invocation.positionals) > 1:
        return (Decision.ASK, "`git config` requires the user validation when setting a value.")
    return (Decision.ALLOW, "Reading the git configuration is allowed.")
