import re

from agnostic.generic import check_access
from agnostic.models.context import Context
from agnostic.models.decision import Decision, Verdict
from agnostic.models.mode import Mode
from agnostic.models.parsing import Access, CommandLine, Invocation, Reference
from agnostic.parsers import git

# The env-var equivalent of `-c NAME=VALUE`: GIT_CONFIG_COUNT=<n> plus one GIT_CONFIG_KEY_<i>/GIT_CONFIG_VALUE_<i> pair per entry.
GIT_CONFIG_ENV_PATTERN = re.compile(r"^GIT_CONFIG_(COUNT|KEY_\d+|VALUE_\d+)$")

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
    "mv",
    "rev-parse",
    "rm",
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


def validate(command:CommandLine, context:Context) -> Decision:
    """
    `git` is allow-listed per subcommand.
    - The `-C`/`--git-dir`/`GIT_DIR`/`--work-tree`/`GIT_WORK_TREE` are refused wherever they sit; `-c` and its env-var
      equivalent (`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`) ask (rule 2.9.3) --
      except `switch -c`/`-C` (create branch), whose grammar node shadows the root one on purpose (see `parsers/git.py`).
    - The history-rewriting subcommands need the user validation,
    - Any path git writes (`--output`, `mv`/`rm`/`checkout <pathspec>`), stages (`add`/`commit`), or restores in the index (`reset`) goes through check_access first.

    An untabled flag is NOT an ASK here: git has ~150 subcommands, so nearly every real line carries one (`-m`, `--list`, `-s`, ...).
    Such a flag stays visible as an operand, which is exactly what `add`/`commit`/`mv`/`rm` path-check.
    The `branch` and `config` verbs deviate: their tables list every read-only spelling, so anything untabled is a write and asks.
    """
    invocation = git.parse(command)
    verb = invocation.cmd_parts[1] if len(invocation.cmd_parts) > 1 else None

    # Deny GIT_DIR/GIT_WORK_TREE variables in the command and in the environment as they override the repository location.
    if any(x.name in ("GIT_DIR", "GIT_WORK_TREE") for x in command.assignments) or "GIT_DIR" in command.environment or "GIT_WORK_TREE" in command.environment:
        return Decision.deny("Do not change the git directory or work tree.")
    # Also deny the related arguments.
    if invocation.has_arg("git-dir"):
        return Decision.deny("Do not change the git directory or work tree.")

    if any(GIT_CONFIG_ENV_PATTERN.match(x.name) for x in command.assignments) or any(GIT_CONFIG_ENV_PATTERN.match(k) for k in command.environment):
        return Decision.ask("`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*` set configuration for the run and require the user validation.")

    if invocation.has_arg("config"):
        return Decision.ask("`git -c` sets configuration for the run and requires the user validation.")

    if verb == "config":
        return validate_config(command, invocation, context)

    if verb == "branch":
        disallowed_args = [x for x in invocation.options if x.name not in BRANCH_READONLY_ARGS]
        if any(disallowed_args):
            return Decision.ask(f"`git branch` requires the user validation when using {[x.key for x in disallowed_args]} flags.")
        if any(invocation.positionals) and context.mode == Mode.MANUAL:
            return Decision.ask("`git branch` requires the user validation when creating a new branch.")
        return Decision.allow("`git branch` is allowed by default.")

    if verb in ["checkout", "switch"]:
        # A `checkout` positional is ambiguous: `git checkout foo` switches to branch `foo` if one exists, but silently restores file `foo` from the index otherwise
        # (the same write as the explicit `git checkout -- foo`, just without the `--`) So every positional is WRITE-checked unconditionally.
        if verb == "checkout" and any(references := [Reference(access=Access.WRITE, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]):
            decision = check_access(command, references, context)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        if context.mode == Mode.MANUAL:
            return Decision.ask(f"`{invocation.command}` requires the user validation.")
        return Decision.allow(f"`{invocation.command}` is allowed by default.")

    if verb == "push":
        if any(x.name == "force" for x in invocation.options):
            return Decision.deny("`git push --force` is forbidden by the security policy: only the user is allowed to change history.")
        return Decision.ask("`git push` requires the user validation.")

    if verb == "reset":
        # `--hard` throws away the working tree with no object left to recover it from, so it is denied like `push --force`.
        if any(x.name == "hard" for x in invocation.options):
            return Decision.deny("`git reset --hard` is forbidden by the security policy: only the user is allowed to discard uncommitted work.")
        if any(references := [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]):
            decision = check_access(command, references, context)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        if context.mode == Mode.MANUAL:
            return Decision.ask("`git reset` requires the user validation.")
        return Decision.allow("`git reset` is allowed by default.")

    if verb == "remote":
        if invocation.command in ["git remote", "git remote get-url", "git remote show"]:
            return Decision.allow(f"The `{invocation.command}` command is allowed.")
        return Decision.ask(f"The `{invocation.command}` command is not allowed by default.")

    references = invocation.references(Access.WRITE, "output")
    if verb in ["add", "commit"]:
        references += [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]
    if verb in ["mv", "rm"]:
        references += [Reference(access=Access.WRITE, text=x.value, expansions=x.expansions) for x in invocation.positionals if x.value is not None]
    if any(references):
        decision = check_access(command, references, context)
        if decision.verdict is not Verdict.ALLOW:
            return decision

    if verb in ALLOWED_SUBCOMMANDS:
        return Decision.allow(f"The `{invocation.command}` command is allowed.")
    return Decision.ask(f"The `{invocation.command}` command is not allowed by default.")


def validate_config(command:CommandLine, invocation:Invocation, context:Context) -> Decision:
    """
    Reading the git config is allowed, writing it asks.
    Anything that is not provably a read is a write: a write verb (`set`, `unset`, `edit`, ...), an untabled flag (`--add`, `--unset`, `--replace-all`, ...), or a second operand (`git config <name> <value>`).
    Only an explicit `--file` goes through check_access: the implicit config files (`~/.gitconfig`, `.git/config`) sit outside the project and would turn every read into an ASK.
    """
    references = invocation.references(Access.READ, "file")
    references += invocation.references(Access.WRITE, "output")
    if any(references):
        decision = check_access(command, references, context)
        if decision.verdict is not Verdict.ALLOW:
            return decision

    disallowed_args = [x for x in invocation.options if x.name not in CONFIG_READONLY_ARGS]
    if any(disallowed_args):
        return Decision.ask(f"`git config` requires the user validation when using {[x.key for x in disallowed_args]} flags.")
    if len(invocation.cmd_parts) > 2 and invocation.cmd_parts[2] not in CONFIG_READONLY_VERBS:
        return Decision.ask(f"The `{invocation.command}` command writes the git configuration and requires the user validation.")
    if len(invocation.positionals) > 1:
        return Decision.ask("`git config` requires the user validation when setting a value.")
    return Decision.allow("Reading the git configuration is allowed.")
