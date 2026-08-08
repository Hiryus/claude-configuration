from pathlib import Path

from model import Command, Decision, Mode, Reference
from parsers.parse_bash import ParseError
from utils import check_access

# `git branch` flags that only list/format branches. Any other flag creates,
# renames, deletes or moves a branch, so it needs the user validation.
BRANCH_READONLY_ARGS = [
    "--color", "--no-color", "--show-current", "-v", "--abbrev", "--no-abbrev",
    "--column", "--no-column", "--sort=<key>", "--merged", "--no-merged",
    "--contains", "--no-contains", "--points-at", "--format",
    "-r", "--remotes", "-a", "--all", "--list",
]

# `git remote` subcommands that only print the current configuration.
REMOTE_READONLY_SUBCOMMANDS = ["show", "get-url"]

# Subcommands that inspect the repository, plus the staging/commit pair whose
# paths are vetted through check_access above.
ALLOWED_SUBCOMMANDS = [
    "add", "check-ignore", "commit", "diff", "grep", "hash-object", "log",
    "ls-files", "ls-tree", "merge-base", "rev-parse", "show", "status",
]

# Flags whose value is a file git writes its output to.
OUTPUT_FLAGS = ["--output", "-o"]

def check_git(command: Command, project_root: Path) -> tuple[Decision, str]:
    """
    `git` is allow-listed per subcommand. The global `-C`/`-c` flags are always
    refused (they relocate the repository / inject arbitrary config), the
    history-rewriting subcommands need the user validation, and any path git is
    told to write (`--output`) or stage (`add`/`commit`) goes through
    check_access first.
    """
    references = []
    if any(x.key == "-C" for x in command.args):
        return (Decision.DENY, "Do not use `git -C`: you are already at the repository root.")
    if any(x.key == "-c" for x in command.args):
        return (Decision.DENY, "Do not use `git -c` to inject config; it can run arbitrary code. Run the command directly.")
    if command.subcommand == "branch":
        if any(arg.key not in BRANCH_READONLY_ARGS for arg in command.named_args) or len(command.positional_args) > 1:
            return (Decision.ASK, "`git branch` requires the user validation.")
        return (Decision.ALLOW, "`git branch` is allowed by default.")
    if command.subcommand == "push":
        if any(arg.key in ["-f", "--force"] for arg in command.args):
            return (Decision.DENY, "`git push --force` is forbidden by the security policy: only the user is allowed to use it.")
        return (Decision.ASK, "`git push` requires the user validation.")
    for idx, arg in enumerate(command.args):
        if arg.low_key in OUTPUT_FLAGS:
            if not arg.value and len(command.args) <= idx + 1:
                raise ParseError("param --output has no value")
            value = arg.value if arg.value else command.args[idx + 1].value
            if value is None:
                raise ParseError("param --output has no value")
            references.append(Reference(mode=Mode.WRITE, text=value))
    if command.subcommand in ["add", "commit"]:
        references += [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args[1:] if arg.value is not None]
    if any(references):
        decision, reason = check_access(command, references, project_root)
        if decision != Decision.ALLOW: return decision, reason
    if command.subcommand == "remote":
        # No subcommand is allowed, including with --xxx modifyers
        if len(command.positional_args) == 1:
            return (Decision.ALLOW, "The `git remote` command is allowed.")
        # Read only subcommands are also ALLOWed
        remote_subcommand = command.args[1].value if (len(command.args) >= 2 and command.args[1].key is None) else None
        if remote_subcommand in REMOTE_READONLY_SUBCOMMANDS:
            return (Decision.ALLOW, f"The `git remote {remote_subcommand}` command is allowed.")
        # Everything else is ASK
        return (Decision.ASK, f"The `git remote {remote_subcommand}` command is not allowed by default.")
    if command.subcommand in ALLOWED_SUBCOMMANDS:
        return (Decision.ALLOW, f"The `git {command.subcommand}` command is allowed.")
    return (Decision.ASK, f"The `git {command.subcommand}` command is not allowed by default.")
