from model import Command, Decision

VERSION_FLAGS = ("--version", "-v")

# Subcommands that only report on the dependency tree.
READONLY_SUBCOMMANDS = ["ls", "outdated", "view"]

# Permission modes in which `npm prune` may touch node_modules unattended.
PRUNE_ALLOWED_MODES = ["acceptEdits", "auto", "bypassPermissions"]

def check_npm(command: Command, mode: str) -> tuple[Decision, str]:
    """
    `npm` is allow-listed per subcommand: the reporting ones are free, `prune`
    depends on the permission mode because it deletes from node_modules, and
    `audit` is only read-only until `--fix` turns it into an installer.
    """
    if len(command.args) == 1 and command.args[0].key in VERSION_FLAGS:
        return (Decision.ALLOW, "The `npm --version` command is allowed.")
    if command.subcommand in READONLY_SUBCOMMANDS:
        return (Decision.ALLOW, f"The `npm {command.subcommand}` command is allowed.")
    if command.subcommand == "prune":
        if mode in PRUNE_ALLOWED_MODES:
            return (Decision.ALLOW, "The `npm prune` command is allowed.")
        return (Decision.ASK, f"The `npm prune` command modifies node_modules; not allowed in {mode} mode.")
    if command.subcommand == "audit":
        if any(a.low_key == "--fix" or a.low_value == "fix" for a in command.args):
            return (Decision.ASK, "The `npm audit fix` command is not allowed by default.")
        return (Decision.ALLOW, "The `npm audit` command is allowed.")
    if command.subcommand:
        return (Decision.ASK, f"The `npm {command.subcommand}` command is not allowed by default.")
    else:
        return (Decision.ASK, "The `npm` command is not allowed by default.")
