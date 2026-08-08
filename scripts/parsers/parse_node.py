from pathlib import Path

from model import Command, Decision, Mode, Reference
from utils import check_access

VERSION_FLAGS = ("--version", "-v")

def check_node(command: Command, project_root: Path) -> tuple[Decision, str]:
    """
    `node` runs arbitrary JavaScript, so nothing is allowed but the two
    inert forms: printing the version, and `--check` which only parses the
    files it is given (those paths still go through check_access).
    """
    if len(command.args) == 1 and command.args[0].key in VERSION_FLAGS:
        return (Decision.ALLOW, "The `node --version` command is allowed.")
    if len(command.args) >= 1 and command.args[0].key == "--check":
        references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args if arg.value is not None]
        return check_access(command, references, project_root)
    if command.subcommand and len(command.subcommand) <= 50:
        return (Decision.ASK, f"The `node {command.subcommand}` command is not allowed by default.")
    else:
        return (Decision.ASK, "The `node` command is not allowed by default.")
