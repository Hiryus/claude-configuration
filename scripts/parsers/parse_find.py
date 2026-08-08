from pathlib import Path

from model import Command, Decision, Mode, Reference
from utils import check_access

# find actions that write files or run arbitrary programs. Their presence
# breaks the read-only guarantee the search roots alone would give.
UNSAFE_ACTIONS = [
    "-delete", "-exec", "-execdir", "-fls",
    "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir",
]

def check_find(command: Command, project_root: Path) -> tuple[Decision, str]:
    """
    `find` is read-only as long as it uses none of the writing/executing
    actions. The files it reads are its search roots: the *leading* positional
    arguments, i.e. everything before the first flag (later positionals belong
    to the expression, e.g. the `*.py` of `-name '*.py'`).
    """
    for arg in UNSAFE_ACTIONS:
        if any(x.low_key == arg for x in command.args):
            return (Decision.ASK, f"`{command.base}` uses the {arg} argument.")
    # The leading positional arguments are the search roots.
    references = []
    for arg in command.args:
        if not arg.positional:
            break
        if arg.value is not None:
            references.append(Reference(mode=Mode.READ, text=arg.value))
    return check_access(command, references, project_root)
