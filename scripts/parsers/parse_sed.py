import re
from pathlib import Path

from model import Command, Decision, Mode, Reference
from utils import check_access

# A "simple" sed script: one or more `addr[,addr]p` print commands, separated
# by `;`. No `s`, `w`, `e`, `r`, ... commands -- those can write or execute
# arbitrary content, so any script that doesn't fully match this is rejected.
SIMPLE_SED_SCRIPT_RE = re.compile(r"^\s*(?:(?:\d+|\$)(?:,(?:\d+|\$))?\s*p\s*;?\s*)+$")

# The only flags that keep sed read-only: they just silence the auto-print.
# Anything else (-i, -e, -f, ...) can write files or hide a script.
READONLY_FLAGS = ("-n", "--quiet", "--silent")

def check_sed(command: Command, project_root: Path) -> tuple[Decision, str]:
    """
    `sed` is only allowed when its script is provably read-only: no flag other
    than the quiet ones, and a script made solely of `p` print commands. The
    files it reads are the positional arguments after that script.
    """
    if any(x.low_key not in READONLY_FLAGS for x in command.named_args):
        return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")
    if not command.positional_args or not SIMPLE_SED_SCRIPT_RE.match(command.positional_args[0].value or ""):
        return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")
    references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args[1:] if arg.value is not None]
    return check_access(command, references, project_root)
