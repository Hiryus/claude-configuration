import re

from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, CommandLine, Reference
from parsers import sed

# A "simple" sed script: one or more `addr[,addr]p` print commands, separated by `;`.
# No `s`, `w`, `e`, `r`, ... commands -- those can write or execute arbitrary content.
SIMPLE_SCRIPT_RE = re.compile(r"^\s*(?:(?:\d+|\$)(?:,(?:\d+|\$))?\s*p\s*;?\s*)+$")


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    `sed` is only allowed when its script is provably read-only: no flag other than the quiet ones
    (every other flag is untabled, so it surfaces in `unknown`), and a script made solely of `p` commands.
    The files it reads are the operands after that script.
    """
    invocation = sed.parse(command)
    if invocation.unknown:
        return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")

    operands = [x for x in invocation.positionals if x.value is not None]
    if not operands or not SIMPLE_SCRIPT_RE.match(operands[0].value or ""):
        return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")

    references = [Reference(access=Access.READ, text=x.value, expansions=x.expansions) for x in operands[1:] if x.value is not None]
    return check_access(command, references, context)
