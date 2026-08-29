from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, Argument, CommandLine, Invocation, Reference
from parsers import readonly


def handles(base:str) -> bool:
    """
    True when the binary is one of the read-only ones this analyzer knows.
    """
    return base in readonly.GRAMMARS


def operands(command:CommandLine, invocation:Invocation) -> list[Argument]:
    """
    `jq`'s first operand is its filter program, not a file -- unless `-f`/`--from-file` already
    supplied the filter, in which case every operand is an input file (same shape as `grep -e`).
    """
    if command.base == "jq" and not invocation.has_arg("program-file"):
        return invocation.positionals[1:]
    return invocation.positionals


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    Files a read-only binary touches: its operands, plus the values of the flags that name a path.
    A tabled flag eats its value, so a count or a delimiter never reaches the operands to be read as a file.
    """
    invocation = readonly.parse(command)
    references = invocation.references(Access.READ, "input-file", "program-file", "magic-file")
    references += invocation.references(Access.WRITE, "output-file")
    references += [Reference(access=Access.READ, text=arg.value, expansions=arg.expansions) for arg in operands(command, invocation) if arg.value is not None]
    if command.base == "file" and invocation.has_arg("compile"):
        # `-C` compiles `-m`'s value into `PATH.mgc`, an extra write reference alongside its read one.
        references += invocation.references(Access.WRITE, "magic-file")
    return check_access(command, references, context)
