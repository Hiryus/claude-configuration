from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, CommandLine, ParseError, Reference
from parsers import grep


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    Files grep reads: positional args, minus the search pattern itself (the first positional, unless supplied via -e/--regexp) and the values consumed by every other tabled flag.
    A `-f`/`--file` value is a file (grep reads patterns from it), so it counts as a read.
    """
    invocation = grep.parse(command)
    references = []

    # The first operand is the pattern, not a file -- unless the pattern was already given by -e/--regexp, in which case every operand is a file.
    positionals = invocation.positionals if invocation.has_arg("regexp") else invocation.positionals[1:]
    for arg in positionals:
        if arg.value is not None:
            references.append(Reference(access=Access.READ, text=arg.value))

    for arg in invocation.get_opts(name="file"):
        if arg.value is None:
            raise ParseError(f"{arg.key} must have a value")
        else:
            references.append(Reference(access=Access.READ, text=arg.value))

    return check_access(command, references, context)
