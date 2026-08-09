from generic import check_access
from models.analyzer import Context, Decision
from models.parsing import Access, CommandLine, ParseError, Reference
from parsers import find


def validate(command:CommandLine, context:Context) -> tuple[Decision, str]:
    """
    `find` is an expression grammar, not getopt: leading flags, then the search roots, then the expression.
    The files it reads are the roots; expression values (`-name '*.py'`) are patterns, never references.
    """
    invocation = find.parse(command)
    references = []

    if any(x.name == "exec" for x in invocation.arguments):
        return (Decision.DENY, "Using the `-exec` argument with `find` is forbidden.")

    if any(x.name == "delete" for x in invocation.arguments):
        return (Decision.DENY, "Using the `-delete` argument with `find` is forbidden.")

    for arg in [x for x in invocation.arguments if x.name == "output-file"]:
        if arg.value is None:
            raise ParseError(f"{arg.key} must have a value")
        else:
            references.append(Reference(access=Access.WRITE, text=arg.value))

    for arg in invocation.positionals:
        if arg.value and arg.value not in ("!", "(", ")"):
            references.append(Reference(access=Access.READ, text=arg.value))

    return check_access(command, references, context)
