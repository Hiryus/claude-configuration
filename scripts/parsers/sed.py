from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation
from parsers import arguments

GRAMMAR = CommandSyntax(
    aliases=["sed"],
    flags=[
        # The only flag that keeps sed read-only: it just silences the auto-print.
        # Anything else (-i, -e, -f, ...) can write files or hide a script, and stays untabled so it surfaces in `unknown`.
        Flag(name="quiet", keys=["-n", "--quiet", "--silent"], value_required=False),
    ],
)

def parse(command_line:CommandLine) -> Invocation:
    return arguments.parse(command_line=command_line, syntax=GRAMMAR)
