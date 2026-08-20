from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation
from parsers import arguments

GRAMMAR = CommandSyntax(
    aliases=["cd"],
    flags=[
        # The two flags that only pick how symlinks are read: neither changes where we land in a way the hook can't follow.
        # Anything else (-e, -@, ...) stays untabled so it surfaces in `unknown` and the move is refused rather than mistracked.
        Flag(name="physical", keys=["-P"], value_required=False),
        Flag(name="logical", keys=["-L"], value_required=False),
    ],
)

def parse(command_line:CommandLine) -> Invocation:
    """
    Note on `cd -`: a bare `-` is classified as an *unknown flag*, not as an operand (`arguments.parse` splits on the leading dash).
    Tabling it as a `Flag` would also swallow the `-` of `cd -- -`, which is a directory named "-".
    """
    return arguments.parse(command_line=command_line, syntax=GRAMMAR)
