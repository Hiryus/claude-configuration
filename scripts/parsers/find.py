from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation
from parsers import arguments

GRAMMAR = CommandSyntax(
    aliases=["find"],
    flags=[
        Flag(name="debug", keys=["-D"], value_required=True),
        Flag(name="delete", keys=["-delete"], value_required=False),
        Flag(name="exec", keys=["-exec", "-execdir", "-ok","-okdir"], value_required=True),
        Flag(name="optimization", keys=["-O"], value_required=True),
        Flag(name="output-file", keys=["-fls", "-fprint", "-fprint0"], value_required=True),
        Flag(name="output-file", keys=["-fprintf"], value_required=True, value_count=2),
        Flag(name="pattern", keys=["-name", "-iname", "-path", "-wholename", "-lname"], value_required=True),
        Flag(name="symlinks-following", keys=["-H", "-L", "-P"], value_required=False),
    ],
)

def parse(command_line:CommandLine) -> Invocation:
    return arguments.parse(command_line=command_line, syntax=GRAMMAR)
