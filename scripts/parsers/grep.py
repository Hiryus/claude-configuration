from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation
from parsers import arguments

GRAMMAR = CommandSyntax(
    aliases=["grep"],
    flags=[
        Flag(name="binary-files", keys=["--binary-files"], value_required=True),
        Flag(name="color", keys=["--color", "--colour"], value_required=False),
        Flag(name="file", keys=["-f", "--file"], value_required=True),
        Flag(name="label", keys=["--label"], value_required=True),
        Flag(name="regexp", keys=["-e", "--regexp"], value_required=True),
        # Every other value-taking flag: the value is neither a pattern nor a file,
        # so it only needs to be consumed correctly, never referenced individually.
        Flag(name="option", keys=[
            "-a", "-A", "--after-context", "-b", "-B", "--before-context", "-C", "--context",
            "-d", "--directories", "-D", "--devices", "-m", "--max-count",
            "--include", "--exclude", "--exclude-dir", "--exclude-from",
            "--group-separator", "--context-separator",
        ], value_required=True),
    ],
)

def parse(command_line:CommandLine) -> Invocation:
    return arguments.parse(command_line=command_line, syntax=GRAMMAR)
