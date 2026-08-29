"""
The read-only binaries of [rule 2.8](../rules.md#28-read-only-binaries): commands whose operands
are the files they read.

Only the value-taking flags are tabled: an untabled one is already recorded as an unknown flag that
eats nothing, which is exactly right for a boolean. A value-taking flag left out, on the contrary,
drops its value in the positionals, where it is read as a file.

Every tabled flag falls in one of three buckets, named by `Flag.name`:
- `option`      -- the value is not a path (a count, a delimiter, a pattern): consume it, forget it,
- `input-file`  -- the value is a path the command reads,
- `output-file` -- the value is a path the command writes.

No `awk`/`sed` here: they can execute arbitrary programs. No `sort`/`uniq` either: `sort -o FILE` and `uniq INPUT OUTPUT` write a file, so neither is read-only.
"""

from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation, ParseError
from parsers import arguments

GRAMMARS = {
    # `cat` has no value-taking flag at all: every option is a boolean.
    "cat": CommandSyntax(aliases=["cat"]),

    "cmp": CommandSyntax(aliases=["cmp"], flags=[
        Flag(name="option", keys=["-i", "--ignore-initial", "-n", "--bytes"], value_required=True),
    ]),

    "cut": CommandSyntax(aliases=["cut"], flags=[
        Flag(name="option", keys=[
            "-b", "--bytes", "-c", "--characters", "-d", "--delimiter",
            "-f", "--fields", "--output-delimiter",
        ], value_required=True),
    ]),

    "diff": CommandSyntax(aliases=["diff"], flags=[
        Flag(name="input-file", keys=[
            "-S", "--starting-file", "-X", "--exclude-from", "--from-file", "--to-file",
        ], value_required=True),
        # `-U`/`-C` require their count, their long spellings make it optional.
        Flag(name="option", keys=["-U", "-C"], value_required=True),
        Flag(name="option", keys=["--unified", "--context", "--color"], value_required=False),
        Flag(name="option", keys=[
            "-D", "--ifdef", "-F", "--show-function-line", "-I", "--ignore-matching-lines",
            "-L", "--label", "-x", "--exclude", "-W", "--width", "--tabsize", "--horizon-lines",
        ], value_required=True),
    ]),

    "file": CommandSyntax(aliases=["file"], flags=[
        Flag(name="input-file", keys=["-f", "--files-from"], value_required=True),
        Flag(name="magic-file", keys=["-m", "--magic-file"], value_required=True),
        Flag(name="compile", keys=["-C", "--compile"], value_required=False),
        Flag(name="option", keys=["-e", "--exclude", "-F", "--separator", "-P", "--parameter"], value_required=True),
    ]),

    "head": CommandSyntax(aliases=["head"], flags=[
        Flag(name="option", keys=["-c", "--bytes", "-n", "--lines"], value_required=True),
    ]),

    "jq": CommandSyntax(aliases=["jq"], flags=[
        # `--from-file` supplies the filter, so it also decides whether the first operand is a file.
        Flag(name="program-file", keys=["-f", "--from-file"], value_required=True),
        Flag(name="input-file", keys=["--slurpfile", "--rawfile"], value_required=True, value_count=2),
        Flag(name="input-file", keys=["-L"], value_required=True),
        Flag(name="option", keys=["--arg", "--argjson"], value_required=True, value_count=2),
        Flag(name="option", keys=["--indent"], value_required=True),
    ]),

    "less": CommandSyntax(aliases=["less"], flags=[
        Flag(name="output-file", keys=["-o", "-O", "--log-file", "--LOG-FILE"], value_required=True),
        Flag(name="input-file", keys=["-k", "--lesskey-file", "-T", "--tag-file"], value_required=True),
        Flag(name="option", keys=[
            "-b", "--buffers", "-h", "--max-back-scroll", "-j", "--jump-target",
            "-p", "--pattern", "-P", "--prompt", "-t", "--tag", "-x", "--tabs",
            "-y", "--max-forw-scroll", "-z", "--window", "-#", "--shift",
        ], value_required=True),
    ]),

    "ls": CommandSyntax(aliases=["ls"], flags=[
        Flag(name="option", keys=["--color"], value_required=False),
        Flag(name="option", keys=[
            "--block-size", "--format", "--hide", "-I", "--ignore", "--indicator-style",
            "--quoting-style", "--sort", "-T", "--tabsize", "--time", "--time-style", "-w", "--width",
        ], value_required=True),
    ]),

    "more": CommandSyntax(aliases=["more"], flags=[
        Flag(name="option", keys=["-n", "--lines"], value_required=True),
    ]),

    "tail": CommandSyntax(aliases=["tail"], flags=[
        # `-f` is a boolean, `--follow[=how]` takes an optional value: neither may eat the file.
        Flag(name="option", keys=["-f", "--follow"], value_required=False),
        Flag(name="option", keys=[
            "-c", "--bytes", "-n", "--lines", "-s", "--sleep-interval",
            "--max-unchanged-stats", "--pid",
        ], value_required=True),
    ]),

    # `test` keeps an empty table on purpose: its "flags" are unary operators whose operand *is* the
    # file (`test -f .env`). Tabling them would make that path disappear from the positionals.
    "test": CommandSyntax(aliases=["test"]),

    "wc": CommandSyntax(aliases=["wc"], flags=[
        Flag(name="input-file", keys=["--files0-from"], value_required=True),
    ]),
}

def parse(command_line:CommandLine) -> Invocation:
    if command_line.base not in GRAMMARS:
        raise ParseError(f"`{command_line.base}` is not a read-only binary")
    return arguments.parse(command_line=command_line, syntax=GRAMMARS[command_line.base])
