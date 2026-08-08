from model import Command, Mode, Reference

# grep flags that consume a separate token as their value.
PATTERN_VALUE_FLAGS = {"-e", "--regexp"}        # value is a search pattern, not a file
FILE_VALUE_FLAGS = {"-f", "--file"}              # value is a file grep reads patterns from
OTHER_VALUE_FLAGS = {                            # value is neither a pattern nor a file
    "-a", "-A", "--after-context", "-b", "-B", "--before-context", "-C", "--context",
    "-d", "--directories", "-D", "--devices", "-m", "--max-count",
    "--binary-files", "--color", "--colour", "--label",
    "--include", "--exclude", "--exclude-dir", "--exclude-from",
    "--group-separator", "--context-separator",
}

def grep_references(command: Command) -> list[Reference]:
    """
    Files grep reads: positional args, minus the search pattern itself (the
    first positional arg, unless supplied via -e/--regexp) and the values
    consumed by other flags. A `-f`/`--file` value is a file (grep reads
    patterns from it), so it counts as a read.
    """
    references = []
    pattern_flag_used = False
    pattern_consumed = False
    consume_next = None  # "file" | "skip"
    for arg in command.args:
        if consume_next is not None and arg.positional:
            if consume_next == "file":
                references.append(Reference(mode=Mode.READ, text=arg.value))
            consume_next = None
            continue
        if not arg.positional:
            if arg.low_key in PATTERN_VALUE_FLAGS:
                pattern_flag_used = True
                if arg.value is None:
                    consume_next = "skip"  # the pattern itself: not a file
                continue
            if arg.low_key in FILE_VALUE_FLAGS:
                if arg.value is not None:
                    references.append(Reference(mode=Mode.READ, text=arg.value))
                else:
                    consume_next = "file"
                continue
            if arg.low_key in OTHER_VALUE_FLAGS and arg.value is None:
                consume_next = "skip"
            continue
        if not pattern_flag_used and not pattern_consumed:
            pattern_consumed = True
            continue
        if arg.value is not None:
            references.append(Reference(mode=Mode.READ, text=arg.value))
    return references
