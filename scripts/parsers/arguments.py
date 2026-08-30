"""
Grammar-driven argument walking.
"""

from models.grammar import CommandSyntax, Flag
from models.parsing import Argument, CommandLine, Invocation, ParseError, Token
from utils.parsing import is_flag


def parse(command_line:CommandLine, syntax:CommandSyntax) -> Invocation:
    """
    Walk the subcommand chain of `syntax`, resolving flag inheritance at each level, then pair whatever is left against the fully accumulated flags.
    - A `--` token ends the walk: every token after it is an operand.
    - The first operand ends it too: a verb never follows an operand, so a verb-shaped token after one is a value.
    """
    arguments:list[Argument] = []
    flags = syntax.flags[:]
    path:list[str] = [syntax.aliases[0]]
    tokens = command_line.args[:]
    operand_seen = False

    while len(tokens) > 0:
        token = tokens.pop(0)
        if token.text == "--":
            # End of options: whatever follows is an operand, even when it looks like a flag or a subcommand.
            # The separator itself is not an argument and is dropped.
            arguments.extend(Argument(value=x.text, expansions=x.expansions) for x in tokens)
            break
        elif not operand_seen and (subcommand := next((x for x in syntax.subcommands if token.text in x.aliases), None)):
            # The token matches a subcommand: descend into it, and accumulate its flags for the next walk
            path.append(subcommand.aliases[0])
            flags = subcommand.flags + flags # subcommand flags take precedence over the parent ones
            syntax = subcommand
        elif token.text.startswith("-"):
            # The token is a named argument (a flag): parse it and consume its value if any.
            # This may expand into several arguments if it's a glued short-flag group (e.g. "-it").
            if operand_seen and syntax.opaque_tail:
                # Past the trusted operand of an opaque-tailed node, a flag-shaped token may belong
                # to a separate, unrelated command line: record it as unknown rather than aborting.
                try:
                    arguments.extend(parse_flag(token, tokens, flags))
                except ParseError:
                    arguments.append(build_argument(key=token.text.partition("=")[0], name=None, token=token, value=None, known=False))
            else:
                arguments.extend(parse_flag(token, tokens, flags))
        else:
            # The token is a positional argument: record it.
            # It also closes the subcommand walk: every CLI here spells its verbs before its operands,
            # so a later verb-shaped token is a value (`git config user.name list` sets `user.name=list`).
            arguments.append(Argument(value=token.text, expansions=token.expansions))
            operand_seen = True

    return Invocation(cmd_parts=path, arguments=arguments, opaque_tail=syntax.opaque_tail)


def parse_flag(token:Token, tokens:list[Token], potential_flags:list[Flag]) -> list[Argument]:
    """
    Parse the given token as an argument based on a list of expected flags.
    May consume the next token as value for flags in the form "--key value".
    If no flag matches, create an unknown argument without consuming next token.
    """
    key = token.text.partition("=")[0]

    # Known flag (as a whole token), consume value if any
    if flag := next((x for x in potential_flags if key in x.keys), None):
        value = parse_value(key=key, token=token, tokens=tokens, value_required=flag.value_required, value_count=flag.value_count)
        return [build_argument(key=key, name=flag.name, token=token, value=value)]

    # Not a known flag as a whole token.
    # Try to split it into individual short flags (ex: "-it" -> "-i", "-t").
    if len(key) > 2 and not key.startswith("--"):  # noqa: SIM102
        if glued := parse_glued_args(token, tokens, potential_flags):
            return glued

    # Unknown flag: record it and do not consume next token as value
    value = parse_value(key=key, token=token, tokens=tokens, value_required=False)
    return [build_argument(key=key, name=None, token=token, value=value, known=False)]


def parse_glued_args(token:Token, tokens:list[Token], potential_flags:list[Flag]) -> list[Argument] | None:
    """
    Attempt to split a single-dash token like "-it" into its component short flags ("-i", "-t").
    Walks the letters left to right: a boolean flag continues the walk, but a value-required flag ends it immediately, getopt-style,
    taking whatever remains of the token as its glued value (ex: "-u0" -> "-u" "0", "-f.env" -> "-f" ".env") instead of trying to resolve it as more flags.
    Only the very last letter may pull its value from the next word instead (ex: "-uroot" vs "-u root").
    Returns None if some letter matches no known flag.
    """
    key = token.text.partition("=")[0]
    letters = key[1:]  # drop the leading "-"

    results:list[Argument] = []
    last_index = len(letters) - 1
    for idx, letter in enumerate(letters):
        flag = next((x for x in potential_flags if f"-{letter}" in x.keys), None)
        if flag is None: # no flag matches the current letter
            return None

        if flag.value_required and idx != last_index:
            # The rest of the token is this flag's value, glued directly: it is never re-walked as more letters.
            # Sliced from `token.text`, not `letters`: `letters` is cut at the first "=" (so a whole flag spelled exactly, ex: "-e=x", still resolves at the top of `parse_flag`),
            # but "=" carries no such meaning here -- a mid-cluster glued value keeps it verbatim (ex: "-eFOO=bar" -> value "FOO=bar").
            value = Token(text=token.text[idx + 2:], expansions=token.expansions)
            results.append(build_argument(key=flag.keys[0], name=flag.name, token=token, value=value))
            return results

        if idx != last_index:
            results.append(Argument(key=flag.keys[0], name=flag.name, value=None, expansions=token.expansions))
        else:
            value = parse_value(key=flag.name, token=token, tokens=tokens, value_required=flag.value_required, value_count=flag.value_count)
            results.append(build_argument(key=flag.keys[0], name=flag.name, token=token, value=value))

    return results


def parse_value(key:str, token:Token, tokens:list[Token], value_required:bool, value_count:int = 1) -> Token | None:
    """
    The value of a flag, either glued behind an `=` or taken from the next word(s).
    It stays a `Token` so a `--file $VAR` value keeps the expansions of the word it came from: they
    belong to the value, not to the flag, and the path check reads them off the resulting `Argument`.

    A flag eating several words (`jq --arg NAME VALUE`) keeps the last one as its value -- that is the
    one that may be a path (`jq --slurpfile NAME FILE`) -- and the expansions of all of them, so none
    of the words it swallowed escapes the dynamic check.
    """
    if "=" in token.text:
        if value_count > 1:
            raise ParseError(f"flag {key} requires {value_count} value(s), which `=` cannot carry (use `{key} NAME VALUE`)")
        return Token(text=token.text.partition("=")[2], expansions=token.expansions)
    elif value_required:
        if len(tokens) < value_count:
            raise ParseError(f"flag {key} requires {value_count} value(s), but only {len(tokens)} were provided")
        # A flag-shaped word is never silently taken as a value: it may hide a genuine error (ex: `--name -v ./x:/y` would name the container "-v" and misplace the volume flag).
        # Use `--flag=value` or `--` to pass a value that genuinely starts with a dash.
        if flag_shaped := [x.text for x in tokens[:value_count] if is_flag(x.text)]:
            raise ParseError(f"flag {key} requires a value, but {flag_shaped} looks like a flag (if this is intended, use `{key}=value` instead)")
        consumed = [tokens.pop(0) for _ in range(value_count)]
        return Token(text=consumed[-1].text, expansions=frozenset(x for word in consumed for x in word.expansions))
    else:
        return None


def build_argument(key:str, name:str|None, token:Token, value:Token|None, known:bool = True) -> Argument:
    """
    Pair a flag token with the value it consumed, carrying the expansions of both.
    """
    return Argument(
        key=key,
        name=name,
        value=value.text if value is not None else None,
        known=known,
        expansions=token.expansions | (value.expansions if value is not None else frozenset()),
    )
