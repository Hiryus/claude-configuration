"""
Grammar-driven argument walking.
"""

from models.grammar import CommandSyntax, Flag
from models.parsing import Argument, CommandLine, Invocation, ParseError, Token


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
            arguments.extend(parse_flag(token, tokens, flags))
        else:
            # The token is a positional argument: record it.
            # It also closes the subcommand walk: every CLI here spells its verbs before its operands,
            # so a later verb-shaped token is a value (`git config user.name list` sets `user.name=list`).
            arguments.append(Argument(value=token.text, expansions=token.expansions))
            operand_seen = True

    return Invocation(cmd_parts=path, arguments=arguments)


def parse_flag(token:Token, tokens:list[Token], potential_flags:list[Flag]) -> list[Argument]:
    """
    Parse the given token as an argument based on a list of expected flags.
    May consume the next token as value for flags in the form "--key value".
    If no flag matches, create an unknown argument without consuming next token.
    """
    key = token.text.partition("=")[0]

    # Known flag (as a whole token), consume value if any
    if flag := next((x for x in potential_flags if key in x.keys), None):
        value = parse_value(key=key, token=token, tokens=tokens, value_required=flag.value_required)
        return [Argument(key=key, name=flag.name, value=value, expansions=token.expansions)]

    # Not a known flag as a whole token.
    # Try to split it into individual short flags (ex: "-it" -> "-i", "-t").
    if len(key) > 2 and not key.startswith("--"):  # noqa: SIM102
        if glued := parse_glued_args(token, tokens, potential_flags):
            return glued

    # Unknown flag: record it and do not consume next token as value
    value = parse_value(key=key, token=token, tokens=tokens, value_required=False)
    return [Argument(key=key, name=None, value=value, known=False, expansions=token.expansions)]


def parse_glued_args(token:Token, tokens:list[Token], potential_flags:list[Flag]) -> list[Argument] | None:
    """
    Attempt to split a single-dash token like "-it" into its component short flags ("-i", "-t").
    Only succeeds if every character resolves to a known flag and no non-terminal flag in the group requires a value.
    Only the last flag in the group may consume a value, matching typical getopt-style semantics).
    Returns None if the token can't be cleanly split.
    """
    key = token.text.partition("=")[0]

    resolved:list[Flag] = []
    for letter in key[1:] : # drop the leading "-"
        if flag := next((x for x in potential_flags if f"-{letter}" in x.keys), None):
            resolved.append(flag)
        else: # no flag matches the current letter
            return None

    # Check if any of the arguments requires a value except the last one.
    # A flag that requires a value can't sit in the middle of a glued group (ex: "-if" where -i needs a value would be ambiguous) — bail out.
    if any(x.value_required for x in resolved[:-1]):
        return None

    results:list[Argument] = []
    last_index = len(resolved) - 1
    for i, flag in enumerate(resolved):
        if i != last_index:
            results.append(Argument(key=flag.keys[0], name=flag.name, value=None, expansions=token.expansions))
        else:
            value = parse_value(key=flag.name, token=token, tokens=tokens, value_required=flag.value_required)
            results.append(Argument(key=flag.keys[0], name=flag.name, value=value, expansions=token.expansions))

    return results


def parse_value(key:str, token:Token, tokens:list[Token], value_required:bool) -> str | None:
    if "=" in token.text:
        return token.text.partition("=")[2]
    elif value_required:
        if len(tokens) == 0:
            raise ParseError(f"flag {key} requires a value, but none was provided")
        return tokens.pop(0).text
    else:
        return None
