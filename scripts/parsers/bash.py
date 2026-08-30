# bashlex imports are not properly recognized by linters and need to be ignored.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import bashlex
import bashlex.ast
from models.parsing import (
    Assignment,
    CommandLine,
    Expansion,
    ParseError,
    Redirect,
    Token,
)

# ============================================================================
# Builders
# ============================================================================

def build_assignment(node:bashlex.ast.node) -> Assignment:
    """
    Parse a bashlex "assignment" into an `Assignment` (name + value).
    """
    name, _, value = getattr(node, "word", "").partition("=")
    token = Token(text=value, expansions=expansions_of(node))
    return Assignment(name=name, value=token)


def build_command(node:bashlex.ast.node) -> CommandLine:
    """
    Parse a bashlex "command" into a `CommandLine` (with program / args / assignments / redirects).
    """
    parts = getattr(node, "parts", [])
    assignment_nodes = [p for p in parts if getattr(p, "kind", None) == "assignment"]
    redirect_nodes = [p for p in parts if getattr(p, "kind", None) == "redirect"]
    words = [p for p in parts if getattr(p, "kind", None) == "word"]

    return CommandLine(
        args=[build_token(x) for x in words[1:]],
        assignments=[build_assignment(x) for x in assignment_nodes],
        program=build_token(words[0]) if words else Token(text=""),
        redirects=[build_redirect(x) for x in redirect_nodes],
    )


def build_redirect(node:bashlex.ast.node) -> Redirect:
    """
    Parse a bashlex "redirect" into a `Redirect` (with target + type).
    """
    target = getattr(node, "output", None)
    is_node = isinstance(target, bashlex.ast.node)
    return Redirect(
        target=build_token(target) if is_node else Token(text=""),
        type=getattr(node, "type", ""),
    )


def build_token(node:bashlex.ast.node) -> Token:
    text = getattr(node, "word", "")
    return Token(text=text, expansions=expansions_of(node))

# ============================================================================
# Utilities
# ============================================================================

def child_nodes(node:bashlex.ast.node) -> list[bashlex.ast.node]:
    """
    Every node directly reachable from `node`, whatever attribute holds it (`parts`, `list`, `command`, `output`, ...).
    """
    children = []
    for value in vars(node).values():
        if isinstance(value, bashlex.ast.node):
            children.append(value)
        elif isinstance(value, (list, tuple)):
            children.extend(v for v in value if isinstance(v, bashlex.ast.node))
    return children


def collect(nodes:list) -> list[bashlex.ast.node]:
    """
    Return every "command" node reachable from `nodes`, descending into children (including command/process substitutions).
    Whether a command actually runs (an `if`/`for` body, the right of a `&&`) is not looked at.

    Grammar only, no policy.
    - Nodes are sorted by starting position, so `cd x; cmd` yields the `cd` first.
    - This function is iterative, so deep nesting does not blow the recursion limit.
    """
    found:list[bashlex.ast.node] = []
    seen:set[int] = set()
    stack:list[bashlex.ast.node] = list(nodes)
    while len(stack) > 0:
        node = stack.pop()
        if id(node) in seen:
            # A node can be reachable twice (ex: a `function` holds its body in both `body` and `parts`).
            continue
        seen.add(id(node))
        stack.extend(child_nodes(node))
        if getattr(node, "kind", None) == "command":
            found.append(node)
    return sorted(found, key=lambda node: node.pos[0])


def expansions_of(node:bashlex.ast.node|None) -> frozenset[Expansion]:
    """
    The top-level expansion kinds a word (or assignment value) is built from.
    An unrecognised part kind must not be silently dropped -- it surfaces as unparseable via the Expansion lookup.
    """
    if parts := getattr(node, "parts", None):
        return frozenset(Expansion(p.kind) for p in parts)
    return frozenset()


def resolve_scope(commands:list[CommandLine]) -> list[CommandLine]:
    """
    Fill each command's `environment` with the variables tracked from the earlier commands
    of the same prompt -- bare assignments (`FOO=bar`) and `export`, per rule 2.4: "tracked by
    the hook for potential impact on other commands (ex: `GIT_DIR` read by the `git` command)".

    `export NAME=value` arrives as a plain argument word, not an assignment node, so it is
    split by hand; a bare `export NAME` (exporting an already-set shell variable) is tracked
    with an empty value -- unknown, but the name still becomes visible to a later command.
    """
    tracked:dict[str, Token] = {}
    for command in commands:
        if not command.base:
            for assignment in command.assignments:
                tracked[assignment.name] = assignment.value
        elif command.base == "export":
            for arg in command.args:
                name, sep, value = arg.text.partition("=")
                tracked[name] = Token(text=value, expansions=arg.expansions) if sep else Token(text="")
        command.environment = {**tracked, **command.environment}
    return commands

# ============================================================================
# Entry point
# ============================================================================

def parse(text:str) -> list[CommandLine]:
    """
    Parse a bash prompt.
    Raises a `LexerError` on anything unparseable.
    """
    try:
        ast = bashlex.parse(text)
        return resolve_scope([build_command(node) for node in collect(ast)])
    except Exception as err:
        raise ParseError(f"unparseable command: {err}") from err
