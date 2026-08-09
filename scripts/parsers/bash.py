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
        assignments=[build_assignment(x) for x in assignment_nodes],
        args=[build_token(x) for x in words[1:]],
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


def collect(nodes:list, kind:str) -> list:
    """
    Return every node of `kind` reachable from `nodes`, descending into children (including command/process substitutions).
    - Nodes are sorted by starting position: `cat $(git log)` yields `cat` before `git log` (even though the substitution is executed first in a).
    - This function is iterative, so deep nesting does not blow the recursion limit.
    """
    found = []
    stack = list(nodes)
    while len(stack) > 0:
        node = stack.pop()
        if getattr(node, "kind", None) == kind:
            found.append(node)
        for value in vars(node).values():
            if isinstance(value, bashlex.ast.node):
                stack.append(value)
            elif isinstance(value, (list, tuple)):
                stack.extend(v for v in value if isinstance(v, bashlex.ast.node))
    return sorted(found, key=lambda n: n.pos[0])


def expansions_of(node:bashlex.ast.node|None) -> frozenset[Expansion]:
    """
    The top-level expansion kinds a word (or assignment value) is built from.
    An unrecognised part kind must not be silently dropped -- it surfaces as unparseable via the Expansion lookup.
    """
    if parts := getattr(node, "parts", None):
        return frozenset(Expansion(p.kind) for p in parts)
    return frozenset()


def parse(text:str) -> list[CommandLine]:
    """
    Parse a bash prompt.
    Raises a `LexerError` on anything unparseable.
    """
    try:
        ast = bashlex.parse(text)
        return [build_command(node) for node in collect(ast, "command")]
    except Exception as err:
        raise ParseError(f"unparseable command: {err}") from err
