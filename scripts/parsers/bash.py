# bashlex imports are not properly recognized by linters and need to be ignored.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

import itertools

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

# TODO: transform into a class for better readability
Tagged = tuple[bashlex.ast.node, tuple[int,...], bool]

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


def build_command(node:bashlex.ast.node, scope:tuple[int,...] = (), conditional:bool = False) -> CommandLine:
    """
    Parse a bashlex "command" into a `CommandLine` (with program / args / assignments / redirects),
    tagged with the execution shape it sits in (cf. `collect`).
    """
    parts = getattr(node, "parts", [])
    assignment_nodes = [p for p in parts if getattr(p, "kind", None) == "assignment"]
    redirect_nodes = [p for p in parts if getattr(p, "kind", None) == "redirect"]
    words = [p for p in parts if getattr(p, "kind", None) == "word"]

    return CommandLine(
        args=[build_token(x) for x in words[1:]],
        assignments=[build_assignment(x) for x in assignment_nodes],
        conditional=conditional,
        program=build_token(words[0]) if words else Token(text=""),
        redirects=[build_redirect(x) for x in redirect_nodes],
        scope=scope,
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


def collect(nodes:list) -> list[Tagged]:
    """
    Return every "command" node reachable from `nodes`, descending into children (including command/process substitutions), each tagged with:
    - its **scope**: the chain of enclosing isolation nodes -- a subshell `( )`, a substitution `$( )`/backticks/`<( )`, a pipeline stage, an async `&` segment. What such a command does to the current directory is invisible to the commands outside it.
    - whether it is **conditional**: it sits in an `if`/`for`/`while` body, or on the right of `&&`/`||`, so whether it runs at all cannot be known statically.

    Grammar only, no policy: what to do with either tag is the analyzer's call.
    - Nodes are sorted by starting position: `cat $(git log)` yields `cat` before `git log` (even though the substitution is executed first). The inversion is harmless -- both stages inherit the same directory.
    - This function is iterative, so deep nesting does not blow the recursion limit.
    """
    found:list[Tagged] = []
    scopes = itertools.count(1)
    stack:list[Tagged] = [(node, (), False) for node in nodes]
    while len(stack) > 0:
        node, scope, conditional = stack.pop()
        if getattr(node, "kind", None) == "command":
            found.append((node, scope, conditional))
        stack.extend(tag_children(node, scope, conditional, scopes))
    return sorted(found, key=lambda tagged: tagged[0].pos[0])


def expansions_of(node:bashlex.ast.node|None) -> frozenset[Expansion]:
    """
    The top-level expansion kinds a word (or assignment value) is built from.
    An unrecognised part kind must not be silently dropped -- it surfaces as unparseable via the Expansion lookup.
    """
    if parts := getattr(node, "parts", None):
        return frozenset(Expansion(p.kind) for p in parts)
    return frozenset()


def is_subshell(node:bashlex.ast.node) -> bool:
    """
    Return whether `node` is a subshell, i.e. whether it forks a new process to run its children.
    Ex: true for `( ... )`, false for `{ ...; }`
    """
    opening = next(iter(getattr(node, "list", [])), None)
    return getattr(opening, "word", "") == "("


def tag_children(node:bashlex.ast.node, scope:tuple[int,...], conditional:bool, scopes:"itertools.count") -> list[Tagged]:
    """
    Return the children of `node` with its scope and conditionality.
    """
    kind = getattr(node, "kind", None)
    if kind == "list":
        return tag_list(node, scope, conditional, scopes)
    if kind == "pipeline":
        # Every stage of a pipeline is its own subshell, so each one gets its own scope.
        return [(child, (*scope, next(scopes)), conditional) for child in child_nodes(node) if getattr(child, "kind", None) != "pipe"]
    if kind in ("commandsubstitution", "processsubstitution") or (kind == "compound" and is_subshell(node)):
        # Nodes that run their children in a subshell: a `cd` inside one is discarded on exit.
        return [(child, (*scope, next(scopes)), conditional) for child in child_nodes(node)]
    if kind in ("if", "for", "while", "until", "case", "function"):
        # Nodes whose children may run zero, one, or many times: how often is statically unknowable.
        return [(child, scope, True) for child in child_nodes(node)]
    return [(child, scope, conditional) for child in child_nodes(node)]


def tag_list(node:bashlex.ast.node, scope:tuple[int,...], conditional:bool, scopes:"itertools.count") -> list[Tagged]:
    """
    Walk a `;`/`&`/`&&`/`||` sequence, left to right:
    - After a `&&` or a `||`, a command runs only if the previous one succeeded (resp. failed), so it is conditional until the next `;` closes the chain;
    - A `&` sends everything since the last separator to the background, i.e. into its own subshell, so that whole segment is re-tagged with a fresh scope.
    """
    pending = conditional
    segment:list[int] = [] # indices in `tagged` of the commands since the last `;`/`&`
    tagged:list[Tagged] = []
    for part in getattr(node, "parts", []):
        if getattr(part, "kind", None) != "operator":
            segment.append(len(tagged))
            tagged.append((part, scope, pending))
            continue
        operator = getattr(part, "op", "")
        if operator in ("&&", "||"):
            pending = True
            continue
        if operator == "&":
            for index in segment:
                isolated = (*scope, next(scopes))
                tagged[index] = (tagged[index][0], isolated, tagged[index][2])
        pending = conditional
        segment = []
    return tagged

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
        return [build_command(node, scope, conditional) for node, scope, conditional in collect(ast)]
    except Exception as err:
        raise ParseError(f"unparseable command: {err}") from err
