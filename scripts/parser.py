# pyright: reportMissingImports=false

import re

import bashlex
import bashlex.ast

from model import Argument, Command, Redirect


ASSIGNMENT_RE = re.compile(r"^[A-Za-z_]\w*=")


class ParseError(Exception):
    pass


class Parser:
    @staticmethod
    def build_argument(word: str) -> Argument:
        """
        Parse one shell token. A value is only attached when glued with `=`
        (`--out=foo`); the space-separated `--out foo` form spans two tokens,
        so its value is paired later by `Command.named_args`.
        """
        if word.startswith("-"):
            key, sep, value = word.partition("=")
            return Argument(key=key, positional=False, value=value if sep else None)
        return Argument(key=None, positional=True, value=word)

    @staticmethod
    def build_command(node: bashlex.ast.node) -> Command:
        """
        Split a CommandNode into program / args / redirects, skipping env prefixes.
        """
        parts = getattr(node, "parts", [])
        words = [p for p in parts if getattr(p, "kind", None) == "word"]
        redirect_nodes = [p for p in parts if getattr(p, "kind", None) == "redirect"]

        i = 0
        while i < len(words) and ASSIGNMENT_RE.match(words[i].word):
            i += 1
        real = words[i:]
        program_node = real[0] if real else None
        arg_nodes = real[1:]

        dynamic = is_dynamic(program_node) or any(is_dynamic(a) for a in arg_nodes)

        redirects = []
        for r in redirect_nodes:
            target = getattr(r, "output", None)
            is_node = isinstance(target, bashlex.ast.node)
            redirects.append(Redirect(
                target=getattr(target, "word", "") if is_node else "",
                type=getattr(r, "type", ""),
            ))
            if is_node and is_dynamic(target):
                dynamic = True

        return Command(
            program=getattr(program_node, "word", ""),
            args=[Parser.build_argument(a.word) for a in arg_nodes],
            redirects=redirects,
            dynamic=dynamic,
        )

    @staticmethod
    def collect(nodes: list, kind: str) -> list:
        """
        Every node of `kind` reachable from `nodes`, descending into children
        (including command/process substitutions). Iterative, so deep nesting
        cannot blow the recursion limit.
        """
        found = []
        stack = list(nodes)
        while stack:
            node = stack.pop()
            if getattr(node, "kind", None) == kind:
                found.append(node)
            for value in vars(node).values():
                if isinstance(value, bashlex.ast.node):
                    stack.append(value)
                elif isinstance(value, (list, tuple)):
                    stack.extend(v for v in value if isinstance(v, bashlex.ast.node))
        return found

    @staticmethod
    def parse(text: str) -> list[Command]:
        """
        Parse a bash prompt.
        Raises a ParseError on anything unparseable.
        """
        try:
            return [Parser.build_command(node) for node in Parser.collect(bashlex.parse(text), "command")]
        except Exception as err:
            raise ParseError(f"unparseable command: {err}") from err


def is_dynamic(node: bashlex.ast.node | None) -> bool:
    """
    A word built from a substitution/expansion -- value unknown at parse time.
    """
    return bool(getattr(node, "parts", None))
