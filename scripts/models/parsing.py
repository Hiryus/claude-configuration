import os
from dataclasses import dataclass, field
from enum import StrEnum

# ============================================================================
# Custom errors
# ============================================================================

class ContextError(Exception):
    """
    The hook cannot establish the ambient facts of the call (project root, current directory).
    """

class ParseError(Exception):
    """
    The hook cannot parse the command line (usually means the call uses an invalid syntax).
    """

# ============================================================================
# Generic types
# ============================================================================

class Access(StrEnum):
    """
    How a path is accessed by a command.
    """
    READ = "read"
    WRITE = "write"

class Expansion(StrEnum):
    """
    The kind of a top-level shell expansion a word is built from.
    """
    TILDE     = "tilde"                # ~/x, ~user/x
    PARAMETER = "parameter"            # $FOO, ${FOO}
    COMMAND   = "commandsubstitution"  # $(...), `...`
    PROCESS   = "processsubstitution"  # <(...), >(...)

# ============================================================================
# Bash command and associated types (low level)
# ============================================================================

@dataclass(frozen=True)
class Token:
    """
    One dequoted shell word, tagged with the expansions it is built from.
    """
    text:str
    expansions:frozenset[Expansion] = frozenset()

    @property
    def dynamic(self) -> bool:
        return bool(self.expansions - {Expansion.TILDE})

@dataclass(frozen=True)
class Assignment:
    """
    One prefix assignment, e.g. the `GIT_DIR=x` of `GIT_DIR=x git status`.
    """
    name:str
    value:Token

@dataclass
class Redirect:
    """
    One redirection, e.g. `> out.txt` or `< in.txt`.
    """
    target:Token  # the file the redirect reads from / writes to ("" for fd-dups)
    type:str      # the operator: ">", ">>", "<", ...

@dataclass
class Reference:
    """
    A path referenced by a command, with its access mode.
    """
    access:Access
    text:str

@dataclass
class CommandLine:
    """
    One parsed command: its program, argument words, prefix assignments and redirects.
    """
    program:Token
    args:list[Token] = field(default_factory=list)
    assignments:list[Assignment] = field(default_factory=list)
    redirects:list[Redirect] = field(default_factory=list)
    environment:dict[str, Token] = field(default_factory=dict)

    @property
    def base(self) -> str:
        if not self.program.text:
            return ""
        return os.path.basename(self.program.text).lower().removesuffix(".exe")

    @property
    def subcommand(self) -> str | None:
        subcommand = next((arg.text for arg in self.args if not arg.text.startswith("-")), None)
        return subcommand.lower() if subcommand else None

    @property
    def dynamic(self) -> bool:
        return self.program.dynamic or any(a.dynamic for a in self.args) \
            or any(a.value.dynamic for a in self.assignments) \
            or any(r.target.dynamic for r in self.redirects)

# ============================================================================
# Higher level commands (Invocations) and their arguments
# ============================================================================

@dataclass(frozen=True)
class Argument:
    """
    An argument in a command invocation (either a flag or a positional operand).
    """
    key:str|None = None    # None for an operand
    known:bool = True      # False when the key matched no Flag
    name:str|None = None   # canonical Flag.name; None for operands and untabled flags
    value:str|None = None
    expansions:frozenset[Expansion] = frozenset()  # carried over from the source Token

    @property
    def positional(self) -> bool:
        return self.key is None

    @property
    def is_dynamic(self) -> bool:
        return bool(self.expansions - {Expansion.TILDE})

@dataclass
class Invocation:
    """
    A CommandLine parsed with a known grammar.
    """
    arguments:list[Argument]
    cmd_parts:list[str] # ex: ["git", "commit"], ["docker", "container", "ls"])

    @property
    def command(self) -> str:
        return " ".join(self.cmd_parts)

    @property
    def options(self) -> list[Argument]:
        return [a for a in self.arguments if not a.positional]

    @property
    def positionals(self) -> list[Argument]:
        return [a for a in self.arguments if a.positional]

    @property
    def subcommand(self) -> str|None:
        if len(self.cmd_parts) > 1:
            return " ".join(self.cmd_parts[1:])
        return None

    @property
    def unknown(self) -> list[str]:
        return [a.key for a in self.options if not a.known and a.key is not None]

    def get_opts(self, name:str) -> list[Argument]:
        return [x for x in self.options if x.name == name]

    def has_arg(self, *names:str) -> bool:
        return any(a.name in names for a in self.options)

    def values(self, *names:str) -> list[str]:
        """
        Every value given to `names`, for the options that may repeat (`-v`, `-e`).
        """
        return [a.value for a in self.options if a.name in names and a.value is not None]
