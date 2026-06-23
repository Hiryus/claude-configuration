import os
from dataclasses import dataclass, field
from enum import Enum

# ============================================================================
# General flow
# ============================================================================

class Decision(Enum):
    """
    The verdict for one command. ALLOW < ASK < DENY in severity.
    """
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"

# ============================================================================
# Bash parsing
# ============================================================================

class Mode(Enum):
    """
    How a path is accessed by a command.
    """
    READ = "read"
    WRITE = "write"

@dataclass
class Argument:
    """
    One argument word: positional (`foo`) or named (`-o`, `--out`, `--out=foo`).
    """
    key: str|None      # None for positional args, else the flag (`-o`, `--out`)
    positional:bool
    value:str|None    # value glued to this token (`--out=foo`), else None

    @property
    def low_key(self) -> str|None:
        return self.key.lower() if self.key else None

    @property
    def low_value(self) -> str|None:
        return self.value.lower() if self.value else None

@dataclass
class Reference:
    """
    A path referenced by a command, with its access mode.
    """
    mode:Mode
    text:str

@dataclass
class Redirect:
    """
    One redirection, e.g. `> out.txt` or `< in.txt`.
    """
    target:str  # the file the redirect reads from / writes to ("" for fd-dups)
    type:str    # the operator: ">", ">>", "<", ...

@dataclass
class Command:
    """
    One parsed command: its program, argument words and redirects.
    """
    program:str
    args:list[Argument] = field(default_factory=list)
    redirects:list[Redirect] = field(default_factory=list)
    dynamic:bool = False  # any part (program, arg or redirect) is substitution-built

    @property
    def base(self) -> str:
        if not self.program:
            return ""
        return os.path.basename(self.program).lower().removesuffix(".exe")

    @property
    def named_args(self) -> list[Argument]:
        return [x for x in self.args if not x.positional]

    @property
    def positional_args(self) -> list[Argument]:
        return [x for x in self.args if x.positional]

    @property
    def subcommand(self) -> str | None:
        subcommand = self.positional_args[0].value if any(self.positional_args) else None
        return subcommand.lower() if subcommand else None
