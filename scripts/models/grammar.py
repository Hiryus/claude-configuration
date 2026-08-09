"""
Declarative flag/subcommand tables, shared by every per-binary grammar.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Flag:
    """
    One flag, under every spelling it is known by.
    """
    name:str                  # canonical, joins to policy: "message", "output", "only"
    keys:list[str]            # every spelling: ("-m", "--message")
    value_required:bool

@dataclass(frozen=True)
class CommandSyntax:
    """
    A binary or a nested verb -- recursive, so the same type describes
    `docker` and `docker container ls` alike.
    """
    aliases:list[str] # keys[0] is canonical: ("list", "ls")
    flags:list[Flag]  = field(default_factory=list)
    subcommands:list["CommandSyntax"] = field(default_factory=list)

    def __post_init__(self):
        if len(self.aliases) == 0:
            raise ValueError("keys must contain at least one value")
