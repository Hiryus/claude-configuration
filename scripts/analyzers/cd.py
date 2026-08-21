from pathlib import Path

from models.analyzer import Context, Decision
from models.parsing import CommandLine, Invocation
from parsers import cd
from utils.filesystem import normalize, standardize


def bash_target(operand:str, invocation:Invocation, cwd:Path) -> Path:
    """
    The directory `cd` really lands in, canonicalized the way bash does it.
    By default (`-L`) bash works on the path *as written*, so `link/..` is the directory holding `link`; `-P` asks for the kernel's own resolution instead, which follows the symlink first. When both flags are given, the last one wins.
    When the logical target does not exist, bash retries with the raw path (`cd /var/run/../etc` lands in `/etc` because `/var/etc` does not exist), so the physical one is the fallback rather than an error.
    """
    modes = [x.name for x in invocation.options if x.name in ("logical", "physical")]
    logical = normalize(operand, cwd)
    if modes and modes[-1] == "physical":
        return standardize(operand, cwd)
    return logical if logical.is_dir() else standardize(operand, cwd)

def validate(command:CommandLine, context:Context, first:bool) -> tuple[Decision, str, Path | None]:
    """
    Rule 2.3: `cd` is allowed when the hook can resolve the target with certainty and it is an existing directory.
    Otherwise the move is refused, because every later relative path would be resolved against a directory the shell is not actually in.
    "With certainty" also means nothing may run before it: an earlier command could delete the target (`rm -rf x; cd x`) or retarget it (`CDPATH=/other; cd x`), and the shell would then stay elsewhere while the hook kept resolving against the move. Hence `first`, which the caller computes from the position-sorted command list.
    `cd` is a special command whose verdict also produces state, so this returns a 3-tuple (verdict, reason, new cwd) and must never be fed to `worst()`.
    """
    if command.conditional:
        return (Decision.DENY, "`cd` may not sit in a conditional or repeated context (`&&`, `||`, `if`, `for`, `while`, function body): whether it runs cannot be known, so the current directory becomes unknown.", None)

    if not first:
        return (Decision.DENY, "`cd` must be the first command of the command line: anything running before it could delete or retarget its destination, leaving the hook resolving paths against a directory the shell never reached. Run it first (`cd x; cmd`), or on its own.", None)

    if command.assignments:
        return (Decision.DENY, "`cd` may not carry a prefix assignment: `CDPATH=... cd x` lands the shell somewhere else entirely. Run `cd` bare.", None)

    if command.dynamic:
        return (Decision.DENY, "`cd` target is built from a substitution or an expansion, so the hook cannot tell where the shell would land. Write the path literally.", None)

    invocation = cd.parse(command)

    # `arguments.parse` classifies the bare `-` as an unknown flag, not as an operand.
    if invocation.unknown == ["-"] and not invocation.positionals:
        return (Decision.DENY, "`cd -` is not supported: it goes back to `$OLDPWD`, which any earlier command can overwrite. Name the directory explicitly.", None)

    if invocation.unknown:
        return (Decision.DENY, f"`cd` option {invocation.unknown[0]} is not supported; only `-P` and `-L` are.", None)

    operands = [x.value for x in invocation.positionals if x.value is not None]
    if len(operands) > 1:
        return (Decision.DENY, "`cd` takes a single directory.", None)

    # No operand means $HOME
    target = bash_target(operands[0], invocation, context.current_cwd) if operands else Path.home()
    if not isinstance(target, Path) or not target.is_dir():
        return (Decision.DENY, f"`cd` target `{target}` is not an existing directory. Create it first before changing directory.", None)

    return (Decision.ALLOW, f"changing directory to `{target}` is allowed.", target)
