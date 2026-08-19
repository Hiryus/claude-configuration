from pathlib import Path

from models.analyzer import Context, Decision
from models.parsing import CommandLine
from parsers import cd
from utils.filesystem import standardize

# The new `(cwd, previous_cwd)` a successful `cd` produces. Both are per-shell in bash,
# so both inherit and are discarded on exactly the same scope boundaries.
Move = tuple[Path, Path | None]


def validate(command:CommandLine, context:Context) -> tuple[Decision, str, Move | None]:
    """
    Rule 2.3: `cd` is allowed when the hook can resolve the target with certainty and it
    really is a directory; otherwise the move is refused, because every later relative path
    would be resolved against a directory the shell is not actually in.

    `cd` is the only command whose verdict also produces state, so this returns a 3-tuple
    (verdict, reason, move) and must never be fed to `worst()`.
    """
    if command.conditional:
        return (Decision.DENY, "`cd` may not sit in a conditional context (`&&`, `||`, `if`, `for`, `while`): whether it runs cannot be known, so the current directory becomes unknown. Run it as a plain sequence (`cd x; cmd`).", None)

    invocation = cd.parse(command)

    # `cd -` goes back to $OLDPWD, which bash keeps per shell -- so the hook tracks it per scope.
    # `arguments.parse` classifies the bare `-` as an unknown flag, not as an operand.
    if invocation.unknown == ["-"] and not invocation.positionals:
        if context.previous_cwd is None:
            return (Decision.DENY, "`cd -` has no previous directory to go back to: the hook has not tracked any `cd` in this shell yet.", None)
        return (Decision.ALLOW, f"`cd` back to `{context.previous_cwd}` is allowed.", (context.previous_cwd, context.current_cwd))

    if invocation.unknown:
        return (Decision.DENY, f"`cd` option {invocation.unknown[0]} is not supported; only `-P` and `-L` are.", None)

    if command.dynamic:
        return (Decision.DENY, "`cd` target is built from a substitution or an expansion, so the hook cannot tell where the shell would land. Write the path literally.", None)

    operands = [x.value for x in invocation.positionals if x.value is not None]
    if len(operands) > 1:
        return (Decision.DENY, "`cd` takes a single directory.", None)

    # No operand means $HOME, exactly like bash.
    target = standardize(operands[0], context.current_cwd) if operands else Path.home()
    if not isinstance(target, Path) or not target.is_dir():
        return (Decision.DENY, f"`cd` target `{target}` is not an existing directory: the shell would stay where it is while the hook believed it moved.", None)

    return (Decision.ALLOW, f"`cd` to `{target}` is allowed.", (target, context.current_cwd))
