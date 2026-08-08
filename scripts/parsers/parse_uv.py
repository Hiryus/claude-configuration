from model import Command, Decision

# Tools that are safe to launch through `uv run`: type-checkers, the test
# runner and the linter. Anything else runs arbitrary code.
RUNNABLE_TOOLS = ["basedpyright", "pyright", "pytest", "ruff", "ty"]

def check_uv(command: Command) -> tuple[Decision, str]:
    """
    `uv` is the sanctioned entry point for every Python tool, so `uv run` is
    allow-listed per tool rather than wholesale. `mypy` is refused here too:
    otherwise `uv run mypy` would be a trivial way around the top-level ban.
    """
    if command.subcommand == "run" and len(command.positional_args) >= 2 and command.positional_args[1].low_value == "mypy":
        return (Decision.DENY, "Do not use `mypy`. Use ty with `uv run ty` instead.")
    if command.subcommand == "sync":
        return (Decision.ALLOW, "The `uv sync` command is allowed.")
    if command.subcommand == "run" and len(command.args) >= 2:
        if command.positional_args[1].value in RUNNABLE_TOOLS:
            return (Decision.ALLOW, f"The `uv run {command.positional_args[1].value}` command is allowed.")
        if len(command.args) == 3 and command.args[1].value == "python" and command.args[2].key == "--version":
            return (Decision.ALLOW, f"The `uv {command.args[1].key} --version` command is allowed.")
        return (Decision.ASK, f"The `uv run {command.positional_args[1].value}` command is not allowed by default.")
    if len(command.args) == 1 and command.args[0].key == "--version":
        return (Decision.ALLOW, "The `uv --version` command is allowed.")
    if command.subcommand:
        return (Decision.ASK, f"The `uv {command.subcommand}` command is not allowed by default.")
    else:
        return (Decision.ASK, "The `uv` command is not allowed by default.")
