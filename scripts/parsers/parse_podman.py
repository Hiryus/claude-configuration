from model import Command, Decision

# Subcommands that only inspect containers, never start/stop/remove them.
READONLY_SUBCOMMANDS = ["logs", "port", "ps"]

# Same, for `podman compose <x>`.
COMPOSE_READONLY_SUBCOMMANDS = ["logs", "ps"]

def check_podman(command: Command) -> tuple[Decision, str]:
    """
    `podman` is allow-listed per subcommand: only the ones that report on
    existing containers are free; anything that creates, mutates or removes
    one needs the user validation.
    """
    if command.subcommand == "compose" and len(command.args) >= 2 and command.args[1].value in COMPOSE_READONLY_SUBCOMMANDS:
        return (Decision.ALLOW, f"The `podman compose {command.args[1].value}` command is allowed.")
    if command.subcommand == "inspect":
        return (Decision.ALLOW, "The `podman inspect` command is allowed.")
    if command.subcommand in READONLY_SUBCOMMANDS:
        return (Decision.ALLOW, f"The `podman {command.subcommand}` command is allowed.")
    if len(command.args) == 1 and command.args[0].key == "--version":
        return (Decision.ALLOW, "The `podman --version` command is allowed.")
    if command.subcommand:
        return (Decision.ASK, f"The `podman {command.subcommand}` command is not allowed by default.")
    else:
        return (Decision.ASK, "The `podman` command is not allowed by default.")
