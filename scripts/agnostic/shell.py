"""
Analysis of a shell command line against the security rules.
"""

from agnostic.analyzers import docker, find, git, grep, readonly, sed
from agnostic.generic import check_access, check_mode_rules, worst
from agnostic.models.context import Context
from agnostic.models.decision import Decision, Verdict
from agnostic.models.parsing import Access, CommandLine, Reference
from agnostic.parsers import bash
from agnostic.parsers.docker import LEGACY_COMPOSE_BASES
from agnostic.utils.format import describe_refs

# ============================================================================
# Redirect references
# ============================================================================

def referenced_paths(command: CommandLine) -> list[Reference]:
    """
    Return the list of paths a command accesses as a list of `Reference`.
    """
    refs = []
    for redirect in command.redirects:
        if not redirect.target.text:
            continue  # fd-dup such as 2>&1 -- no file involved
        if redirect.target.text == "/dev/null":
            continue  # ignore /dev/null which is not a real file
        if redirect.type in (">", ">>", ">|", "&>", "&>>"):
            refs.append(Reference(access=Access.WRITE, text=redirect.target.text, expansions=redirect.target.expansions))
        elif redirect.type in ("<", "<>", "<<<"):
            refs.append(Reference(access=Access.READ, text=redirect.target.text, expansions=redirect.target.expansions))
    return refs

# ============================================================================
# Security policy  (business logic)
# ============================================================================

def check_command(command: CommandLine, references: list[Reference], context: Context) -> Decision:
    """
    Command-specific checks: explicit denials and the allow-list classification.
    """
    if command.base in ["bash", "cmd", "dash", "exec", "eval", "ksh", "powershell", "pwsh", "sh", "zsh"]:
        return Decision.deny("Do not invoke another shell or eval a command. Run the command directly.")

    if readonly.handles(command.base):
        return readonly.validate(command, context)

    if command.base in ["cd", "popd", "pushd"]:
        return Decision.allow(f"The `{command.base}` command is allowed.")

    if command.base in ["echo", "printf", "pwd", "sleep", "tr", "which"]:
        return Decision.allow(f"The `{command.base}` command is allowed.")

    if command.base in ("docker", "podman", *LEGACY_COMPOSE_BASES):
        return docker.validate(command, context)

    if command.base == "find":
        return find.validate(command, context)

    if command.base == "gh":
        return Decision.deny("The `gh` command is not installed. Use the github MCP instead.")

    if command.base == "git":
        return git.validate(command, context)

    if command.base == "grep":
        return grep.validate(command, context)

    if command.base in ["source", "."]:
        return Decision.deny(f"Do not use `{command.base}`: sourcing a file is not authorized on the host.")

    if command.base == "sed":
        return sed.validate(command, context)

    # Unknown command -> consent, surfacing any files involved.
    if accesses := describe_refs(references):
        return Decision.ask(f"`{command.base}` is not in the allow-list ({accesses}).")
    return Decision.ask(f"`{command.base}` is not in the allow-list.")

def analyze(prompt: str, context: Context) -> Decision:
    """
    Analyze every command in the prompt, then emit one aggregated decision.
    Each command verdict is the most severe of its generic (file-access) and
    command-specific checks; the whole prompt is the most severe of those.

    The current directory is fixed for the whole call: it comes from the payload and
    the hook never simulates a move. That is what rule 2.3 buys by allowing a `cd`
    only when it is alone -- the harness reports where the shell landed on the next call.
    """
    if not context.intent.strip() or context.intent.strip().lower() == "run shell command":
        return Decision.deny("Provide a meaningful, specific `description` for this command, explaining why it is required and what it does.")

    results = []
    commands = bash.parse(prompt)
    for command in commands:
        if not command.base:
            # Assignment only, ex: FOO=bar. Harmless in itself, but it can still carry a redirect (`FOO=bar > .env`).
            results.append(check_access(command, referenced_paths(command), context))
        elif command.base in ["cd", "popd", "pushd"] and len(commands) > 1:
            # A command that moves the shell is allowed only when it is the whole command line.
            results.append(Decision.deny(f"Avoid changing directory. If you really need to, run the `{command.base}` alone, then make another tool call."))
        else:
            references = referenced_paths(command)
            results.append(worst(
                check_access(command, references, context),
                check_command(command, references, context),
            ))

    if denies := [decision.reason for decision in results if decision.verdict is Verdict.DENY]:
        return Decision.deny("\n".join(dict.fromkeys(denies)))
    if asks := [decision.reason for decision in results if decision.verdict is Verdict.ASK]:
        return check_mode_rules(Decision.ask("\n".join(f" - {reason}" for reason in dict.fromkeys(asks))), context)
    return Decision.allow("All commands validated automatically.")
