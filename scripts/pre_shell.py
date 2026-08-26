import json
import os
import re
import sys
from collections.abc import Mapping

from analyzers import docker, find, git, grep, sed
from generic import check_access, check_mode_rules, format_response, worst
from models.analyzer import Context, Decision
from models.grammar import CommandSyntax
from models.parsing import Access, CommandLine, ContextError, ParseError, Reference
from parsers import arguments, bash
from utils.format import describe_refs

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
            refs.append(Reference(access=Access.WRITE, text=redirect.target.text))
        elif redirect.type in ("<", "<>", "<<<"):
            refs.append(Reference(access=Access.READ, text=redirect.target.text))
    return refs

# ============================================================================
# Security policy  (business logic)
# ============================================================================

def check_command(command: CommandLine, references: list[Reference], context: Context) -> tuple[Decision, str]:
    """
    Command-specific checks: explicit denials and the allow-list classification.
    """
    if command.base in ["bash", "cmd", "dash", "exec", "eval", "ksh", "powershell", "pwsh", "sh", "zsh"]:
        return (Decision.DENY, "Do not invoke another shell or eval a command. Run the command directly via Bash.")

    # No awk/sed: they can execute arbitrary programs.
    if command.base in ["cat", "cmp", "cut", "diff", "file", "head", "jq", "less",  "ls", "more", "sort", "tail", "test", "uniq", "wc"]:
        invocation = arguments.parse(command_line=command, syntax=CommandSyntax(aliases=[command.base]))
        references = [Reference(access=Access.READ, text=x.value) for x in invocation.positionals if x.value is not None]
        return check_access(command, references, context)

    if command.base in ["cd", "popd", "pushd"]:
        return (Decision.ALLOW, f"The `{command.base}` command is allowed.")

    if command.base in ["echo", "printf", "pwd", "sleep", "tr"]:
        return (Decision.ALLOW, f"The `{command.base}` command is allowed.")

    if command.base == "docker":
        return docker.validate(command, context)

    if command.base == "find":
        return find.validate(command, context)

    if command.base == "gh":
        return (Decision.DENY, "The `gh` command is not installed. Use the github MCP instead.")

    if command.base == "git":
        return git.validate(command, context)

    if command.base == "grep":
        return grep.validate(command, context)

    if command.base == "mypy":
        return (Decision.DENY, "Do not use `mypy`. Use ty with `uv run ty` instead.")
        
    if re.match(r"^pip[\d.]*$", command.base): # PIP
        return (Decision.DENY, "Do not use `pip`. Use `uv add`, `uv sync`, or `uvx` instead.")

    if command.base in ["source", "."]:
        return (Decision.DENY, f"Do not use `{command.base}`: sourcing a file is not authorized on the host.")

    if command.base == "sed":
        return sed.validate(command, context)

    # Unknown command -> consent, surfacing any files involved.
    if accesses := describe_refs(references):
        return (Decision.ASK, f"`{command.base}` is not in the allow-list ({accesses}).")
    return (Decision.ASK, f"`{command.base}` is not in the allow-list.")

def analyze(prompt: str, context: Context) -> tuple[Decision, str]:
    """
    Analyze every command in the prompt, then emit one aggregated decision.
    Each command verdict is the most severe of its generic (file-access) and
    command-specific checks; the whole prompt is the most severe of those.

    The current directory is fixed for the whole call: it comes from the payload and
    the hook never simulates a move. That is what rule 2.3 buys by allowing a `cd`
    only when it is alone -- the harness reports where the shell landed on the next call.
    """
    if not context.intent.strip() or context.intent.strip().lower() == "run shell command":
        return (Decision.DENY, "Provide a meaningful, specific `description` for this command, explaining why it is required and what it does.")

    results = []
    commands = bash.parse(prompt)
    for command in commands:
        if not command.base:
            # Assignment only, ex: FOO=bar. Harmless in itself, but it can still carry a redirect (`FOO=bar > .env`).
            results.append(check_access(command, referenced_paths(command), context))
        elif command.base in ["cd", "popd", "pushd"] and len(commands) > 1:
            # A command that moves the shell is allowed only when it is the whole command line.
            results.append((Decision.DENY, f"Avoid changing directory. If you really need to, run the `{command.base}` alone, then make another tool call."))
        else:
            references = referenced_paths(command)
            results.append(worst(
                check_access(command, references, context),
                check_command(command, references, context),
            ))

    if denies := [reason for (decision, reason) in results if decision is Decision.DENY]:
        return (Decision.DENY, "\n".join(dict.fromkeys(denies)))
    if asks := [reason for (decision, reason) in results if decision is Decision.ASK]:
        return (Decision.ASK, "\n".join(f" - {reason}" for reason in dict.fromkeys(asks)))
    return (Decision.ALLOW, "All commands validated automatically.")

# ============================================================================
# Entry point
# ============================================================================

def main(input_data:dict, environ:Mapping[str, str] = os.environ) -> str:
    try:
        context = Context.of(input_data, environ)
        prompt:str = input_data.get("tool_input", {}).get("command")
        if context.tool_name != "Bash":
            return format_response(Decision.DENY.value, f"Tool `{context.tool_name}` is not allowed. Use the `Bash` tool instead.")
        else:
            decision, reason = analyze(prompt, context)
            decision, reason = check_mode_rules(decision, reason, context.mode)
            return format_response(decision=decision.value, reason=reason)
    except ContextError as err:
        return format_response(Decision.DENY.value, f"invalid tool context: {err}")
    except ParseError as err:
        return format_response(Decision.DENY.value, f"Refusing to run an unparseable command: {err}")

if __name__ == "__main__":
    try:
        input_data:dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err: # noqa: BLE001
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
