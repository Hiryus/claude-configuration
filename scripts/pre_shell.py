import json
import re
import sys

from analyzers import docker, find, git, grep, sed
from generic import check_access, format_response, worst
from models.analyzer import Context, Decision
from models.grammar import CommandSyntax
from models.parsing import Access, CommandLine, ParseError, Reference
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
    if command.base in ["bash", "cmd", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"]:
        return (Decision.DENY, "Do not invoke another shell. Run the command directly via Bash.")

    # No awk/sed: they can execute arbitrary programs.
    if command.base in ["cat", "cmp", "cut", "diff", "file", "head", "jq", "less",  "ls", "more", "sort", "tail", "test", "uniq", "wc"]:
        invocation = arguments.parse(command_line=command, syntax=CommandSyntax(aliases=[command.base]))
        references = [Reference(access=Access.READ, text=x.value) for x in invocation.positionals if x.value is not None]
        return check_access(command, references, context)

    if command.base in ["echo", "printf", "pwd", "sleep", "tr"]:
        return (Decision.ALLOW, f"The `{command.base}` command is allowed.")

    if command.base == "cd":
        return (Decision.DENY, "Do not change directory as it messes with security path validation.")

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

    if command.base == "sed":
        return sed.validate(command, context)

    # TODO: allow the use of ty and ruff
    # if command.base == "uv":
    #     return uv.validate(command, context)

    # Unknown command -> consent, surfacing any files involved.
    if accesses := describe_refs(references):
        return (Decision.ASK, f"`{command.base}` is not in the allow-list ({accesses}).")
    return (Decision.ASK, f"`{command.base}` is not in the allow-list.")

def analyze(prompt: str, context: Context) -> tuple[Decision, str]:
    """
    Analyze every command in the prompt, then emit one aggregated decision.
    Each command's verdict is the most severe of its generic (file-access) and
    command-specific checks; the whole prompt is the most severe of those.
    """
    results = []
    commands = bash.parse(prompt)
    for command in commands:
        if not command.base: # assignment only, ex: FOO=bar
            results.append((Decision.ALLOW, "Assignment is allowed."))
        else:
            references = referenced_paths(command)
            verdicts = [check_access(command, references, context), check_command(command, references, context)]
            results.append(worst(*verdicts))

    if denies := [reason for (decision, reason) in results if decision is Decision.DENY]:
        return (Decision.DENY, "\n".join(dict.fromkeys(denies)))
    if asks := [reason for (decision, reason) in results if decision is Decision.ASK]:
        return (Decision.ASK, "\n".join(f" - {reason}" for reason in dict.fromkeys(asks)))
    return (Decision.ALLOW, "All commands validated automatically.")

# ============================================================================
# Entry point
# ============================================================================

def main(input_data:dict) -> str:
    try:
        context = Context.of(input_data)
        prompt:str = input_data.get("tool_input", {}).get("command")
        if context.tool_name != "Bash":
            return format_response(Decision.DENY.value, f"Tool `{context.tool_name}` is not allowed. Use the `Bash` tool instead.")
        elif not context.intent.strip() or context.intent.strip().lower() == "run shell command":
            return format_response(Decision.DENY.value, "Provide a meaningful, specific `description` for this command, explaining why it is required and what it does.")
        else:
            decision, reason = analyze(prompt, context)
            return format_response(decision.value, reason)
    except ParseError as err:
        return format_response(Decision.DENY.value, f"Refusing to run an unparseable command: {err}")

if __name__ == "__main__":
    try:
        input_data:dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err: # noqa: BLE001
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
