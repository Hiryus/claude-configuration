import json
import re
import sys
from pathlib import Path

from model import Command, Decision, Mode, Reference
from parsers.parse_bash import ParseError, Parser
from parsers.parse_container import check_container
from parsers.parse_find import check_find
from parsers.parse_git import check_git
from parsers.parse_grep import grep_references
from parsers.parse_node import check_node
from parsers.parse_npm import check_npm
from parsers.parse_sed import check_sed
from parsers.parse_uv import check_uv
from utils import check_access, format_references, format_response, worst

# ============================================================================
# Reference extraction  (which paths a command touches)
# ============================================================================

def referenced_paths(command: Command) -> list[Reference]:
    refs = []
    for redirect in command.redirects:
        if not redirect.target:
            continue  # fd-dup such as 2>&1 -- no file involved
        if redirect.target == "/dev/null":
            continue  # ignore /dev/null which is not a real file
        if redirect.type in (">", ">>", ">|", "&>", "&>>"):
            refs.append(Reference(mode=Mode.WRITE, text=redirect.target))
        elif redirect.type in ("<", "<>", "<<<"):
            refs.append(Reference(mode=Mode.READ, text=redirect.target))
    return refs

# ============================================================================
# Security policy  (business logic)
# ============================================================================

def describe_refs(refs: list[Reference]) -> str:
    accesses = []
    for file in sorted(r.text for r in refs if r.mode is Mode.READ):
        accesses.append(f"reads {format_references([file])}")
    for file in sorted(r.text for r in refs if r.mode is Mode.WRITE):
        accesses.append(f"writes {format_references([file])}")
    return ", ".join(accesses)

def check_command(command: Command, references: list[Reference], project_root: Path, mode: str) -> tuple[Decision, str]:
    """
    Command-specific checks: explicit denials and the allow-list classification.
    """
    if command.base in ["cd"]:
        return (Decision.DENY, "Do not change directory as it messes with security path validation.")
    if re.match(r"^pip[\d.]*$", command.base): # PIP
        return (Decision.DENY, "Do not use `pip`. Use `uv add`, `uv sync`, or `uvx` instead.")
    if command.base == "mypy":
        return (Decision.DENY, "Do not use `mypy`. Use ty with `uv run ty` instead.")
    if command.base in ["python", "python3"]:
        if any(x.low_key == "-m" for x in command.args):
            return (Decision.DENY, "Do not use `python -m`. Use `uv run` or `uvx` instead.")
        else:
            return (Decision.DENY, "Do not use python directly. Use `uv run python` instead.")
    if command.base in ["bash", "cmd", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"]:
        return (Decision.DENY, "Do not invoke another shell. Run the command directly via Bash.")
    if re.search(r"(?i)\.venv[\\/].*python", command.program): # .venv
        return (Decision.DENY, "Do not call the venv python directly. Use `uv run` or `uvx` instead.")

    if command.base == "cmp":
        references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args if arg.value is not None]
        return check_access(command, references, project_root)

    if command.base == "find":
        return check_find(command, project_root)

    if command.base == "gh":
        return (Decision.DENY, "The `gh` command is not installed. Use the github MCP instead.")

    if command.base == "git":
        return check_git(command, project_root)

    if command.base == "grep":
        return check_access(command, grep_references(command), project_root)

    if command.base == "node":
        return check_node(command, project_root)

    if command.base == "npm":
        return check_npm(command, mode)

    if command.base in ["docker", "docker-compose", "podman", "podman-compose"]:
        return check_container(command, project_root)

    if command.base == "sed":
        return check_sed(command, project_root)

    if command.base == "uv":
        return check_uv(command)

    # Commands that read the files named in their positional arguments: the # paths must be vetted (secret / outside the project) before allowing.
    # No awk/sed: they can execute arbitrary programs.
    if command.base in ["cat", "file", "head", "tail", "less", "more", "cut", "diff", "jq", "ls", "sort", "test", "uniq", "wc"]:
        references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args if arg.value is not None]
        return check_access(command, references, project_root)

    # These touch no files: pwd takes none, echo prints its literal args, tr reads stdin only.
    if command.base in ["pwd", "echo", "printf", "sleep", "tr"]:
        return (Decision.ALLOW, f"The `{command.base}` command is allowed.")

    # Unknown command -> consent, surfacing any files involved.
    if accesses := describe_refs(references):
        return (Decision.ASK, f"`{command.base}` is not in the allow-list ({accesses}).")
    return (Decision.ASK, f"`{command.base}` is not in the allow-list.")

def analyze(prompt: str, project_root: Path, mode: str) -> tuple[Decision, str]:
    """
    Analyze every command in the prompt, then emit one aggregated decision.
    Each command's verdict is the most severe of its generic (file-access) and
    command-specific checks; the whole prompt is the most severe of those.
    """
    results = []
    for command in Parser.parse(prompt):
        if not command.base: # assignment only, ex: FOO=bar
            results.append((Decision.ALLOW, "Assignment is allowed."))
            continue
        references = referenced_paths(command)
        verdicts = [check_access(command, references, project_root), check_command(command, references, project_root, mode)]
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
        description: str = input_data.get("tool_input", {}).get("description", "")
        project_root = Path(input_data.get("cwd", ""))
        prompt: str = input_data.get("tool_input", {}).get("command")
        tool_name: str = input_data.get("tool_name", "")
        mode: str = input_data.get("permission_mode", "default")

        if tool_name != "Bash":
            return format_response(Decision.DENY.value, f"Tool `{tool_name}` is not allowed. Use the `Bash` tool instead.")
        if not description or not description.strip() or description.strip().lower() == "run shell command":
            return format_response(Decision.DENY.value, "Provide a meaningful, specific `description` for this command, explaining why it is required and what it does.")

        decision, reason = analyze(prompt, project_root, mode)
        return format_response(decision.value, reason)
    except ParseError as err:
        return format_response(Decision.DENY.value, f"Refusing to run an unparseable command: {err}")

if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:  # noqa: BLE001
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
