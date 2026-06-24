import json
import re
import sys

from pathlib import Path

from model import Command, Decision, Mode, Reference
from parser import ParseError, Parser
from utils import expand_glob, format_response, has_glob, is_file_access_allowed, is_git_dir, is_secret

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

# A "simple" sed script: one or more `addr[,addr]p` print commands, separated
# by `;`. No `s`, `w`, `e`, `r`, ... commands -- those can write or execute
# arbitrary content, so any script that doesn't fully match this is rejected.
SIMPLE_SED_SCRIPT_RE = re.compile(r"^\s*(?:(?:\d+|\$)(?:,(?:\d+|\$))?\s*p\s*;?\s*)+$")

def describe_refs(refs: list[Reference]) -> str:
    accesses = []
    for file in sorted(r.text for r in refs if r.mode is Mode.READ):
        accesses.append(f"reads {file}")
    for file in sorted(r.text for r in refs if r.mode is Mode.WRITE):
        accesses.append(f"writes {file}")
    return ", ".join(accesses)

def check_access(command: Command, references: list[Reference], project_root: Path) -> tuple[Decision, str]:
    """
    Generic, command-agnostic checks on the files and shape of a command.
    """
    # Expand gloab patterns if any
    expanded = []
    for r in references:
        if not has_glob(r.text):
            expanded.append(r)
            continue
        matches = expand_glob(r.text, project_root)
        if matches is None:
            expanded.append(r)  # can't trust expansion -- keep as unresolved glob
        elif not matches and r.mode is Mode.WRITE:
            expanded.append(r)  # nullglob-off: bash would still write the literal, unverified name
        else:
            expanded.extend(Reference(mode=r.mode, text=str(m)) for m in matches)
    # Then apply ALLOW/ASK/DENY rules
    if secret_files := [r.text for r in expanded if is_secret(r.text, project_root)]:
        return (Decision.DENY, f"Refusing to access {', '.join(secret_files)}: they look like secret files.")
    if gitdir_files := [r.text for r in expanded if r.mode is Mode.WRITE and is_git_dir(r.text, project_root)]:
        return (Decision.DENY, f"Refusing to write {', '.join(gitdir_files)} inside the .git directory.")
    if command.dynamic:
        return (Decision.ASK, f"`{command.base or 'command'}` has a dynamically-computed part - cannot verify it.")
    if glob_files := [r.text for r in expanded if has_glob(r.text)]:
        return (Decision.ASK, f"`{command.base}` uses a glob pattern ({', '.join(glob_files)}); cannot statically verify which files it matches.")
    if external_files := [r.text for r in expanded if not is_file_access_allowed(r.text, project_root, read=r.mode is Mode.READ)]:
        return (Decision.ASK, f"`{command.base}` accesses {', '.join(external_files)} outside the project.")
    return (Decision.ALLOW, "")

def check_command(command: Command, references: list[Reference], project_root: Path) -> tuple[Decision, str]:
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
        for arg in ["-delete", "-exec", "-execdir", "-fls", "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir"]:
            if any(x.low_key == arg for x in command.args):
                return (Decision.ASK, f"`{command.base}` uses the {arg} argument.")
        # The leading positional arguments are the search roots.
        references = []
        for arg in command.args:
            if not arg.positional:
                break
            if arg.value is not None:
                references.append(Reference(mode=Mode.READ, text=arg.value))
        return check_access(command, references, project_root)

    if command.base == "git":
        references = []
        if any(x.key == "-C" for x in command.args):
            return (Decision.DENY, "Do not use `git -C`: you are already at the repository root.")
        if any(x.key == "-c" for x in command.args):
            return (Decision.DENY, "Do not use `git -c` to inject config; it can run arbitrary code. Run the command directly.")
        if command.subcommand == "push":
            return (Decision.DENY, "`git push` is forbidden by the security policy: only the user is allowed to push.")
        for idx, arg in enumerate(command.args):
            if arg.low_key in ["--output", "-o"]:
                if not arg.value and len(command.args) <= idx + 1:
                    raise ParseError("param --output has no value")
                value = arg.value if arg.value else command.args[idx + 1].value
                if value is None:
                    raise ParseError("param --output has no value")
                references.append(Reference(mode=Mode.WRITE, text=value))
        if command.subcommand in ["add", "commit"]:
            references += [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args[1:] if arg.value is not None]
        if any(references):
            decision, reason = check_access(command, references, project_root)
            if decision != Decision.ALLOW: return decision, reason
        if command.subcommand in ["add", "check-ignore", "commit", "diff", "grep", "hash-object", "log", "ls-files", "ls-tree", "merge-base", "rev-parse", "show", "status"]:
            return (Decision.ALLOW, f"The `git {command.subcommand}` command is allowed.")
        return (Decision.ASK, f"The `git {command.subcommand}` command is not allowed by default.")

    if command.base == "node":
        if len(command.args) == 1 and command.args[0].key in ("--version", "-v"):
            return (Decision.ALLOW, "The `node --version` command is allowed.")
        if len(command.args) >= 1 and command.args[0].key == "--check":
            references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args if arg.value is not None]
            return check_access(command, references, project_root)
        if command.subcommand:
            return (Decision.ASK, f"The `node {command.subcommand}` command is not allowed by default.")
        else:
            return (Decision.ASK, f"The `node` command is not allowed by default.")

    if command.base == "npm":
        if len(command.args) == 1 and command.args[0].key in ("--version", "-v"):
            return (Decision.ALLOW, "The `npm --version` command is allowed.")
        if command.subcommand in ["ls", "outdated", "view"]:
            return (Decision.ALLOW, f"The `npm {command.subcommand}` command is allowed.")
        if command.subcommand == "audit":
            if any(a.low_key == "--fix" or a.low_value == "fix" for a in command.args):
                return (Decision.ASK, "The `npm audit fix` command is not allowed by default.")
            return (Decision.ALLOW, "The `npm audit` command is allowed.")
        if command.subcommand:
            return (Decision.ASK, f"The `npm {command.subcommand}` command is not allowed by default.")
        else:
            return (Decision.ASK, f"The `npm` command is not allowed by default.")

    if command.base == "podman":
        if command.subcommand == "compose":
            if len(command.args) >= 2 and command.args[1].value == "logs":
                return (Decision.ALLOW, "The `podman compose logs` command is allowed.")
            if len(command.args) >= 2 and command.args[1].value == "ps":
                return (Decision.ALLOW, "The `podman compose ps` command is allowed.")
        if command.subcommand == "inspect":
            return (Decision.ALLOW, "The `podman inspect` command is allowed.")
        if command.subcommand in ["logs", "ps"]:
            return (Decision.ALLOW, f"The `podman {command.subcommand}` command is allowed.")
        if len(command.args) == 1 and command.args[0].key == "--version":
            return (Decision.ALLOW, "The `podman --version` command is allowed.")
        if command.subcommand:
            return (Decision.ASK, f"The `podman {command.subcommand}` command is not allowed by default.")
        else:
            return (Decision.ASK, f"The `podman` command is not allowed by default.")

    if command.base == "sed":
        if any(x.low_key not in ("-n", "--quiet", "--silent") for x in command.named_args):
            return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")
        if not command.positional_args or not SIMPLE_SED_SCRIPT_RE.match(command.positional_args[0].value or ""):
            return (Decision.ASK, f"`{command.base}` script is too complex; cannot verify it's read-only.")
        references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args[1:] if arg.value is not None]
        return check_access(command, references, project_root)

    if command.base == "uv":
        if command.subcommand == "run" and len(command.positional_args) >= 2 and command.positional_args[1].low_value == "mypy":
            return (Decision.DENY, "Do not use `mypy`. Use ty with `uv run ty` instead.")
        if command.subcommand == "sync":
            return (Decision.ALLOW, "The `uv sync` command is allowed.")
        if command.subcommand == "run" and len(command.args) >= 2:
            if command.positional_args[1].value in ["basedpyright", "pyright", "pytest", "ruff", "ty"]:
                return (Decision.ALLOW, f"The `uv run {command.positional_args[1].value}` command is allowed.")
            if len(command.args) == 3 and command.args[1].value == "python" and command.args[2].key == "--version":
                return (Decision.ALLOW, f"The `uv {command.args[1].key} --version` command is allowed.")
            return (Decision.ASK, f"The `uv run {command.positional_args[1].value}` command is not allowed by default.")
        if len(command.args) == 1 and command.args[0].key == "--version":
            return (Decision.ALLOW, "The `uv --version` command is allowed.")
        if command.subcommand:
            return (Decision.ASK, f"The `uv {command.subcommand}` command is not allowed by default.")
        else:
            return (Decision.ASK, f"The `uv` command is not allowed by default.")

    # Commands that read the files named in their positional arguments: the # paths must be vetted (secret / outside the project) before allowing.
    # No awk/sed: they can execute arbitrary programs.
    if command.base in ["cat", "file", "grep", "head", "tail", "less", "more", "cut", "diff", "jq", "ls", "sort", "test", "uniq", "wc"]:
        references = [Reference(mode=Mode.READ, text=arg.value) for arg in command.positional_args if arg.value is not None]
        return check_access(command, references, project_root)

    # These touch no files: pwd takes none, echo prints its literal args, tr reads stdin only.
    if command.base in ["pwd", "echo", "printf", "sleep", "tr"]:
        return (Decision.ALLOW, f"The `{command.base}` command is allowed.")

    # Unknown command -> consent, surfacing any files involved.
    if accesses := describe_refs(references):
        return (Decision.ASK, f"`{command.base}` is not in the allow-list ({accesses}).")
    return (Decision.ASK, f"`{command.base}` is not in the allow-list.")

def analyze(prompt: str, project_root: Path) -> tuple[Decision, str]:
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
        verdicts = [check_access(command, references, project_root), check_command(command, references, project_root)]
        results.append(max(verdicts, key=lambda verdict: list(Decision).index(verdict[0])))

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

        if tool_name != "Bash":
            return format_response(Decision.DENY.value, f"Tool `{tool_name}` is not allowed. Use the `Bash` tool instead.")
        if not description or not description.strip() or description.strip().lower() == "run shell command":
            return format_response(Decision.DENY.value, "Provide a meaningful, specific `description` for this command, explaining why it is required and what it does.")

        decision, reason = analyze(prompt, project_root)
        return format_response(decision.value, reason)
    except ParseError as err:
        return format_response(Decision.DENY.value, f"Refusing to run an unparseable command: {err}")

if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
