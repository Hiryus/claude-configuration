import json

from models.analyzer import Context, Decision, Mode
from models.parsing import Access, CommandLine, Reference
from utils.filesystem import (
    expand_references,
    has_glob,
    in_project,
    is_claude_dir,
    is_file_access_allowed,
    is_git_dir,
    is_secret,
    standardize,
)
from utils.format import format_references

# ============================================================================
# Hook I/O
# ============================================================================

AUTO_MODE_DENIAL = """
**Your tool call was denied because it requires the user validation.**
{reason}

You are in auto mode. In this mode, the user will not validate tool calls.
Any tool call that is not explictely authorized, is denied.

To complete your objective, you need to only request allowed calls.
- The allowed list is described in ~/.claude/scripts/rules.md.
- If you need to run forbidden bash commands, instead run them inside a docker container with "docker run ...".
  You are allowed to mount the project directory inside the container - nothing else.
- Do not try to bypass restrictions.
  If you can't fulfil your objective, just report back to the user.
"""

def format_response(decision: str, reason: str) -> str:
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })

# ============================================================================
# Access policy
# ============================================================================

def check_access(command: CommandLine, references: list[Reference], context: Context) -> tuple[Decision, str]:
    """
    Generic, command-agnostic checks on the files and shape of a command.
    """
    decision, reason = check_file_rules(references, context)
    if decision is Decision.ALLOW:
        return (Decision.ALLOW, f"`{command.base}` is allowed" if command.base else "allowed")
    return (decision, f"`{command.base}`: {reason}" if command.base else reason)

def check_file_rules(references: list[Reference], context: Context) -> tuple[Decision, str]:
    """
    The [File rules](rules.md#1-file-rules), applied to every path a call
    accesses, whatever the tool that accesses them.
    The decision is the worst one across all the references.
    """
    expanded = expand_references(references, context.current_cwd)
    resolved = [(ref, standardize(ref.text, context.current_cwd)) for ref in expanded]
    if secret_files := [ref.text for ref, path in resolved if is_secret(path)]:
        return (Decision.DENY, f"Refusing to access {format_references(secret_files)}: they look like secret files.")
    if gitdir_files := [ref.text for ref, path in resolved if ref.access is Access.WRITE and is_git_dir(path)]:
        return (Decision.DENY, f"Refusing to write {format_references(gitdir_files)} inside the .git directory.")
    if harness_files := [ref.text for ref, path in resolved if ref.access is Access.WRITE and is_claude_dir(path) and not in_project(path, context.project_root)]:
        return (Decision.DENY, f"Refusing to write {format_references(harness_files)} inside the harness directory.")
    if glob_files := [ref.text for ref, _ in resolved if has_glob(ref.text)]:
        return (Decision.ASK, f"{format_references(glob_files)} looks like a glob pattern; cannot statically verify which files it matches.")
    if external_files := [ref.text for ref, path in resolved if not is_file_access_allowed(path, context.project_root, read=ref.access is Access.READ)]:
        return (Decision.ASK, f"Accessing {format_references(external_files)} outside the project requires your validation.")
    if context.mode is Mode.MANUAL and (written_files := [ref.text for ref, _ in resolved if ref.access is Access.WRITE]):
        return (Decision.ASK, f"Writing {format_references(written_files)} in {context.mode.value} mode requires your validation.")
    return (Decision.ALLOW, "")

def check_mode_rules(decision: Decision, reason: str, mode: Mode) -> tuple[Decision, str]:
    """
    The [Modes rules](rules.md#modes): in auto mode an `ask` becomes a `deny`,
    since nobody is there to validate it. The `ask` reason is kept as context.
    """
    if decision is Decision.ASK and mode is Mode.AUTO:
        return (Decision.DENY, AUTO_MODE_DENIAL.strip().format(reason=reason))
    return (decision, reason)

def worst(*verdicts: tuple[Decision, str]) -> tuple[Decision, str]:
    """
    The most severe verdict (DENY > ASK > ALLOW), so that a deny never degrades
    into an ask. A tie keeps the first one: its reason is the more specific.
    """
    return max(verdicts, key=lambda verdict: list(Decision).index(verdict[0]))
