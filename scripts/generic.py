import json
from pathlib import Path

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
)
from utils.format import format_references

# ============================================================================
# Hook I/O
# ============================================================================

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
    decision, reason = check_file_rules(references, context.project_root, context.mode)
    if decision is not Decision.ALLOW:
        return (decision, f"`{command.base}`: {reason}" if command.base else reason)
    if command.dynamic:
        return (Decision.ASK, f"`{command.base or 'command'}` has a dynamically-computed part - cannot verify it.")
    return (Decision.ALLOW, "")

def check_file_rules(references: list[Reference], project_root: Path, mode: Mode) -> tuple[Decision, str]:
    """
    The [File rules](rules.md#1-file-rules), applied to every path a call
    accesses, whatever the tool that accesses them.
    The decision is the worst one across all the references.
    """
    expanded = expand_references(references, project_root)
    if secret_files := [x.text for x in expanded if is_secret(x.text, project_root)]:
        return (Decision.DENY, f"Refusing to access {format_references(secret_files)}: they look like secret files.")
    if gitdir_files := [x.text for x in expanded if x.access is Access.WRITE and is_git_dir(x.text, project_root)]:
        return (Decision.DENY, f"Refusing to write {format_references(gitdir_files)} inside the .git directory.")
    if harness_files := [x.text for x in expanded if x.access is Access.WRITE and is_claude_dir(x.text, project_root) and not in_project(x.text, project_root)]:
        return (Decision.DENY, f"Refusing to write {format_references(harness_files)} inside the harness directory.")
    if glob_files := [x.text for x in expanded if has_glob(x.text)]:
        return (Decision.ASK, f"{format_references(glob_files)} looks like a glob pattern; cannot statically verify which files it matches.")
    if external_files := [x.text for x in expanded if not is_file_access_allowed(x.text, project_root, read=x.access is Access.READ)]:
        return (Decision.ASK, f"Accessing {format_references(external_files)} outside the project requires your validation.")
    if mode is Mode.MANUAL and (written_files := [x.text for x in expanded if x.access is Access.WRITE]):
        return (Decision.ASK, f"Writing {format_references(written_files)} in {mode.value} mode requires your validation.")
    return (Decision.ALLOW, "")

def worst(*verdicts: tuple[Decision, str]) -> tuple[Decision, str]:
    """
    The most severe verdict (DENY > ASK > ALLOW), so that a deny never degrades
    into an ask. A tie keeps the first one: its reason is the more specific.
    """
    return max(verdicts, key=lambda verdict: list(Decision).index(verdict[0]))
