import os
from pathlib import Path

from agnostic.models.context import Context
from agnostic.models.decision import Decision, Verdict
from agnostic.models.mode import Mode
from agnostic.models.parsing import Access, CommandLine, Reference
from agnostic.utils.filesystem import (
    expand_references,
    has_glob,
    in_harness,
    in_project,
    is_git_dir,
    is_secret,
    is_tmp_file,
    standardize,
)
from agnostic.utils.format import format_references

DIRECTORY = os.path.dirname(__file__)
TPL_DIR = os.path.join(DIRECTORY, "templates")

def check_access(command: CommandLine, references: list[Reference], context: Context) -> Decision:
    """
    Generic, command-agnostic checks on the files and shape of a command.
    """
    decision = check_file_rules(references, context)
    if decision.verdict is Verdict.ALLOW:
        return Decision.allow(f"`{command.base}` is allowed" if command.base else "allowed")
    return Decision(decision.verdict, f"`{command.base}`: {decision.reason}" if command.base else decision.reason)

def check_file_rules(references: list[Reference], context: Context) -> Decision:
    """
    The [file rules](SECURITY.md#1-file-rules), applied to every path a call accesses, whatever the tool that accesses them.
    The decision is the worst one across all the references.

    A path built from an expansion is an ASK, but only after the DENY checks:
    those read  the literal text, so `cat $HOME/.ssh/id_rsa` is still refused on its visible `.ssh` segment.
    """
    expanded = expand_references(references, context.current_cwd)
    resolved = [(ref, standardize(ref.text, context.current_cwd)) for ref in expanded]
    if secret_files := [ref.text for ref, path in resolved if is_secret(path)]:
        return Decision.deny(f"Refusing to access {format_references(secret_files)}: they look like secret files.")
    if gitdir_files := [ref.text for ref, path in resolved if ref.access is Access.WRITE and is_git_dir(path)]:
        return Decision.deny(f"Refusing to write {format_references(gitdir_files)} inside the .git directory.")
    if harness_files := [ref.text for ref, path in resolved if ref.access is Access.WRITE and in_harness(path, context.harness_root) and not in_project(path, context.project_root)]:
        return Decision.deny(f"Refusing to write {format_references(harness_files)} inside the harness directory.")
    if dynamic_files := [ref.text for ref, _ in resolved if ref.dynamic]:
        return Decision.ask(f"{format_references(dynamic_files)} is built from a shell expansion; cannot statically verify which file it targets.")
    if glob_files := [ref.text for ref, _ in resolved if has_glob(ref.text)]:
        return Decision.ask(f"{format_references(glob_files)} looks like a glob pattern; cannot statically verify which files it matches.")
    if external_files := [ref.text for ref, path in resolved if not is_file_access_allowed(path, context, read=ref.access is Access.READ)]:
        return Decision.ask(f"Accessing {format_references(external_files)} outside the project requires your validation.")
    if context.mode is Mode.MANUAL and (written_files := [ref.text for ref, _ in resolved if ref.access is Access.WRITE]):
        return Decision.ask(f"Writing {format_references(written_files)} in {context.mode.value} mode requires your validation.")
    return Decision.allow("")

def check_mode_rules(decision: Decision, context: Context) -> Decision:
    """
    The [modes rules](SECURITY.md#modes): in auto mode an `ask` becomes a `deny`, since nobody is there to validate it.
    The `ask` reason is kept as context.
    """
    if decision.verdict is Verdict.ASK and context.mode is Mode.AUTO:
        with open(os.path.join(TPL_DIR, "auto_mode_denial.md")) as file:
            return Decision.deny(file.read().strip().format(reason=decision.reason, security_file=context.harness_root / "SECURITY.md"))
    return decision

def is_file_access_allowed(path: Path, context: Context, read: bool) -> bool:
    """
    True for locations that don't need to prompt the user for an out-of-project access:
    - A tmp file,
    - Inside the project,
    - The agent harness only in read mode.
    """
    if in_project(path, context.project_root):
        return True
    if is_tmp_file(path):
        return True
    return read and in_harness(path, context.harness_root)

def worst(*decisions: Decision) -> Decision:
    """
    The most severe verdict (DENY > ASK > ALLOW), so that a deny never degrades
    into an ask. A tie keeps the first one: its reason is the more specific.
    """
    return max(decisions, key=lambda decision: list(Verdict).index(decision.verdict))
