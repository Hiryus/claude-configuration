import glob
import json
import os
import re
import sys

from pathlib import Path, PurePosixPath, PureWindowsPath

from model import Command, Decision, Mode, Reference

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
# Formatting
# ============================================================================

def format_references(paths: list[str]) -> str:
    # Wrap each path in backticks: a bare path is parsed as markdown when shown
    # to the user, which strips backslashes as escape characters.
    return ", ".join(f"`{path}`" for path in paths)

# ============================================================================
# Filesystem
# ============================================================================

def standardize(path_text: str, project_root: Path) -> Path|PurePosixPath:
    # Resolve variables (order matters)
    path_text = os.path.expandvars(path_text)
    path_text = os.path.expanduser(path_text)
    # Handle POSIX paths on Windows
    if sys.platform == "win32" and path_text.startswith("/"):
        path_text = os.path.normpath(path_text)
        path = PurePosixPath(PureWindowsPath(path_text).as_posix())
        # Special case to convert CYGWIN paths like "/c/..." to Windows paths "C:\..."
        if len(path.parts) >= 2 and path.parts[0] == "/" and len(path.parts[1]) == 1 and path.parts[1].isalpha():
            return Path(f"{path.parts[1].upper()}:\\", *path.parts[2:])
        return path
    # Handle normal paths
    if not os.path.isabs(path_text):
        return (project_root / path_text).resolve()
    else:
        return Path(path_text).resolve()

def has_glob(path_text: str) -> bool:
    """
    A path with shell glob metacharacters expands at runtime, so the hook only
    sees the literal pattern (e.g. `*` never matches is_secret). Such patterns
    cannot be verified statically. Includes brace expansion (`{a,b}`) and
    extglob (`!(a)`, `@(a|b)`, ...): bash expands both, but expand_glob can't,
    so they must still be routed there to fall back to "can't verify".
    """
    return any(ch in path_text for ch in "*?[{}()")

def expand_glob(path_text: str, project_root: Path) -> list[Path] | None:
    """
    Expand a glob to the concrete paths it currently matches, using bash's
    default semantics (no globstar, no dotglob): `*` and `**` don't cross a
    `/` on their own, and a leading `*` skips dotfiles unless the pattern
    segment itself starts with `.`.

    Returns None -- "don't trust this as positive evidence" -- when:
      - the pattern uses syntax Python's glob doesn't understand (braces,
        extglob), since it would silently treat it as literal characters
        and could under-report matches that bash would actually expand to.
      - the anchored pattern isn't a real filesystem path on this OS (e.g.
        a POSIX-style absolute path while running on Windows).

    An empty list is a real (if negative) result, whether the pattern
    matches nothing in a real directory or the directory itself doesn't
    exist: glob.glob() returns [] either way without erroring, and in both
    cases there's nothing real for the pattern to disclose right now.
    """
    if any(ch in path_text for ch in "{}()"):
        return None
    anchored = standardize(path_text, project_root)
    if not isinstance(anchored, Path):
        return None
    return [Path(match) for match in glob.glob(str(anchored), recursive=False)]

def in_project(path_text: str, project_root: Path) -> bool:
    return standardize(path_text, project_root).is_relative_to(project_root)

def is_git_dir(path_text: str, project_root: Path) -> bool:
    return bool(re.search(r"(?i)(?:^|[\\/])\.git(?:[\\/]|$)", path_text))

def is_secret(path_text: str, project_root: Path) -> bool:
    # Windows ignores ending dot
    path = Path(path_text.rstrip(".") ) if sys.platform == "win32" else Path(path_text)
    if path.name.lower().endswith((".example", ".sample", ".template", ".dist")):
        return False
    if path.suffix in [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"]:
        return True
    if path.name in [".env", ".env.local"]:
        return True
    if path.name in [".htpasswd", ".netrc", ".npmrc", ".pgpass"]:
        return True
    if ".ssh" in path.parts or path.name in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]:
        return True
    return False

def is_claude_dir(path_text: str, project_root: Path) -> bool:
    path = standardize(path_text, project_root)
    if not isinstance(path, Path):
        return False
    return path.is_relative_to(Path.home() / ".claude")

def is_tmp_file(path_text: str, project_root: Path) -> bool:
    path = standardize(path_text, project_root)
    if sys.platform == "win32" and path.is_relative_to(Path(os.path.expandvars("%LOCALAPPDATA%\\Temp"))):
        return True
    if sys.platform == "win32" and path.is_relative_to(Path("C:\\Windows\\Temp")):
        return True
    if path.is_relative_to(PurePosixPath("/tmp")) or path.is_relative_to(PurePosixPath("/var/tmp")) or path.is_relative_to(PurePosixPath("/dev/null")):
        return True
    return False

def is_file_access_allowed(path_text: str, project_root: Path, read: bool) -> bool:
    """
    True for locations that don't need to prompt the user for an
    out-of-project access: inside the project, a tmp file, or (read-only)
    inside ~/.claude.
    """
    if in_project(path_text, project_root):
        return True
    if is_tmp_file(path_text, project_root):
        return True
    if read and is_claude_dir(path_text, project_root):
        return True
    return False

# ============================================================================
# Access policy
# ============================================================================

def worst(*verdicts: tuple[Decision, str]) -> tuple[Decision, str]:
    """
    The most severe verdict (DENY > ASK > ALLOW), so that a deny never degrades
    into an ask. A tie keeps the first one: its reason is the more specific.
    """
    return max(verdicts, key=lambda verdict: list(Decision).index(verdict[0]))

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
        return (Decision.DENY, f"Refusing to access {format_references(secret_files)}: they look like secret files.")
    if gitdir_files := [r.text for r in expanded if r.mode is Mode.WRITE and is_git_dir(r.text, project_root)]:
        return (Decision.DENY, f"Refusing to write {format_references(gitdir_files)} inside the .git directory.")
    if command.dynamic:
        return (Decision.ASK, f"`{command.base or 'command'}` has a dynamically-computed part - cannot verify it.")
    if glob_files := [r.text for r in expanded if has_glob(r.text)]:
        return (Decision.ASK, f"`{command.base}` uses a glob pattern ({format_references(glob_files)}); cannot statically verify which files it matches.")
    if external_files := [r.text for r in expanded if not is_file_access_allowed(r.text, project_root, read=r.mode is Mode.READ)]:
        return (Decision.ASK, f"`{command.base}` accesses {format_references(external_files)} outside the project.")
    return (Decision.ALLOW, "")
