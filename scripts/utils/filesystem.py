import glob
import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

from models.parsing import Access, Reference

# Three groups live here, and the parameter says which one a helper belongs to:
#   - the anchoring helpers take `cwd`         -- they turn a written path into a real one,
#   - the boundary helpers take `project_root` -- they answer "is this ours?",
#   - the classifiers take a standardized path -- they answer "what kind of file is this?".
# A classifier must never see raw text: `cd .git && echo x > config` would defeat rule 1.2.

StandardPath = Path | PurePosixPath


def expand_glob(path_text: str, cwd: Path) -> list[Path] | None:
    """
    Expand a glob to the concrete paths it currently matches, using bash's default semantics (no globstar, no dotglob): `*` and `**` don't cross a `/` on their own, and a leading `*` skips dotfiles unless the pattern segment itself starts with `.`.

    Returns None -- "don't trust this as positive evidence" -- when:
      - the pattern uses syntax Python's glob doesn't understand (braces, extglob), since it would silently treat it as literal characters and could under-report matches that bash would actually expand to.
      - the anchored pattern isn't a real filesystem path on this OS (e.g. a POSIX-style absolute path while running on Windows).

    An empty list is a real (if negative) result, whether the pattern matches nothing in a real directory or the directory itself doesn't exist: glob.glob() returns [] either way without erroring, and in both cases there's nothing real for the pattern to disclose right now.
    """
    if any(ch in path_text for ch in "{}()"):
        return None
    anchored = standardize(path_text, cwd)
    if not isinstance(anchored, Path):
        return None
    return [Path(match) for match in glob.glob(str(anchored), recursive=False)]

def expand_references(references: list[Reference], cwd: Path) -> list[Reference]:
    """
    Replace every glob reference with the concrete paths it matches.
    A pattern that cannot be trusted is kept as-is, so it is later reported as an unresolved glob rather than silently vetted as a literal name.
    """
    expanded = []
    for ref in references:
        if not has_glob(ref.text):
            expanded.append(ref)
            continue
        matches = expand_glob(ref.text, cwd)
        if matches is None:
            expanded.append(ref)  # can't trust expansion -- keep as unresolved glob
        elif not matches and ref.access is Access.WRITE:
            expanded.append(ref)  # nullglob-off: bash would still write the literal, unverified name
        else:
            expanded.extend(Reference(access=ref.access, text=str(m)) for m in matches)
    return expanded

def has_glob(path_text: str) -> bool:
    """
    A path with shell glob metacharacters expands at runtime, so the hook only sees the literal pattern (e.g. `*` never matches is_secret).
    Such patterns cannot be verified statically.
    Includes brace expansion (`{a,b}`) and extglob (`!(a)`, `@(a|b)`, ...): bash expands both, but expand_glob can't, so they must still be routed there to fall back to "can't verify".
    """
    return any(ch in path_text for ch in "*?[{}()")

def in_project(path: StandardPath, project_root: Path) -> bool:
    return path.is_relative_to(project_root)

def is_claude_dir(path: StandardPath) -> bool:
    if not isinstance(path, Path):
        return False
    return path.is_relative_to(Path.home() / ".claude")

def is_git_dir(path: StandardPath) -> bool:
    """
    True for the `.git` directory itself and anything under it, at any depth.
    Matched on the standardized parts rather than the written text: `cd .git; echo x > config` writes a git file too.
    """
    return any(part.lower() == ".git" for part in path.parts)

def is_secret(path: StandardPath) -> bool:
    name = path.name.lower()
    if sys.platform == "win32":
        name = name.rstrip(".")  # Windows ignores a trailing dot, so ".env." opens ".env"
    if name.endswith((".example", ".sample", ".template")):
        return False
    if os.path.splitext(name)[1] in [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"]:
        return True
    if name in [".env", ".env.local", ".env.prod", ".env.production"]:
        return True
    if name in [".htpasswd", ".netrc", ".npmrc", ".pgpass"]:
        return True
    if any(part.lower() == ".ssh" for part in path.parts):
        return True
    return name in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]

def is_tmp_file(path: StandardPath) -> bool:
    if sys.platform == "win32" and path.is_relative_to(Path(os.path.expandvars("%LOCALAPPDATA%\\Temp"))):
        return True
    if sys.platform == "win32" and path.is_relative_to(Path("C:\\Windows\\Temp")):
        return True
    return path.is_relative_to(PurePosixPath("/tmp")) or path.is_relative_to(PurePosixPath("/var/tmp")) or path.is_relative_to(PurePosixPath("/dev/null"))

def is_file_access_allowed(path: StandardPath, project_root: Path, read: bool) -> bool:
    """
    True for locations that don't need to prompt the user for an
    out-of-project access: inside the project, a tmp file, or (read-only)
    inside ~/.claude.
    """
    if in_project(path, project_root):
        return True
    if is_tmp_file(path):
        return True
    return read and is_claude_dir(path)

def standardize(path_text: str, cwd: Path) -> StandardPath:
    """
    Turn a written path into the real one it designates, anchoring a relative path on the current directory (which moves with `cd`, cf. rule 2.3) -- not on the project root.
    """
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
        return (cwd / path_text).resolve()
    else:
        return Path(path_text).resolve()
