import glob
import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

from models.parsing import Access, Reference


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

def in_project(path: Path, project_root: Path) -> bool:
    return path.is_relative_to(project_root)

def is_claude_dir(path: Path) -> bool:
    if not isinstance(path, Path):
        return False
    return path.is_relative_to(Path.home() / ".claude")

def is_git_dir(path: Path) -> bool:
    """
    True for the `.git` directory itself and anything under it, at any depth.
    Matched on the standardized parts rather than the written text: `cd .git; echo x > config` writes a git file too.
    """
    return any(part.lower() == ".git" for part in path.parts)

def is_secret(path: Path) -> bool:
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

def is_tmp_file(path: Path) -> bool:
    if sys.platform == "win32" and path.is_relative_to(Path(os.path.expandvars("%LOCALAPPDATA%\\Temp"))):
        return True
    if sys.platform == "win32" and path.is_relative_to(Path("C:\\Windows\\Temp")):
        return True
    return path.is_relative_to(PurePosixPath("/tmp")) or path.is_relative_to(PurePosixPath("/var/tmp")) or path.is_relative_to(PurePosixPath("/dev/null"))

def normalize(input_path: str, cwd: Path) -> Path:
    """
    Turn a written path into the one *bash* computes for `cd` in its default logical mode (`-L`): a `..` drops the previous component textually instead of following the symlink it may sit behind, so `link/..` is the directory holding `link`, not the parent of what it points to.
    `standardize()` stays the right one for every path handed to a command: those are resolved by the kernel, which always follows symlinks first.
    """
    # Resolve variables (order matters)
    input_path = os.path.expandvars(input_path)
    input_path = os.path.expanduser(input_path)
    # A POSIX path on Windows is already canonicalized textually by `standardize`.
    if sys.platform == "win32" and input_path.startswith("/"):
        return standardize(input_path, cwd)
    if not os.path.isabs(input_path):
        input_path = str(cwd / input_path)
    return Path(os.path.normpath(input_path))

def standardize(input_path: str, cwd: Path) -> Path:
    """
    Turn a written path into the real one it designates, anchoring a relative path on the current directory (which moves with `cd`).
    Symlinks are followed, like the kernel does for a path handed to a command.
    """
    # Resolve variables (order matters)
    input_path = os.path.expandvars(input_path)
    input_path = os.path.expanduser(input_path)
    # Handle POSIX paths on Windows
    if sys.platform == "win32" and input_path.startswith("/"):
        input_path = os.path.normpath(input_path)
        path = PurePosixPath(PureWindowsPath(input_path).as_posix())
        # Special case to convert CYGWIN paths like "/c/..." to Windows paths "C:\..."
        if len(path.parts) >= 2 and path.parts[0] == "/" and len(path.parts[1]) == 1 and path.parts[1].isalpha():
            return Path(f"{path.parts[1].upper()}:\\", *path.parts[2:])
        return Path(path)
    # Handle normal paths
    if not os.path.isabs(input_path):
        return (cwd / input_path).resolve()
    else:
        return Path(input_path).resolve()
