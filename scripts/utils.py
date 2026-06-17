import json
import os
import re
import sys

from pathlib import Path, PurePosixPath, PureWindowsPath

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

def in_project(path_text: str, project_root: Path) -> bool:
    return standardize(path_text, project_root).is_relative_to(project_root)

def is_git_dir(path_text: str, project_root: Path) -> bool:
    return bool(re.search(r"(?i)(?:^|[\\/])\.git(?:[\\/]|$)", path_text))

def is_secret(path_text: str, project_root: Path) -> bool:
    path = Path(path_text)
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

def is_tmp_file(path_text: str, project_root: Path) -> bool:
    path = standardize(path_text, project_root)
    if sys.platform == "win32" and path.is_relative_to(Path(os.path.expandvars("%LOCALAPPDATA%\\Temp"))):
        return True
    if sys.platform == "win32" and path.is_relative_to(Path("C:\\Windows\\Temp")):
        return True
    if path.is_relative_to(PurePosixPath("/tmp")) or path.is_relative_to(PurePosixPath("/var/tmp")) or path.is_relative_to(PurePosixPath("/dev/null")):
        return True
    return False
