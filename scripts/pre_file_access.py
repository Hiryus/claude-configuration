import json
import sys

from pathlib import Path

from model import Decision
from utils import expand_glob, format_response, has_glob, in_project, is_git_dir, is_secret, is_tmp_file


def analyze(file_path:str, project_root:Path, tool_name:str, mode:str) -> tuple[Decision, str]:
    if is_secret(file_path, project_root):
        return (Decision.DENY, f"Refusing access to '{file_path}': it contains secret values.")
    elif is_git_dir(file_path, project_root) and tool_name != "read":
        return (Decision.DENY, f"Refusing to {tool_name} '{file_path}': it's a git file'.")
    elif has_glob(file_path):
        matches = expand_glob(file_path, project_root)
        if matches is None:
            if tool_name == "read" and not project_root.exists():
                return (Decision.ALLOW, "")  # the project itself doesn't exist; nothing real to read
            return (Decision.ASK, f"'{file_path}' looks like a glob pattern; cannot statically verify which files it matches.")
        for match in matches:
            decision, reason = analyze(str(match), project_root, tool_name, mode)
            if decision is not Decision.ALLOW:
                return (decision, reason)
    elif not in_project(file_path, project_root) and not is_tmp_file(file_path, project_root):
        return (Decision.ASK, f"Request accesses to '{file_path}' outside the project.")

    if tool_name == "read" or mode in ["acceptEdits", "auto", "bypassPermissions"]:
        return (Decision.ALLOW, "")
    else:
        # Mode "default" -> Standard behavior: prompts for permission on first use of each tool
        # Mode "dontAsk" -> Auto-denies tools unless pre-approved via /permissions or permissions.allow rules
        # Source: https://code.claude.com/docs/en/permissions#permission-modes
        return (Decision.ASK, f"Request accesses to '{file_path}' in {mode} mode.")


def main(input_data:dict) -> str:
    file_path:str = input_data.get("tool_input", {}).get("file_path")
    mode:str = input_data.get("permission_mode", "default")
    project_root = Path(input_data.get("cwd", ""))
    tool_name:str = input_data.get("tool_name", "access").lower()
    if file_path is None:
        return format_response(Decision.DENY.value, "No file_path given.")
    else:
        (decision, reason) = analyze(file_path, project_root, tool_name, mode)
        return format_response(decision.value, reason)


if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
