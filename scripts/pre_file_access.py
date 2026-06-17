import json
import sys

from pathlib import Path

from model import Decision
from utils import format_response, has_glob, in_project, is_git_dir, is_secret, is_tmp_file


def analyze(file_path:str, project_root:Path, tool_name:str) -> tuple[Decision, str]:
    if is_secret(file_path, project_root):
        return (Decision.DENY, f"Refusing access to '{file_path}': it contains secret values.")
    elif is_git_dir(file_path, project_root) and tool_name != "read":
        return (Decision.DENY, f"Refusing to {tool_name} '{file_path}': it's a git file'.")
    elif has_glob(file_path):
        return (Decision.ASK, f"'{file_path}' looks like a glob pattern; cannot statically verify which files it matches.")
    elif not in_project(file_path, project_root) and not is_tmp_file(file_path, project_root):
        return (Decision.ASK, f"Request accesses to '{file_path}' outside the project.")
    else:
        return (Decision.ALLOW, "")


def main(input_data:dict) -> str:
    file_path: str = input_data.get("tool_input", {}).get("file_path")
    project_root = Path(input_data.get("cwd", ""))
    tool_name: str = input_data.get("tool_name", "access").lower()
    if file_path is None:
        return format_response(Decision.DENY.value, "No file_path given.")
    else:
        (decision, reason) = analyze(file_path, project_root, tool_name)
        return format_response(decision.value, reason)


if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
