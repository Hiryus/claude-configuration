"""
Hook pre-processing file access (`Edit` | `Read` | `Write` | `Grep`) to enforce the security rules.
"""

import json
import os
import sys
from collections.abc import Mapping

from agnostic.file_access import analyze
from agnostic.models.decision import Decision
from agnostic.models.parsing import Access, ContextError
from claude.utils.context import context_of
from claude.utils.response import format_response


def main(input_data:dict, environ:Mapping[str, str] = os.environ) -> str:
    tool_name:str = input_data.get("tool_name", "").lower()
    tool_input = input_data.get("tool_input", {})
    # `Grep` names its search location `path` (optional, defaults to the cwd) rather than `file_path`.
    if tool_name == "grep":
        file_path:str = tool_input.get("path") or "."
    else:
        file_path:str = tool_input.get("file_path")
    if file_path is None:
        return format_response(Decision.deny("No file_path given."))
    # Any tool not known to only read is a write: an unknown tool fails closed.
    access = Access.READ if tool_name in ("read", "grep") else Access.WRITE

    try:
        context = context_of(input_data, environ)
        return format_response(analyze(file_path=file_path, access=access, context=context))
    except ContextError as err:
        return format_response(Decision.deny(f"invalid tool context: {err}"))


if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:  # noqa: BLE001
        print(format_response(Decision.deny(f"Hook error, denying for safety: {err}")))
