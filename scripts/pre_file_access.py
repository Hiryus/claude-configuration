"""
Hook pre-processing file access (`Edit` | `Read` | `Write`) to enforce the security rules.
"""

import json
import os
import sys
from collections.abc import Mapping

from generic import check_file_rules, check_mode_rules, format_response
from models.analyzer import Context, Decision
from models.parsing import Access, ContextError, Reference


def analyze(file_path:str, context:Context) -> tuple[Decision, str]:
    access = Access.READ if context.tool_name.lower() == "read" else Access.WRITE
    decision, reason = check_file_rules([Reference(access=access, text=file_path)], context)
    if decision is Decision.ALLOW:
        return (decision, f"Accessing '{file_path}' in {context.mode.value} mode is allowed.")
    return check_mode_rules(decision, reason, context.mode)


def main(input_data:dict, environ:Mapping[str, str] = os.environ) -> str:
    file_path:str = input_data.get("tool_input", {}).get("file_path")
    if file_path is None:
        return format_response(Decision.DENY.value, "No file_path given.")

    try:
        context = Context.of(input_data, environ)
        (decision, reason) = analyze(file_path=file_path, context=context)
        return format_response(decision.value, reason)
    except ContextError as err:
        return format_response(Decision.DENY.value, f"invalid tool context: {err}")


if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:  # noqa: BLE001
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
