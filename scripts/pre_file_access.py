import json
import sys

from generic import check_file_rules, check_mode_rules, format_response
from models.analyzer import Context, Decision
from models.parsing import Access, Reference


def analyze(file_path:str, context:Context) -> tuple[Decision, str]:
    access = Access.READ if context.tool_name.lower() == "read" else Access.WRITE
    reference = Reference(access=access, text=file_path)
    decision, reason = check_file_rules([reference], context.project_root, context.mode)
    if decision is Decision.ALLOW:
        return (decision, f"Accessing '{file_path}' in {context.mode.value} mode is allowed.")
    return check_mode_rules(decision, reason, context.mode)


def main(input_data:dict) -> str:
    file_path:str = input_data.get("tool_input", {}).get("file_path")
    if file_path is None:
        return format_response(Decision.DENY.value, "No file_path given.")

    (decision, reason) = analyze(file_path=file_path, context=Context.of(input_data))
    return format_response(decision.value, reason)


if __name__ == "__main__":
    try:
        input_data: dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err:  # noqa: BLE001
        print(format_response(Decision.DENY.value, f"Hook error, denying for safety: {err}"))
