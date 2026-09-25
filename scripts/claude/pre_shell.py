"""
Hook pre-processing `Bash` calls to enforce the security rules.
"""

import json
import os
import sys
from collections.abc import Mapping

from agnostic.models.decision import Decision
from agnostic.models.parsing import ContextError, ParseError
from agnostic.shell import analyze
from claude.utils.context import context_of
from claude.utils.response import format_response


def main(input_data:dict, environ:Mapping[str, str] = os.environ) -> str:
    try:
        context = context_of(input_data, environ)
        tool_name:str = input_data.get("tool_name", "")
        prompt:str = input_data.get("tool_input", {}).get("command")
        if tool_name != "Bash":
            return format_response(Decision.deny(f"Tool `{tool_name}` is not allowed. Use the `Bash` tool instead."))
        else:
            return format_response(analyze(prompt, context))
    except ContextError as err:
        return format_response(Decision.deny(f"invalid tool context: {err}"))
    except ParseError as err:
        return format_response(Decision.deny(f"Refusing to run an unparseable command: {err}"))

if __name__ == "__main__":
    try:
        input_data:dict = json.loads(sys.stdin.read())
        print(main(input_data))
    except Exception as err: # noqa: BLE001
        print(format_response(Decision.deny(f"Hook error, denying for safety: {err}")))
