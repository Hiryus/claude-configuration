import json

from agnostic.models.decision import Decision


def format_response(decision: Decision) -> str:
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.verdict.value,
            "permissionDecisionReason": decision.reason,
        }
    })
