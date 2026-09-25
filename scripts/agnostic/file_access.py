"""
Analysis of a direct file access (read or write, as the harness resolved it) against the security rules.
"""

from agnostic.generic import check_file_rules, check_mode_rules
from agnostic.models.context import Context
from agnostic.models.decision import Decision, Verdict
from agnostic.models.parsing import Access, Reference


def analyze(file_path:str, access:Access, context:Context) -> Decision:
    decision = check_file_rules([Reference(access=access, text=file_path)], context)
    if decision.verdict is Verdict.ALLOW:
        return Decision.allow(f"Accessing '{file_path}' in {context.mode.value} mode is allowed.")
    return check_mode_rules(decision, context)
