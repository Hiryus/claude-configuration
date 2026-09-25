# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

"""
The bash rules, exercised straight from a plain `Context`: no payload, no session file, no `~/.claude`.
"""

from pathlib import Path

import pytest

from agnostic.models.context import Context
from agnostic.models.decision import Verdict
from agnostic.models.mode import Mode
from agnostic.shell import analyze

PROJECT = Path("/proj")
HARNESS = Path("/opt/some-harness")


def context(mode=Mode.MANUAL, intent="List the project files") -> Context:
    return Context(current_cwd=PROJECT, harness_root=HARNESS, intent=intent, mode=mode, project_root=PROJECT)

def verdict(command:str, **kwargs) -> Verdict:
    return analyze(command, context(**kwargs)).verdict

@pytest.mark.parametrize("intent", ["", "   "])
def test_missing_intent_is_denied(intent):
    assert verdict("ls", intent=intent) is Verdict.DENY

def test_allowed_command():
    assert verdict("ls /proj") is Verdict.ALLOW

def test_unknown_command_asks():
    assert verdict("make build") is Verdict.ASK

def test_auto_mode_is_enforced_by_the_analysis_itself():
    decision = analyze("make build", context(mode=Mode.AUTO))
    assert decision.verdict is Verdict.DENY
    assert str(HARNESS / "SECURITY.md") in decision.reason

def test_write_to_harness_is_denied():
    assert verdict("echo x > /opt/some-harness/settings.json", mode=Mode.EDIT) is Verdict.DENY

def test_read_from_harness_is_allowed():
    assert verdict("cat /opt/some-harness/settings.json") is Verdict.ALLOW
