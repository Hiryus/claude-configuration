# pytest is a test-only dependency and is not resolved by the linters.
# pyright: reportMissingImports=false
# ty: ignore[unresolved-import]

"""
The file rules, exercised straight from a plain `Context`: no payload, no session file, no `~/.claude`.
"""

from pathlib import Path

import pytest

from agnostic.file_access import analyze
from agnostic.models.context import Context
from agnostic.models.decision import Verdict
from agnostic.models.mode import Mode
from agnostic.models.parsing import Access

PROJECT = Path("/proj")
HARNESS = Path("/opt/some-harness")


SHARED = Path("/opt/shared-harness")


def context(mode=Mode.MANUAL, project_root=PROJECT) -> Context:
    return Context(current_cwd=project_root, harness_roots=[HARNESS, SHARED], mode=mode, project_root=project_root)

def verdict(file_path:str, access:Access, **kwargs) -> Verdict:
    return analyze(file_path, access, context(**kwargs)).verdict

def test_read_in_project_is_allowed():
    assert verdict("/proj/main.py", Access.READ) is Verdict.ALLOW

@pytest.mark.parametrize(("mode", "expected"), [(Mode.MANUAL, Verdict.ASK), (Mode.EDIT, Verdict.ALLOW), (Mode.AUTO, Verdict.ALLOW)])
def test_write_in_project_follows_mode(mode, expected):
    assert verdict("/proj/main.py", Access.WRITE, mode=mode) is expected

def test_secret_is_denied_whatever_the_access():
    assert verdict("/proj/.env", Access.READ) is Verdict.DENY
    assert verdict("/proj/.env", Access.WRITE, mode=Mode.EDIT) is Verdict.DENY

def test_harness_root_comes_from_the_context():
    assert verdict("/opt/some-harness/settings.json", Access.READ) is Verdict.ALLOW
    assert verdict("/opt/some-harness/settings.json", Access.WRITE, mode=Mode.EDIT) is Verdict.DENY

def test_every_harness_root_is_protected():
    assert verdict("/opt/shared-harness/scripts/hook.py", Access.READ) is Verdict.ALLOW
    assert verdict("/opt/shared-harness/scripts/hook.py", Access.WRITE, mode=Mode.EDIT) is Verdict.DENY

def test_harness_as_project_is_writable():
    assert verdict("/opt/some-harness/settings.json", Access.WRITE, mode=Mode.EDIT, project_root=HARNESS) is Verdict.ALLOW

def test_outside_project_asks():
    assert verdict("/etc/hosts", Access.READ) is Verdict.ASK

def test_auto_mode_turns_ask_into_deny_and_points_to_the_harness_rules():
    decision = analyze("/etc/hosts", Access.READ, context(mode=Mode.AUTO))
    assert decision.verdict is Verdict.DENY
    assert "~/ai-harness/SECURITY.md" in decision.reason
    assert "/etc/hosts" in decision.reason
