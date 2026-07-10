# Writing good tests

## Test behavior, not implementation

A good test survives any refactor that preserves behavior. If renaming an internal helper breaks a test, that test was testing the helper, not the behavior.

Concretely:
- Drive tests through the public interface (the function, the class API, the HTTP route). Never call private helpers or reach into `_internal` attributes.
- Name tests after the capability: `test_compaction_keeps_system_prompt`, not `test_compact_calls_summarise_then_truncate`.
- Assert on observable outcomes (return values, raised exceptions, state visible through the public API), not on which collaborators were invoked.

If you can't think of an assertion that doesn't name an internal, the interface is probably wrong — surface that to the user before continuing. See [interface-design.md](./interface-design.md).

## GIVEN / WHEN / THEN structure

Each test reads in three blocks, separated by a blank line:

```python
def test_compaction_keeps_system_prompt():
    # GIVEN a conversation past the compaction threshold
    conv = build_conversation(messages=50, system="you are aura")

    # WHEN compaction runs
    compacted = compact(conv)

    # THEN the system prompt is preserved verbatim
    assert compacted.system == "you are aura"
```

You don't need the literal comments — but the three-act shape should be visible at a glance. If a test has no clear WHEN (no single action under test), split it.

## What not to test

- **Third-party library internals.** Don't test that pydantic validates, that pytest collects, that `pathlib.Path` joins paths. Test your usage of them, integrated.
- **Trivial pass-throughs.** A one-line wrapper that forwards args adds no behavior to verify. Test the thing it calls instead, or test the integration point that exercises both.
- **Every method.** You're testing behaviors of the system, not methods of classes. One behavior may cross several methods; one method may participate in several behaviors. Coverage of behaviors > coverage of methods.

Coverage target: aim for high coverage of the behavior list you agreed on; don't chase 100% of lines. A thin, sharp test suite beats a fat, flaky one.

## Pytest conventions

Layout:
```
src/aura/<module>.py
tests/<module>/test_<feature>.py
tests/conftest.py
```

Tooling:
- `pytest` — the runner. Plain `def test_x()` functions, no `unittest.TestCase`.
- `@pytest.fixture` — for setup. Prefer `yield`-based fixtures when teardown matters.
- `@pytest.mark.parametrize` — when the same behavior holds across many inputs. One parametrized test, not ten copy-pasted ones.
- `@pytest.mark.<name>` — for slow/integration/e2e tests; register markers in `pyproject.toml` or `pytest.ini` so unknown-marker warnings stay loud.

Test independence:
- Tests must pass in any order. No shared mutable module-level state.
- Fixtures own their setup and teardown. If a test mutates global state (env vars, the registry, a temp dir), the fixture restores it.
