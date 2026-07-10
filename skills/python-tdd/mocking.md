# Mocking: externals only

Mock at the **edges of your system**, never inside it.

- ✅ Mock: HTTP calls to model providers, filesystem when irrelevant to the test, the system clock, subprocess spawns.
- ❌ Don't mock: your own modules, classes, or functions. If you find yourself patching `aura.something.SomeClass`, stop — the test is now coupled to internal wiring and will break on refactor.

Prefer fakes over mocks when you can: an in-memory fake of the provider client tells a better story than `mock.patch` with `assert_called_with`.

```python
# Brittle — patches an internal symbol path.
def test_send_calls_provider(monkeypatch):
    mock_client = Mock()
    monkeypatch.setattr("aura.agent.AnthropicClient", lambda **kw: mock_client)
    run_turn(conv)
    mock_client.send.assert_called_once()  # tests wiring, not behavior

# Robust — pass a fake at the edge; assert on the observable outcome.
class FakeProvider:
    def send_message(self, conv):
        return Message(role="assistant", text="ok")

def test_run_turn_appends_assistant_reply():
    result = run_turn(conv, provider=FakeProvider())
    assert result.messages[-1].role == "assistant"
```

The right shape at the boundary makes fakes trivial — see [interface-design.md](./interface-design.md) for how to design that boundary.
