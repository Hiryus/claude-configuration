# Testable function design

The shape of your code decides how much pain tests cause. Four rules pull most of the weight.

## 1. Accept dependencies, don't construct them

```python
# Hard to test — the provider is welded in.
def compact(conv: Conversation) -> Conversation:
    client = AnthropicClient(api_key=os.environ["ANTHROPIC_API_KEY"])
    summary = client.summarise(conv.older_messages)
    ...

# Testable — pass the collaborator in. The test supplies a fake.
def compact(conv: Conversation, summariser: Summariser) -> Conversation:
    summary = summariser(conv.older_messages)
    ...
```

The injected version takes a fake `summariser` in tests and the real client in production. No `mock.patch` needed.

## 2. Return new values, don't mutate inputs

```python
# Hard to test — assertion has to inspect a mutated object.
def apply_rule(conv: Conversation, rule: Rule) -> None:
    conv.messages.append(rule.to_message())

# Testable — the function's effect *is* its return value.
def apply_rule(conv: Conversation, rule: Rule) -> Conversation:
    return replace(conv, messages=[*conv.messages, rule.to_message()])
```

Pure functions assert in one line: `assert apply_rule(conv, rule).messages[-1] == ...`. If a function's only output is a side effect, tests end up reading internals to confirm it.

## 3. Keep the surface small

Fewer parameters → fewer combinations to set up. Fewer public methods → fewer entry points to cover.

```python
# Wide surface — eight knobs every test has to rewire.
def run_turn(conv, model, tools, skills, permissions, verbosity, hooks, on_event): ...

# Narrow surface — group cohesive params behind one object.
def run_turn(conv: Conversation, context: TurnContext) -> TurnResult: ...
```

If the param list still feels long, the function is doing more than one thing. Split it.

## 4. At system edges, prefer SDK-style functions over a generic fetcher

```python
# Hard to mock — every test reasons about which endpoint is hit.
class Api:
    def call(self, endpoint: str, **kw): ...

# Easy to mock — each operation is its own callable, mockable in isolation.
class ProviderClient(Protocol):
    def send_message(self, conv: Conversation) -> Message: ...
    def list_models(self) -> list[Model]: ...
```

One callable per external operation = each fake returns one shape, no `if endpoint == "..."` branching in tests.
