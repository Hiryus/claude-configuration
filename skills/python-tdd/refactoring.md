# Refactoring

Refactoring is the third leg of the cycle, not an afterthought.

## Ground rules

- Only refactor while green. If a step turns the bar red, revert — don't dig forward.
- Run tests after each step, not just at the end.
- Refactor the test code too. Smell there matters as much as in production code.
- The trigger is a smell you can name, not "this might be nicer".

## Common smells

- **Duplication** → extract a function or a `@dataclass`.
- **Long function** → break out private helpers; keep the tests on the public face.
- **Shallow module** (public surface ≈ size of implementation) → merge with a caller, or push more behavior down.
- **Feature envy** (a function reaching into another object's attributes) → move the function next to the data.
- **Primitive obsession** (`str`/`int`/`dict` carrying domain meaning) → introduce a value object: `@dataclass(frozen=True)`, `Enum`, or `NewType`.
- **Stringly-typed args** → `Literal["a", "b", "c"]` or `Enum`.

New code sometimes exposes a smell in *surrounding* code. Surface it to the user — don't quietly expand the refactor.

## Example — primitive obsession

```python
# Before — "role" is a bare str; typos miscompare silently.
def add_message(conv: Conversation, role: str, text: str) -> Conversation: ...

# After — a Literal catches typos at type-check time.
Role = Literal["system", "user", "assistant"]
def add_message(conv: Conversation, role: Role, text: str) -> Conversation: ...
```

## When to stop

- The named smell is gone.
- All tests still pass.
- The next move would require changing tests. That's a signal you'd be reshaping behavior, not refactoring — stop and start a new RED.
