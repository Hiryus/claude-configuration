---
name: python-tdd
description: Drive a change through tight RED → GREEN → REFACTOR cycles using pytest. One failing test, then minimal code to pass, then refactor. Use when coding in python and the user asks for "TDD" ("Test Driven Development"), says "test-first", or wants new behavior added behavior-by-behavior rather than upfront.
---

<what-to-do>
Work one behavior at a time. For eachbehavior, execute _IN THIS ORDER_:
1. **SCAFFOLD** — if the function to test does not exist yet, create a stub for it with its declaration and a `pass` for all body.
2. **RED** — write _ONE_ failing pytest test that names a behavior through the public interface. Run it. Confirm it fails for the reason you expect (not an import error, not a typo).
3. **GREEN** — write the _SMALLEST_ change that makes it pass. No extra fields, no extra branches, no "while I'm here". Run the test. Confirm it passes.
4. **REFACTOR** — only when green. Clean up duplication, deepen the module, rename for clarity.
5. **CONTROL** — run the full test suit (not only the one you implemented, _ALL_ the tests). Also run linter and type checker. Fix any error before moving to next step.

Then pick the next behavior and repeat.

Before the first cycle, agree with the user on:
- the public interface (function signatures, class API, HTTP endpoint shape — whatever the caller sees)
- the ordered list of behaviors to drive out (3–7 items, prioritised)
- which behaviors are out of scope for this round

Show that list back to the user and get a yes before writing the first test.
</what-to-do>

<supporting-info>

## The cardinal sin: horizontal slicing

**Do not write all the tests first, then all the code.** That produces tests of imagined behavior — they assert on the shape you guessed before you knew anything. They pass when the system breaks and break when nothing changed.

Vertical slices only: one test → one implementation → next test. Each cycle teaches you something that informs the next test.

```
WRONG (horizontal):
  RED:   test1, test2, test3, test4, test5
  GREEN: impl1, impl2, impl3, impl4, impl5

RIGHT (vertical):
  RED→GREEN: test1 → impl1
  RED→GREEN: test2 → impl2
  ...
```

## Per-cycle checklist

Before moving to the next behavior:
- [ ] Test names the behavior, not the mechanism
- [ ] Test reaches the code only through the public interface
- [ ] Test would still pass after a plausible internal refactor
- [ ] Production code is the minimum that satisfies the test
- [ ] No speculative fields, branches, or abstractions added
- [ ] Full test file runs green
- [ ] Refactor pass done (or explicitly skipped this cycle)

## Further reading

Load on demand, when the cycle calls for it:

- [writing-tests.md](./writing-tests.md) — what makes a good test: behavior over implementation, GIVEN/WHEN/THEN structure, what not to test, pytest conventions.
- [mocking.md](./mocking.md) — mock at the edges of the system, never inside; prefer fakes over `mock.patch`.
- [interface-design.md](./interface-design.md) — shape production code so tests are easy: dependency injection, return-not-mutate, small surface, SDK-style boundaries.
- [refactoring.md](./refactoring.md) — refactor green code (and tests) using named smells: duplication, long function, shallow module, primitive obsession.
- [troubleshooting.md](./troubleshooting.md) — symptoms and fixes when the cycle stalls.

</supporting-info>
