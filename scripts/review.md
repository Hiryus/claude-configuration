# Code review — last 8 commits (`ba486d5` back to `071611e`)

Scope: 26 files, ~850 insertions / ~930 deletions.

Baseline checks run before the review:

- `uv run --with bashlex --with pytest pytest scripts/tests` → **596 passed, 1 skipped, 30 xfailed**
- `uvx ruff check scripts` → clean
- `uvx ty check scripts` → clean

Every finding below was confirmed by driving `pre_shell.main()` against crafted command lines,
not by reading alone. Findings already tracked in `rules-gaps.md` (#36, #37, #38, #32, #12, …)
are deliberately omitted.


## 1. `rules.md` §2.7 lost the pip/mypy/python rules, but the code still enforces them

**Summary.** A commit deleted the "use `uv` instead of pip/python/mypy" paragraphs from the
specification, but left the matching denials in the hook. The spec and the code now disagree, and
the denial messages send the agent toward commands that are themselves refused.

**Impact.** Moderate, and it bites in normal use. In **auto** mode the agent hits a hard wall with
no exit:

```
deny | mypy .            -> Do not use `mypy`. Use ty with `uv run ty` instead.
deny | uv run ty check   -> denied: `uv` is not in the allow-list
deny | pip install x     -> Do not use `pip`. Use `uv add`, `uv sync`, or `uvx` instead.
deny | uv add requests   -> denied: `uv` is not in the allow-list
```

Every route the message recommends is an `ask`, which auto mode converts to `deny`. The agent is
told what to do and then blocked from doing it.

**Description / root cause.** Commit `9f7e04a` ("remove python/uv/uvx rules for simplification and
cleanup") removed the §2.7 clauses from `rules.md` and the `uv` analyzer branch, but three things
survived it:

- `pre_shell.py:69-73` still returns `DENY` for `mypy` and for `^pip[\d.]*$`;
- `tests/test_pre_shell.py:242-252` still asserts both are denied;
- `tests/test_pre_shell.py:254` is a `strict=True` xfail named `test_python_denied` whose reason
  cites "rule 2.7 … (the pip/mypy ones survived)" — a rule that no longer exists in the document.

`rules-gaps.md`, which exists precisely to record spec-vs-code divergence, has no §2.7 entry.
Since the live tests still pin the behaviour, the **document** is the stale side, not the code.

**Suggested fixes.**

- *Preferred:* restore a short §2.7 clause covering `pip` and `mypy` (and state explicitly what
  `python` should do, so the strict xfail points at a real rule). Purely documentation — zero
  behavioural risk.
- Then fix the messages, which are now misleading whichever way you go: either re-allow the
  recommended escape hatch (`uv run ty`, `uv add`) or reword the denials to point at something the
  hook actually permits (e.g. running the tool in a container, per the standing recommendation in
  §2 of `rules.md`).
- *Alternative:* if the removal was meant to be total, delete both branches plus the three tests.
  Side effect: `mypy`/`pip` degrade from `deny` to `ask`, which is a real loosening — so this only
  makes sense if that was the intent.


## 2. `jq --slurpfile=NAME FILE` skips the file check entirely (regression from `ba486d5`)

**Summary.** The new "flag eats two words" support only works in the `--flag value` spelling.
Written with an `=`, the second word — the one that can be a file path — silently falls through and
is never checked. For `jq` it then gets discarded as the filter program, so a secret file passes.

**Impact.** Low in practice, real as a checker hole. Confirmed:

```
deny  | jq --slurpfile a .env . d.json           <- correct
allow | jq --slurpfile=a .env . d.json           <- .env never checked
allow | jq --rawfile=a .env . d.json
allow | jq --slurpfile=a /home/other/x . d.json  <- out-of-project read, no ask
```

Before this commit the same line was **denied**: these binaries were parsed with an empty flag
table, so `.env` stayed an operand and was path-checked. That makes it a regression, not a
pre-existing gap.

To be precise about severity: `jq` itself does not accept the `=` spelling for these options, so
the command would fail at runtime and no data would actually leak. This is a hole in the checker's
model, not a live exfiltration path.

**Description / root cause.** `parsers/arguments.py:114-120`:

```python
if "=" in token.text:
    return Token(text=token.text.partition("=")[2], expansions=token.expansions)  # value_count ignored
elif value_required:
    if len(tokens) < value_count: raise ParseError(...)
    consumed = [tokens.pop(0) for _ in range(value_count)]
    return Token(text=consumed[-1].text, expansions=frozenset(...))
```

The `=` branch predates `value_count` and was never taught about it. So `--slurpfile=a` yields
value `"a"` and consumes nothing further. `.env` becomes operand #0, and `analyzers/readonly.py:14-20`
then drops operand #0 as jq's filter program (correct for `jq '.x' file`, wrong here). Two
independently reasonable rules compose into a blind spot. The same shape applies to `--rawfile=`,
`--arg=`, `--argjson=`; only `jq` declares `value_count=2`, so nothing else is affected.

**Suggested fixes.**

- *Cleanest, and it matches rule 2.1 ("if parsing fails, deny"):* raise `ParseError` in the `=`
  branch when `value_count > 1`. The spelling is invalid for the only tool that uses it, so
  refusing to parse it is both correct and safe — an unparseable line is already denied. Two lines,
  no effect on any other command.
- *Alternative:* in the `=` branch, when `value_count > 1`, take the `=` part as the first word and
  pop the remaining `value_count - 1` from `tokens`. Closer to "what would the tool do", but it
  invents semantics `jq` does not have.
- Either way, put the fix in `parse_value`, not in `readonly.operands()` — the defect is in the
  shared grammar walker, and patching the jq-specific side would leave the general case broken for
  the next two-word flag added.


## 3. `file -C -m PATH` writes a file but is classified as a read

**Summary.** `file`'s magic-file option is tabled as an input, which is right for every use except
one: combined with `-C`, `file` *compiles* the magic file and writes the result.

**Impact.** Low, and narrow. `file -C -m notes` writes `notes.mgc`. Since the reference is recorded
as a `READ`, the manual-mode "writing X requires your validation" check never fires:

```
allow | file -C -m out.mgc     (manual mode, in-project target)
deny  | file -C -m .env        (still denied — the secret rule reads the literal name)
```

The deny rules are unaffected (they don't care about access mode), and an out-of-project target
still asks. So the only lost verdict is a manual-mode write prompt on an in-project path.

**Description / root cause.** `parsers/readonly.py:47-50` buckets `-m`/`--magic-file` as
`input-file`. That is correct for plain `file -m magic target`; the module docstring's three-bucket
model just has no way to express "read, unless `-C` is also present". `file` is otherwise genuinely
read-only, so this is the single exception.

**Suggested fixes.** Worth noting the misclassification rather than patching it, because a
mechanical fix doesn't actually name the right file:

- Re-bucketing `-m` as `output-file` would be wrong in the common case *and* still wouldn't help —
  the file written is `PATH.mgc`, not `PATH`, so the reference would name a path that is never
  touched.
- A correct fix needs a small conditional in `analyzers/readonly.py`: when `command.base == "file"`
  and `-C` is present, emit an extra `Reference(WRITE, f"{value}.mgc")`. That is a per-binary
  special case in a module that has so far kept exactly one (jq's operand rule), so it's a judgment
  call whether it earns its keep.
- Cheapest option: record it in `rules-gaps.md` alongside the other §2.8 entries and move on.


## Also noticed (not defects in these commits)

- **`CommandLine.subcommand`** (`models/parsing.py:101`) and **`Invocation.subcommand`**
  (`models/parsing.py:146`) have no readers anywhere. History check: `command.subcommand` was last
  used before `442ceef`, well before this range, so both predate these commits. Worth deleting
  during the next cleanup pass, since the "cleanup" commits in this range removed the
  `conditional`/`scope`/`dynamic` fields for exactly this reason.
- **`CommandLine.environment`** is read at `analyzers/git.py:72` but never written, so the `GIT_DIR`
  environment check is inert. This one is deliberate scaffolding: it is `rules-gaps.md` #12 and is
  pinned by two `strict=True` xfail tests.


## What held up

The rest of the range holds up well under probing:

- The `Reference`-carries-expansions refactor is consistently applied — every `Reference(...)`
  construction site was checked.
- `strip_container_argv`'s trust conditions are sound; no docker flag in `RUN_FLAGS`/`EXEC_FLAGS` is
  mis-declared as a boolean in a way that would let the strip point drift and hide a
  `--privileged`.
- All thirteen read-only grammars were audited for the two failure modes the module docstring warns
  about — a path-valued flag bucketed as `option`, and an optional-value flag declared
  `value_required=True` that would swallow the next filename. Neither occurs.
- The compose global flag table is fully partitioned by `COMPOSE_ALLOWED_FLAGS` ∪
  `COMPOSE_UNSAFE_FLAGS` ∪ `{help}`, so no global option slips through the `ALLOWED_COMMANDS`
  branch unchecked.
