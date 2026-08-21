# Plan: track the current directory

Goal: resolve relative paths against the **real cwd** of each sub-command, and stop using the cwd as the project boundary.

## Problem

`Context.project_root` is read from the payload `cwd` and used for two unrelated jobs:

| Job                            | Used by                                    | Source       |
| ------------------------------ | ------------------------------------------ | ------------ |
| anchor for relative paths      | `standardize()`, `expand_glob()`           | current dir  |
| project boundary (1.2/1.3/1.4) | `in_project()`, `is_file_access_allowed()` | project root |

While `cd` is denied the two coincide. As soon as `cd` is allowed (rule 2.3 / gap 7) they diverge and both jobs break:
- relative path resolved against the wrong dir,
- project boundary moves with the agent (`cd /tmp` -> `/tmp` becomes "the project").

## Step 0 - project-root source: CONFIRMED

Probed by dumping `os.environ` from `pre_shell.py` (probe since reverted):

| Fact                       | Value                                   |
| -------------------------- | --------------------------------------- |
| `CLAUDE_PROJECT_DIR`       | `/home/hiryus/.claude` (= project root) |
| payload `cwd`              | `/home/hiryus/.claude`                  |
| payload `workspace` key    | absent (statusline payloads only)       |
| hook process `os.getcwd()` | `/home/hiryus/.claude`                  |

So: `project_root` <- `CLAUDE_PROJECT_DIR`, `cwd` <- payload `cwd`.

**No fallback chain** (amended): both are *required*. A missing/empty `CLAUDE_PROJECT_DIR`, or a missing/empty payload `cwd`, is an error -> **refuse the call** (deny). Guessing one from the other reintroduces exactly the conflation this plan removes, and silently degrades to an unbounded project boundary.

## Step 1 - [x] split cwd from project_root

`models/analyzer.py`:

```python
@dataclass(frozen=True)
class Context:
    cwd:Path = Path()              # current dir, moves with `cd`
    previous_cwd:Path|None = None  # $OLDPWD for `cd -`; None until the first cd
    project_root:Path = Path()     # fixed for the whole call
    ...

    @staticmethod
    def of(input_data:dict, environ:Mapping[str,str] = os.environ) -> "Context":
        cwd = input_data.get("cwd", "")
        project_root = environ.get("CLAUDE_PROJECT_DIR", "")
        if not cwd:
            raise ContextError("payload has no `cwd`")
        if not project_root:
            raise ContextError("CLAUDE_PROJECT_DIR is not set")
        return Context(cwd=Path(cwd), project_root=Path(project_root), ...)
```

**Injection.** `environ` is injectable so tests can set it without monkeypatching, but the route has to be opened: today `main()` calls `Context.of(input_data)` with no environ (`pre_shell.py:117`, `pre_file_access.py:23`) and the tests call `main()` directly. So both hooks get `def main(input_data:dict, environ:Mapping[str,str] = os.environ)` and thread it into `Context.of`. That single param is what step 6's `output(project_root=...)` writes to.

**Error path.** `ContextError` is a new exception in `models/parsing.py`, next to `ParseError` - that is the module `main()` already imports and catches from. `main()` currently catches `ParseError` only (`pre_shell.py:127`); the bare `except Exception` net lives in `__main__` (`pre_shell.py:132-135`), *outside* `main()`, so an uncaught raise would give the tests a traceback instead of a deny payload. So: catch `ContextError` next to `ParseError` in `main()` and return `format_response(DENY, f"Hook cannot determine the working directory: {err}")`. `pre_file_access.py` has no try at all in `main()` (`pre_file_access.py:18-24`) - wrap the `Context.of` call there the same way.

`utils/filesystem.py` stays pure (no `Context` import), params made explicit:

Three groups, once step 2 lands: the anchoring helpers take `cwd`, the boundary helpers take `project_root`, and the classifiers take a standardized path and nothing else.

| Before                                   | After                                              |
| ---------------------------------------- | -------------------------------------------------- |
| `standardize(text, project_root)`        | `standardize(text, cwd)`                           |
| `expand_glob(text, project_root)`        | `expand_glob(text, cwd)`                           |
| `expand_references(refs, project_root)`  | `expand_references(refs, cwd)`                     |
| `in_project(text, project_root)`         | `in_project(path, project_root)`                   |
| `is_file_access_allowed(text, pr, read)` | `is_file_access_allowed(path, project_root, read)` |
| `is_claude_dir(text, project_root)`      | `is_claude_dir(path)`                              |
| `is_tmp_file(text, project_root)`        | `is_tmp_file(path)`                                |
| `is_secret(text, project_root)`          | `is_secret(path)`                                  |
| `is_git_dir(text, project_root)`         | `is_git_dir(path)`                                 |

Do not "simplify" `generic.py:67` - `is_claude_dir(...) and not in_project(...)` is how rule 1.3's "project *is* the harness" exception is expressed. It still composes under this split.

`generic.py`: `check_file_rules(references, project_root, mode)` -> `check_file_rules(references, context)`.
Callers: `generic.py:51`, `pre_file_access.py:12`.

## Step 2 - [x] standardize once, then apply the predicates (security fix)

**This must land with step 1, not after.** `is_git_dir()` regex-matches the *raw* text and `is_secret()` builds `Path(raw)`. Today harmless because `cd` is denied. Once cwd tracking lands:

```
cd .git && echo x > config
```

`is_git_dir("config")` -> False -> `in_project()` standardizes to `<proj>/.git/config` -> in project -> **ALLOW**. Rule 1.2 defeated. Same class for `is_secret` (`cd ~/.ssh && cat id_rsa` keeps its name check, but the `.ssh`-in-parts check dies).

Fix: the pipeline in `check_file_rules()` becomes **expand (with `cwd`) -> standardize each result -> predicates**, in that order. Not "standardize first": `has_glob()` needs the raw text and `expand_references()` does its own anchoring. Side benefit: drops the `project_root` param `is_secret`/`is_git_dir` never used.

Caveat: `standardize()` returns `Path|PurePosixPath` (a POSIX path on Windows, `filesystem.py:108-112`), so every predicate must accept the union. `is_claude_dir` already guards with `isinstance(path, Path)`; `is_secret`'s win32 `rstrip(".")` works on raw text today and needs a decision when it moves to a resolved path.

## Step 3 - [~] scope tags in the bash parser

Dropped entirely, scope tags and conditional tag alike. A `cd` is now allowed only when it is the only command of the call (`rules.md` §2.3), so there is nothing to isolate per scope, and nothing depends on whether a command runs: the hook predicts nothing about the shell, it reads the resulting directory from the harness on the next call.

**Ordering is not the problem.** `collect()` sorts by `pos[0]`, and positions are monotonic with the enclosing sequence, so `cd /tmp && cat $(ls)` already yields `cd` first. The one inversion is *within* a command (`cat $(git log)` -> `cat` before `git log`), and it is harmless: both run with the same inherited cwd. No re-ordering needed.

What breaks a linear fold is **isolation** and **conditionality**:

| Construct                    | Problem                                 | Handling  |
| ---------------------------- | --------------------------------------- | --------- |
| `(cd /tmp && ls); cat x`     | subshell - cd must not leak to `cat x`  | scope tag |
| `echo $(cd /tmp && pwd)`     | substitution - isolated                 | scope tag |
| `cd /tmp \| ls`              | each pipeline stage is its own subshell | scope tag |
| `cd /tmp &`                  | async - runs in its own subshell        | scope tag |
| `if ...; then cd /tmp; fi`   | did it run?                             | **deny**  |
| `for f in *; do cd $f; done` | how many times?                         | **deny**  |
| `cmd \|\| cd /tmp`           | runs only if `cmd` failed               | **deny**  |
| `test -d x && cd x`          | runs only if the left side succeeded    | **deny**  |

The last four are not a parser limitation - they are statically unknowable, and rule 2.3 ("the hook must know with certainty") licenses the deny.

`&&` is **not** uniformly safe, and the asymmetry matters:
- `cd x && cat y` - `cd` on the **left**, allowed: step 4 already verified the target exists, so the `cd` succeeds and `cat y` runs.
- `test -d x && cd x` - `cd` on the **right**, denied: the left side may fail, and `false && cd /tmp; cat x` would then desync the fold in the permissive direction.

Implementation - no tree rewrite, the list stays flat and position-sorted:

- `collect()` computes for each command node a **scope path** (tuple of ids of the enclosing isolation nodes: `( )`, `$( )`/backticks, pipeline stage) and a **conditional** flag (inside an `if`/`for`/`while` body, or on the right of `||`).
- `CommandLine` gains `scope:tuple[int,...]` and `conditional:bool`. Grammar only, still no policy.
- `analyze()` folds with `cwd_by_scope:dict[tuple, Path]`: a command inherits the cwd of its nearest ancestor scope prefix; a `cd` writes back only to its own scope. Leaving a scope discards it implicitly - the tuple never recurs.
- `cd` with `conditional=True` -> **DENY**, reason telling the agent to run it as a plain sequence.

## Step 4 - [~] `cd` semantics

Dropped: the hook resolves no `cd` target at all. `parsers/cd.py` and `analyzers/cd.py` were deleted; only the `pushd`/`popd`/`exec`/`eval` denials remain.

`cd` is **intercepted in `analyze()`** (step 5's fold), before the generic verdicts: it is the only command whose verdict also produces state. The `command.base == "cd"` branch of `check_command()` (`pre_shell.py:53`) is deleted, not rewritten, and `cd.validate()` deliberately does *not* have the `check_command` shape - it returns a 3-tuple and must never be fed to `worst()`.

Two new modules, following the repo's parser/analyzer split:

- **`parsers/cd.py`** - grammar only, no policy: `CommandSyntax(aliases=["cd"], flags=[Flag(name="physical", keys=["-P"], value_required=False), Flag(name="logical", keys=["-L"], value_required=False)])` + `parse()` delegating to `arguments.parse`, like `parsers/sed.py`. Only these two are tabled; anything else (`-e`, `-@`, ...) lands in `unknown` and denies, per the `sed.py:8-9` idiom.
- **`analyzers/cd.py`** - the decision table below, `validate(command, context) -> (Decision, str, moved)` where `moved` is the new `(cwd, previous_cwd)` or `None` (signature used by step 5).

Note on `-`: `arguments.parse` classifies a bare `-` as an **unknown flag** (`arguments.py:33` matches on `startswith("-")`, and `parse_glued_args` is skipped since `len(key) <= 2`), not as a positional. So `analyzers/cd.py` detects `cd -` as "exactly one unknown argument, `key == "-"`, no positional" rather than looking for a `-` operand. Do not table it as a `Flag`: that would also swallow `cd -- -`.

New handling:

| Form                     | Decision | cwd effect       |
| ------------------------ | -------- | ---------------- |
| `cd` (no arg)            | allow    | `$HOME`          |
| `cd /abs`, `cd rel`      | allow    | resolved         |
| `cd ~/x`                 | allow    | tilde-expanded   |
| `cd -- path`, `-P`, `-L` | allow    | resolved         |
| `cd $VAR`, `cd $(...)`   | deny     | -                |
| target is not a real dir | deny     | -                |
| conditional (step 3)     | deny     | -                |
| isolated (step 3)        | allow    | scope-local only |
| outside the project      | allow    | resolved         |
| `cd -` (previous known)  | allow    | previous dir     |
| `cd -` (no previous yet) | deny     | -                |

Reuse `Token.dynamic` (TILDE excluded) for the dynamic case.

`cd` outside the project is **allowed** (decided): the `cd` itself discloses nothing, and every later access is still path-checked against the unchanged `project_root`.

Non-existent target must deny: `cd /nope; cat x` leaves the shell in the *old* dir while the hook believes it moved.

`cd -` is **tracked** (decided). Bash keeps the previous dir in `$OLDPWD`:
- every successful `cd` sets `previous_cwd` to the dir it left,
- `cd -` swaps: new cwd = `previous_cwd`, new `previous_cwd` = the dir it left,
- `$OLDPWD` is per-shell, so it inherits and discards on exactly the same scope boundaries as the cwd (step 3) - one more field in the per-scope state, no new mechanism,
- the payload carries no `OLDPWD`, so a `cd -` before any tracked `cd` in the scope chain has no resolvable target -> **DENY**, consistent with rule 2.3.

If it turns out to be a burden during implementation, fall back to denying `cd -` outright.

`pushd`/`popd`/`exec`/`eval` -> explicit **DENY** in `check_command()`, where the old `cd` deny sat. None of them is in the allow-list today, so all four currently fall through to ASK; an approved ASK desyncs tracking silently (`pushd`/`popd`) or hands over an unanalyzable command (`exec`/`eval`).

## Step 5 - [~] thread the cwd through the analysis

Dropped: the payload cwd is authoritative for the whole call, so there is no fold.

`pre_shell.analyze()` becomes a fold over the position-sorted commands, keyed by scope: `cd` updates the state *before* the next command of that scope is checked.

The per-scope state is the pair `(cwd, previous_cwd)` - both are per-shell in bash, so both inherit and discard on the same boundaries.

```python
state_by_scope:dict[tuple, tuple[Path, Path|None]] = {(): (context.cwd, None)}
for command in commands:
    cwd, previous = inherited(state_by_scope, command.scope)
    current = replace(context, cwd=cwd, previous_cwd=previous)
    if command.base == "cd":
        decision, reason, moved = cd.validate(command, current)  # moved: the new (cwd, previous) or None
        if moved is not None:
            state_by_scope[command.scope] = moved
        results.append((decision, reason))
    else:
        verdicts = [check_access(command, references, current), check_command(command, references, current)]
        results.append(worst(*verdicts))
```

`inherited()` walks `command.scope` prefixes outwards and returns the first state present - that is the "inherit on entry, discard on exit" rule, with no explicit stack.

Analyzer signatures are unchanged - they already take a `Context`, they just get the right cwd now. `git`/`grep`/`find`/`sed`/`docker` inherit correct relative-path resolution for free.

## Step 6 - [x] tests

`tests/test_pre_shell.py` and `tests/test_pre_file_access.py`: `output()` gains a `project_root` kwarg **defaulting to the `cwd` argument**, passed as `main(payload, environ={"CLAUDE_PROJECT_DIR": project_root})` (the param added in step 1); `project_root=None` sends `{}`, i.e. the var unset. Since `CLAUDE_PROJECT_DIR` is now mandatory (step 0) it cannot default to unset, but root == cwd reproduces today's behavior exactly, so **existing tests pass unchanged**.

New cases:
- `CLAUDE_PROJECT_DIR` unset -> deny, no traceback
- payload `cwd` missing or empty -> deny, no traceback
- `cd sub && cat file.txt` -> resolved under `<proj>/sub`
- `cd /tmp && cat /proj/x` -> still in project
- `cd /tmp` does not move the project boundary (`cat /tmp/../etc/passwd` still asks)
- `cd .git && echo x > config` -> deny (step 2 regression guard)
- `cd $HOME` / `cd $(pwd)` -> deny
- `cd /nonexistent` -> deny
- `(cd /tmp && cat x); cat y` -> `x` under `/tmp`, `y` under the project (scope isolation)
- `cd /tmp | ls`, `echo $(cd /tmp)`, then a later `cat x` -> `x` still under the project
- `cmd || cd /tmp`, `if x; then cd /tmp; fi`, `test -d x && cd x` -> deny (conditional)
- `cd /tmp && cd - && cat x` -> `x` under the project (`cd -` round trip)
- `cd -` as the first cd -> deny (no tracked previous)
- `(cd /tmp); cd -` -> deny (the subshell's OLDPWD does not leak out)
- `pushd`/`popd` -> deny

To revisit - they encode the current conflation:
- `test_pre_file_access.py:159` (`cwd=str(harness / "scripts")`, asserts deny) - a subdir cwd currently defeats harness-as-project detection; with `CLAUDE_PROJECT_DIR` honored the intent changes.
- `test_pre_file_access.py:145` and `:151` - same family.

## Step 7 - [x] docs

`rules.md` §2.3 - rule changes, all approved:
- ~~"target does not exist" denies~~ - **done**, already written by the user in §2.3, do not rewrite it.
- `pushd`/`popd`/`exec`/`eval` -> DENY: approved, still to write in §2.3.
- Still to write: conditional context denies; isolated `cd` (subshell, substitution, pipeline stage, `&`) is scope-local; `cd -` is allowed once a previous dir is tracked in the scope chain, denied before that.
- Still to write: the hook denies the call outright when it cannot read `CLAUDE_PROJECT_DIR` or the payload `cwd` (step 0) - same "must know with certainty" reason.

Plain documentation:
- `rules-gaps.md`: close item 7.
- `README.md`: the "Bash analysis" section references `parsers/parse_bash.py`, `parsers/grammar.py` and `scripts/parsing-spec.md`, none of which exist. Fix the paths while touching it.

## Decided

- `project_root` <- `CLAUDE_PROJECT_DIR` (confirmed present) and `cwd` <- payload `cwd`, both **mandatory**: no fallback, missing value -> deny the call (step 0).
- Isolated `cd` is tracked per scope, not denied; only conditional `cd` denies (step 3).
- `cd` outside the project -> **allow** (step 4).
- `cd -` -> **tracked** via a per-scope `previous_cwd` (step 4). Fall back to denying it if it proves a burden while implementing.
- **Cross-call persistence**: the payload `cwd` is taken as the authoritative current directory at the start of each call. If it ever fails to follow a `cd` from a previous call, that is a harness bug to report, not something this hook works around.

No open questions - ready to implement.
