# Code review — current state after `aec8d57..748371d` (6 commits since the last review)

Scope: 6 commits (`aec8d57` cleanup/rename, `9aaf788` template path fix, `6865e5c` docker-volumes spec
clarification, `4799e90` opaque-tail parsing + CLAUDE.md, `db8a845` more git verbs, `748371d` test-path
fix), 18 files touched, 201 insertions / 138 deletions (excluding both sides of the `review.md` and
`rules-gaps.md` relocations). `scripts/rules.md` moved to `SECURITY.md` (repo root) and
`scripts/rules-gaps.md` to `tmp/rules-gaps.md` in `aec8d57`; anchors below use the new locations.

Baseline checks run before this update:

- `uv run --with bashlex --with pytest pytest scripts/tests` → **600 passed, 1 skipped, 30 xfailed**
  (was 596/1/30 — the 4 new passes are `4799e90`'s opaque-tail crash-regression tests)
- `uvx ruff check scripts` → clean
- `uvx ty check scripts` → clean

Findings already tracked in `tmp/rules-gaps.md` are omitted, same as before.


### 3. `file -C -m PATH` still writes a file classified as a read

Unchanged: `scripts/parsers/readonly.py:50` still tables `-m`/`--magic-file` as `input-file`. `file -C
-m notes` writes `notes.mgc`; the manual-mode "writing X requires validation" check never fires for an
in-project target. Still a narrow, low-impact gap; still worth only a `tmp/rules-gaps.md` line unless
someone wants the per-binary special case in `analyzers/readonly.py`.


### Also noticed (not defects in these 6 commits, still unchanged)

- **`CommandLine.subcommand`** (`models/parsing.py:102-103`) and **`Invocation.subcommand`**
  (`models/parsing.py:147-149`) still have no readers anywhere. Both dataclasses were touched twice in
  this range — `db8a845` added grammar nodes that flow through `Invocation`, and `4799e90` added the
  `opaque_tail` field directly next to `Invocation.subcommand` — without anyone needing or removing the
  dead property. Still worth deleting in the next cleanup pass.
- **`CommandLine.environment`** is still read only at `analyzers/git.py:72` and never written anywhere,
  so the `GIT_DIR`-via-environment check is still inert scaffolding. Still deliberate: `tmp/rules-gaps.md`
  #12 (renumbered from `scripts/rules-gaps.md`) and pinned by the same two `strict=True` xfail tests.


### 4. The `rules.md` → `SECURITY.md` rename left dead references, including one the agent sees live

`aec8d57` moved `scripts/rules.md` to `SECURITY.md` and fixed the two callers that read it as data
(`generic.py`'s `check_mode_rules`, later re-fixed for the `~`-path bug in `9aaf788`). It missed every
place that only *mentions* the old path in prose:

- `scripts/templates/auto_mode_denial.md:8` — **"The allowed list is described in
  `~/.claude/scripts/rules.md`."** This is the message rendered back to the agent on every auto-mode
  denial (`generic.py:check_mode_rules`); it now sends the agent looking for a file that doesn't
  exist, on the one path where there's no user around to notice the mistake.
- `README.md:39` and `README.md:52` — both link to `scripts/rules.md`.
- `scripts/generic.py:50` and `scripts/generic.py:77` — docstring links to `rules.md#1-file-rules` and
  `rules.md#modes`.
- `scripts/parsers/readonly.py:2` — links to `../rules.md#28-read-only-binaries`; doubly stale, since
  §2.8 was also renamed "Read binaries" in the same commit (`aec8d57`), so even a path fix would still
  need `#28-read-binaries`.

(`scripts/tests/test_post_markdown.py:75` also names `scripts/rules.md`, but only in a comment
explaining a test fixture — no functional effect, not counted above.)

**Suggested fix:** update all six references — the `auto_mode_denial.md` one first, since it's the
only one an LLM (not a human) reads, and correct the `readonly.py` anchor while at it.


### 5. `6865e5c`'s volume-mount clarification outran both the code and a strict xfail

`6865e5c` rewrote the docker-volumes paragraph of §3.3. It now says explicitly that `/tmp` may be
mounted read-write, that a read-only-only directory (e.g. `~/.claude`) may be mounted `ro`, and adds:
*"Volumes from other containers can also be mounted in read-only."* Checking both directions against
`analyzers/docker.py`:

- **`--volumes-from` never inspects its `:ro`/`:rw` suffix.** `parse_mount_ref`
  (`analyzers/docker.py:229-271`) only iterates `invocation.values("volume")` and
  `invocation.values("mount")`; `volumes-from` sits in `MOUNT_FLAGS` (`analyzers/docker.py:138`) so it
  clears the allowed-flags gate at `validate()` (`:337-338`) but its value is never read. Confirmed:
  `docker run --volumes-from other:rw alpine ls` and `...other:ro alpine ls` both **allow**, with no
  distinction — unlike `-v`/`--mount`, where the suffix is what decides `Access.READ` vs
  `Access.WRITE` (`:252`, `:268`). Unlike the mount-source path, the `:ro`/`:rw` suffix genuinely *is*
  on the command line, so this one is checkable, not merely "trust the container" (that caveat still
  applies to whatever the *named* container itself has mounted, which is unknowable statically either
  way). Only the bare, unsuffixed form is covered by an existing test
  (`test_pre_shell.py:1179,1268`); `:ro`/`:rw` spellings are untested. Not yet in
  `tmp/rules-gaps.md`.

- **The `strict=True` xfail at `test_pre_shell.py:1364-1375`
  (`test_mount_outside_the_project_asks`) is now half-stale.** Its reason string says rule 3.3 is
  "stricter than the file rules" for `/tmp` and `~/.claude`; the new §3.3 text says the opposite for 3
  of its 4 parametrized cases. Re-run in `acceptEdits` mode (as the test does):

  ```
  allow | docker run --rm -v /tmp/work:/work alpine                                    <- now spec-compliant
  allow | docker run --rm --mount type=bind,source=/tmp/work,target=/work alpine        <- now spec-compliant
  allow | docker run --rm --mount type=bind,source=~/.claude,target=/x,ro alpine        <- now spec-compliant
  allow | docker volume create --opt device=/tmp/work data                              <- still a real gap
  ```

  Only the last case is still a genuine mismatch: §3.3's `docker volume create` clause is unchanged
  ("allowed as long as it only references the project directory"). It is *not* covered by
  `tmp/rules-gaps.md` #30 either — that entry is about `-v`/`--mount` on `run`/`exec`/`create`, not
  about `volume create`'s `--opt device=` — so this specific mismatch is currently untracked anywhere.
  The other three cases should be split out of this xfail (they now pass for the right reason) so the
  remaining one can get its own `rules-gaps.md` entry instead of being graded against a rule the spec
  no longer states.
