# Rules not enforced

Gaps between `rules.md` and the current behavior. Rules that are correctly implemented are omitted, so the numbering has holes.

**Loosening the sandbox** (the rest are stricter than the rule, or wrong in a harmless direction):
- **2.13/3.x** (#28) — `podman` is unknown, so `podman run --privileged` asks instead of denying.
- **2.8** (#38) — a path glued to a short flag (`file -f.env`, `grep -f.env pat`) is neither consumed as a value nor left in the operands, so it is never checked at all.
- **3.3** (#39) — `--volumes-from`'s `:ro`/`:rw` suffix is never checked, so a volume the running container mounted read-only can be re-mounted `:rw`.
- **3.3** (#40) — `docker volume create --opt device=` goes through the general write rules (which allow `/tmp`), not the stricter "project directory only" `volume create` clause.


## 2.8 Read-only binaries

38. [ ] Rule: every path a read-only binary names is checked. Current: only the `--flag value` and `--flag=value` spellings are; a path glued to a short flag (`file -f.env`, `diff -X.env`, `jq -f.env`, `less -k.env`/`-o.env`, `grep -f.env pat`) is neither consumed as a value nor left in the operands, so nothing is checked at all.
        Same root cause as the docker `-u0` of #29: `parse_glued_args` splits a cluster letter by letter and bails as soon as one is not a tabled flag, and `parse_flag` only matches a short flag as a whole token, so `-f.env` ends up an unknown flag that consumes nothing.
        Pre-existing (the empty flag table behaved the same), and it spans `grep`, `docker` and `find` (`-O2`) alike, so fixing it belongs in `parse_flag` -- a prefix match against the tabled value-taking flags, taking the remainder as the glued value -- not in any single binary's grammar.


## 2.9.1 Git directory

12. [ ] Rule: defining `GIT_DIR` is denied. Current: denied only when it sits on the same command line as the `git` call; set by an earlier sub-command (`export GIT_DIR=... ; git log`) it goes through.


## 2.9.2 History security

15. [x] Rule: `git reset --hard` is denied. Current: **ask**.


## 2.9.3 Configuration

16. [ ] Rule: writing the configuration, `git -c` included, is an **ask**. Current: `git -c` is denied.


## 2.9.4 Usual commands

17. [ ] Rule: `git checkout` and `git switch` are allowed. Current: **ask**.
18. [ ] Rule: `git reset` is allowed as long as `--hard` is not used. Current: **ask**.
19. [ ] Rule: `git mv` and `git rm` are allowed, subject to the file rules. Current: **ask**, whatever the paths.
20. [ ] Rule: `git add` is allowed. Current: its pathspecs are path-checked, so a pathspec outside the project asks.
21. [ ] Rule: `git commit` is path-checked only when `--only`/`-o` is supplied. Current: its pathspecs are path-checked in every case.
        Amplified by #36: `-m` is untabled, so it does not consume its value and the message lands in the positionals. A message that used to pass as an in-project filename now asks as soon as it holds an expansion (`git commit -m "$MSG"`).


## 2.9.5 Read-only commands

23. [ ] Rule: only a fixed set of read-only `git branch` flags is allowed; creating a branch is not listed, so it should **ask**. Current: `git branch <name>` is allowed in **edit** and **auto** modes.


## 2.10 Specific find rules

24. [x] Rule: `-fls`, `-fprint`, `-fprint0` and `-fprintf` are denied. Current: allowed. The first three only get their target path-checked; `-fprintf` is not looked at at all, target included.
25. [ ] Rule: only the leading search roots are path-checked. Current: every non-flag word is, so expression values (`-newer FILE`, `-size +1M`, ...) are checked as if they were search roots.


## 2.13 / 3. Containers

28. [ ] Rule: every podman equivalent is allowed or denied alongside its docker counterpart, and the legacy `docker-compose`/`podman-compose` binaries are treated as `docker compose`. Current: none of the three is recognized, so they all fall through to **ask** — including the calls that must be denied, such as `podman run --privileged`.
29. [ ] Rule (3.3): `--user root`/`-u 0` is denied. Current: denied when the value is a separate word, allowed through when it is glued to the flag (`-u0`).
31. [ ] Rule (3.3): every mount source is checked. Current: a spec that repeats `source=`/`src=` only has one of the two checked, a bind-backed named volume declared through `--volume-opt device=` is not checked, and a spec carrying both `ro` and a contradicting `readonly` is read as read-only.
32. [ ] Rule (3.3): the container's own argv is not read as docker options. Current: dropped at the first operand, but only when every option before it is tabled and none swallowed a flag-shaped value — otherwise an option may be read as the operand, so the whole line stays under option parsing (`docker run -u0 alpine app --privileged` is still denied). `docker service create` is not covered: it takes an argv too, but is an ask by default.
33. [ ] Rule (3.4): the build option paths are checked. Current: inside a structured value, only the path-looking fields are checked, so an unanchored one (`--output dest=secrets.env`) is skipped.
39. [ ] Rule (3.3): volumes from other containers may only be mounted read-only. Current: `--volumes-from`'s `:ro`/`:rw` suffix is never inspected — `parse_mount_ref` (`analyzers/docker.py:229-271`) only reads the values of `-v`/`--mount`; `--volumes-from` clears the allowed-flags gate in `validate()` but its value is never read — so `docker run --volumes-from other:rw ...` and `...other:ro ...` both allow, with no distinction.
        Unlike the mount-source path, the `:ro`/`:rw` suffix genuinely is on the command line, so this is checkable (what the *named* container itself has mounted stays unknowable statically, and that half is still "trust the container"). Only the bare, unsuffixed form is tested (`test_pre_shell.py:1179,1268`).
40. [ ] Rule (3.3): `docker volume create` may only reference the project directory. Current: its `--opt device=` value goes through the general write-path check (`analyzers/docker.py:357-361`), which exempts `/tmp` like every other write, though §3.3's `volume create` clause carries no such exemption — `docker volume create --opt device=/tmp/work data` allows.
        Distinct from #30/#31, both about `-v`/`--mount`/`--volume-opt` on `run`/`exec`/`create`, not `volume create`'s own `--opt device=`.
