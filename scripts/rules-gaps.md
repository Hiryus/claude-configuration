# Rules not enforced

Gaps between `rules.md` and the current behavior. Rules that are correctly implemented are omitted, so the numbering has holes.

**Loosening the sandbox** (the rest are stricter than the rule, or wrong in a harmless direction):
- **2.5** (#36) — a `$VAR` path is never seen as dynamic, so `V=~/.ssh/id_rsa; cat $V` is allowed, credentials rule included.
- **2.13/3.x** (#28) — `podman` is unknown, so `podman run --privileged` asks instead of denying.


## Modes

1. [x] Rule: in **auto** mode every **ask** becomes a **deny**. Current: **ask** stays **ask**, in both the file and the shell hook.


## 1.1 No credentials access

2. [x] Rule: `.env.production` is denied. Current: allowed.
3. [x] Rule: the credential extensions are denied whatever their spelling. Current: only the lowercase spelling is denied (`key.PEM` is allowed).
4. [x] Rule: the exempted template suffixes are `.example`, `.sample`, `.template`. Current: `.dist` is exempted too.


## 1.3 No harness modifications

5. [x] Rule: writing anywhere under `~/.claude` is denied, except when it's the project directory - in this case, writes are ask in manual mode and allowed in the other modes..
       Current: it is an **ask** when the project sits elsewhere, and an **allow** when the working directory is the harness itself.


## 1.4 Allowed folders

6. [x] Rule: writes are automatic in **edit** mode only, so a **manual** mode write is an **ask** - whatever the tool that writes.


## 2.3 Current directory

7. [x] Rule: a lone `cd` is allowed. Current: every `cd` is denied.
35. [x] Rule: the hook must know with certainty where the shell is. Current: the hook simulated the move to track it, and got it wrong in three ways — `-L`/`-P` canonicalization, a target that exists but cannot be entered (no `+x`, ex: `/root`), and a target an earlier command deletes. Closed by dropping the simulation entirely: a `cd` is only allowed alone, so the hook always resolves against the directory the harness reports.


## 2.5 Filesystem access

36. [ ] Rule: a path built from a substitution or expansion makes the whole command dynamic, hence an **ask**.
        Current: nothing reads `CommandLine.dynamic`/`Argument.is_dynamic` - they are dead code. `standardize` runs `os.path.expandvars` against the *hook's* environment (not the shell's), and an unset variable stays literal and is then vetted as a plain filename, so `cat $SECRET` resolves to `<project>/$SECRET` and is allowed.
        `$(...)` and `${VAR}` only ask by accident: `(`, `)`, `{` and `}` are in the `has_glob` character set. A bare `$VAR` carries none of them.


## 2.8 Read-only binaries

10. [x] Rule: `cut` and `uniq` are allowed unconditionally, `sort` is path-checked. Current: `cut` is path-checked like `cat`, `sort` and `uniq` ask.
        Closed by fixing the rule, not the code: `cut` and `uniq` take their files as positional operands (no flag involved), and both `sort -o FILE` and `uniq INPUT OUTPUT` write a file, so neither of those two is read-only.
11. [x] Rule: a simple `$VAR`/`${VAR}` substitution is allowed as an argument to these commands. Current: `echo $HOME` is allowed - these commands reference no file, so nothing is ever checked.
        Never a real gap: closed by observation, not by a code change. The opposite problem is real, cf. #36.


## 2.9.1 Git directory

12. [ ] Rule: defining `GIT_DIR` is denied. Current: denied only when it sits on the same command line as the `git` call; set by an earlier sub-command (`export GIT_DIR=... ; git log`) it goes through.


## 2.9.2 History security

13. [ ] Rule: pushing on `main`/`master` is denied. Current: **ask**.
14. [ ] Rule: pushing on a `feat/` or `fix/` branch is allowed. Current: **ask**. No branch name is ever looked at: every push that is not `--force` is an **ask**.
15. [ ] Rule: `git reset --hard` is denied. Current: **ask**.


## 2.9.3 Configuration

16. [ ] Rule: writing the configuration, `git -c` included, is an **ask**. Current: `git -c` is denied.


## 2.9.4 Usual commands

17. [ ] Rule: `git checkout` and `git switch` are allowed. Current: **ask**.
18. [ ] Rule: `git reset` is allowed as long as `--hard` is not used. Current: **ask**.
19. [ ] Rule: `git mv` and `git rm` are allowed, subject to the file rules. Current: **ask**, whatever the paths.
20. [ ] Rule: `git add` is allowed. Current: its pathspecs are path-checked, so a pathspec outside the project asks.
21. [ ] Rule: `git commit` is path-checked only when `--only`/`-o` is supplied. Current: its pathspecs are path-checked in every case.


## 2.9.5 Read-only commands

22. [ ] Rule: `git merge-base` is not listed, so it should **ask**. Current: allowed.
23. [ ] Rule: only a fixed set of read-only `git branch` flags is allowed; creating a branch is not listed, so it should **ask**. Current: `git branch <name>` is allowed in **edit** and **auto** modes.


## 2.10 Specific find rules

24. [ ] Rule: `-fls`, `-fprint`, `-fprint0` and `-fprintf` are denied. Current: allowed. The first three only get their target path-checked; `-fprintf` is not looked at at all, target included.
25. [ ] Rule: only the leading search roots are path-checked. Current: every non-flag word is, so expression values (`-newer FILE`, `-size +1M`, ...) are checked as if they were search roots.


## 2.11 Specific node rules

26. [ ] Rule: `node --version`/`-v` allowed, `node --check <file>` path-checked, anything else **ask**. Current: nothing is implemented, so every `node` call asks — `node --version` included.


## 2.12 Specific npm rules

27. [ ] Rule: `npm --version`/`-v`, `npm ls`, `npm outdated`, `npm view` and `npm audit` (without `fix`) are allowed, plus `npm prune` in **edit** mode. Current: nothing is implemented, so every `npm` call asks.


## 2.13 / 3. Containers

28. [ ] Rule: every podman equivalent is allowed or denied alongside its docker counterpart, and the legacy `docker-compose`/`podman-compose` binaries are treated as `docker compose`. Current: none of the three is recognized, so they all fall through to **ask** — including the calls that must be denied, such as `podman run --privileged`.
29. [ ] Rule (3.3): `--user root`/`-u 0` is denied. Current: denied when the value is a separate word, allowed through when it is glued to the flag (`-u0`).
30. [ ] Rule (3.3): only the project directory and other containers' volumes may be mounted. Current: `/tmp`, `/var/tmp` and (read-only) `~/.claude` may be mounted too.
31. [ ] Rule (3.3): every mount source is checked. Current: a spec that repeats `source=`/`src=` only has one of the two checked, a bind-backed named volume declared through `--volume-opt device=` is not checked, and a spec carrying both `ro` and a contradicting `readonly` is read as read-only.
32. [ ] Rule (3.3): the container's own argv is not read as docker options. Current: dropped at the first operand, but only when every option before it is tabled and none swallowed a flag-shaped value — otherwise an option may be read as the operand, so the whole line stays under option parsing (`docker run -u0 alpine app --privileged` is still denied). `docker service create` is not covered: it takes an argv too, but is an ask by default.
33. [ ] Rule (3.4): the build option paths are checked. Current: inside a structured value, only the path-looking fields are checked, so an unanchored one (`--output dest=secrets.env`) is skipped.

