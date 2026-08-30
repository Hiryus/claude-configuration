# Rules not enforced

Gaps between `rules.md` and the current behavior. Rules that are correctly implemented are omitted, so the numbering has holes.


## 2.8 Read-only binaries

38. [ ] Rule: every path a read-only binary names is checked. Current: only the `--flag value` and `--flag=value` spellings are; a path glued to a short flag (`file -f.env`, `diff -X.env`, `jq -f.env`, `less -k.env`/`-o.env`, `grep -f.env pat`) is neither consumed as a value nor left in the operands, so nothing is checked at all.
        Same root cause as the docker `-u0` of #29: `parse_glued_args` splits a cluster letter by letter and bails as soon as one is not a tabled flag, and `parse_flag` only matches a short flag as a whole token, so `-f.env` ends up an unknown flag that consumes nothing.
        Pre-existing (the empty flag table behaved the same), and it spans `grep`, `docker` and `find` (`-O2`) alike, so fixing it belongs in `parse_flag` -- a prefix match against the tabled value-taking flags, taking the remainder as the glued value -- not in any single binary's grammar.


## 2.13 / 3. Containers

29. [ ] Rule (3.3): `--user root`/`-u 0` is denied. Current: denied when the value is a separate word, allowed through when it is glued to the flag (`-u0`).
32. [ ] Rule (3.3): the container's own argv is not read as docker options. Current: dropped at the first operand, but only when every option before it is tabled and none swallowed a flag-shaped value — otherwise an option may be read as the operand, so the whole line stays under option parsing (`docker run -u0 alpine app --privileged` is still denied). `docker service create` is not covered: it takes an argv too, but is an ask by default.
40. [ ] Rule (3.3): `docker volume create` may only reference the project directory. Current: its `--opt device=` value goes through the general write-path check (`analyzers/docker.py:357-361`), which exempts `/tmp` like every other write, though §3.3's `volume create` clause carries no such exemption — `docker volume create --opt device=/tmp/work data` allows.
        Distinct from #30/#31, both about `-v`/`--mount`/`--volume-opt` on `run`/`exec`/`create`, not `volume create`'s own `--opt device=`.
