# Rules not enforced

Gaps between `rules.md` and the current behavior. Rules that are correctly implemented are omitted, so the numbering has holes.


## 2.13 / 3. Containers

32. [ ] Rule (3.3): the container's own argv is not read as docker options. Current: dropped at the first operand, but only when every option before it is tabled and none swallowed a flag-shaped value — otherwise an option may be read as the operand, so the whole line stays under option parsing (`docker run -x0 alpine app --privileged` is still denied, `-x0` being a genuinely untabled flag). `docker service create` is not covered: it takes an argv too, but is an ask by default.
