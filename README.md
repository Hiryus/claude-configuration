Personal configuration and scripts for claude code.

## File structure

```
├─ setings.json              - the claude code central configuration
├─ agents/                   - the agents definitions
├─ skills/                   - the kills definitions (commands are deprecated and now defiend as skills)
└─ scripts/                  - the agents definitions
   ├─ model.py               - the models used by the below scripts
   ├─ pre_file_access.py     - a script to control and secure files access from the Read/Edit/Write tools
   ├─ pre_shell.py           - a (too) complex script to control and secure bash calls
   ├─ statusline_command.ps1 - a script rendering the status bar in claude code
   └─ rules.md               - the validation rules specifications
```

## Requirements

- The [uv command](https://docs.astral.sh/uv/getting-started/installation/) installed and in the PATH.

## Scripts tests

Run tests with `uv run --with bashlex --with pytest pytest scripts/tests`.

## How it works

The claude configuration define two hooks:
- `scripts/pre_file_access.py` for the `Edit|Read|Write` tools,
- `scripts/pre_shell.py` for the `Bash` tools.

Any direct access to a file is thus validated by the `pre_file_access.py` script and any bash command is validated by the `pre_shell.py` script implemented based on [specifications rules](scripts/rules.md).

Analyzing bash commands requires parsing them, which is not exactly easy and not 100% secure due to the complexity and commands updates.
However, it a good compromise between security and usability. A full sandbox would be better, but would require to include git credentials in the sandbox and is not easy to integrate with claude code while keeping good interractivity with the user.

The aura project will eventually solve this issue in a much cleaner way (more tools - fully sandboxed bash by design).
Until then, the bash analysis for claude code is described below.

### Bash analysis

The analysis is done in four passes, detailed in [`scripts/parsing-spec.md`](scripts/parsing-spec.md):
1. **Lexing** (`parsers/parse_bash.py`) turns the bash prompt into `CommandLine(program, args[], assignments[], redirects[])` objects, one per command, each word a `Token` tagged with the shell expansions it is built from. Grammar only, no policy.
2. **Grammar** (`parsers/grammar.py`, `parsers/parse_arguments.py`) pairs a `CommandLine`'s words against a binary's `CommandSyntax` table (keys, flags, subcommands) into an `Invocation(path, arguments[], passthrough[])`. A binary with no table is still parsed, with every word an operand — this is not a fallback, it is what makes `--` safe by default. `find` is the documented exception: it is an expression grammar, not getopt, so it gets its own zone walker instead of a `CommandSyntax` table.
3. **Scope** (`resolve_scope()`) propagates a bare assignment (`GIT_DIR=x; git log`) to the commands that follow it, filling `CommandLine.environment`. Detection only, never used to resolve a path.
4. **Policy** (`parsers/parse_*.py`, `pre_shell.py`) matches the `Invocation` against the [specification rules](scripts/rules.md) to return a `Decision(ALLOW|ASK|DENY)` and a `reason(string)`. Each supported binary has its own `parsers/parse_*.py`; an unrecognised one is analyzed directly and usually asks for human validation.

## Useful links

- [Official Claude Code documentation for settings](https://code.claude.com/docs/en/settings#available-settings)
- [Claude Code — Complete settings.json Reference](https://gist.github.com/mculp/c082bd1e5a439410158974de90c89db7)
- [How To Kill The Bloat In Claude Code's System Prompt](https://www.aihero.dev/how-to-kill-the-bloat-in-claude-codes-system-prompt)
