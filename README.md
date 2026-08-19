Personal configuration and scripts for claude code.

## File structure

```
├─ setings.json              - the claude code central configuration
├─ agents/                   - the agents definitions
├─ skills/                   - the kills definitions (commands are deprecated and now defiend as skills)
└─ scripts/                  - the agents definitions
   ├─ analyzers/             - the per-binary policy checks (docker, find, git, grep, sed)
   ├─ models/                - the models shared by all the scripts
   ├─ parsers/               - the bash lexing and per-binary argument grammars
   ├─ utils/                 - the pure helpers (filesystem paths, message formatting)
   ├─ generic.py             - the command-agnostic policy (file rules, access checks) and the hook response
   ├─ pre_file_access.py     - a script to control and secure files access from the Read/Edit/Write tools
   ├─ pre_shell.py           - a (too) complex script to control and secure bash calls
   ├─ statusline_command.py  - a script rendering the status bar in claude code
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

The analysis is done in four passes:
1. **Lexing** (`parsers/bash.py`) turns the bash prompt into `CommandLine(program, args[], assignments[], redirects[])` objects, one per command, each word a `Token` tagged with the shell expansions it is built from. Grammar only, no policy.
2. **Grammar** (`models/grammar.py`, `parsers/arguments.py`) pairs a `CommandLine`'s words against a binary's `CommandSyntax` table (aliases, flags, subcommands) into an `Invocation(cmd_parts[], arguments[])`. A binary with no table is still parsed, with every word an operand — this is not a fallback, it is what makes `--` safe by default. `find` is the documented exception: it is an expression grammar, not getopt, so it gets its own zone walker instead of a `CommandSyntax` table.
3. **Scope** (`parsers/bash.py`) tags each command with the execution shape it sits in: the chain of enclosing isolation contexts (subshell, substitution, pipeline stage, `&`) and whether it is conditional. That is what lets `pre_shell.analyze()` fold the commands into a current directory, so a relative path is resolved against the directory the shell is really in (cf. [rule 2.3](scripts/rules.md#23-tracking-current-directory)). Propagating a bare assignment (`GIT_DIR=x; git log`) to the commands that follow belongs to this pass too, and is not implemented yet.
4. **Policy** (`analyzers/*.py`, `pre_shell.py`) matches the `Invocation` against the [specification rules](scripts/rules.md) to return a `Decision(ALLOW|ASK|DENY)` and a `reason(string)`. Each supported binary has its own `analyzers/*.py`; an unrecognised one is analyzed directly and usually asks for human validation.

Two directories are threaded through every check and must not be confused: the **current directory** (`Context.cwd`, from the payload) anchors relative paths and moves with `cd`, while the **project directory** (`Context.project_root`, from `CLAUDE_PROJECT_DIR`) is the perimeter of the file rules and is fixed for the whole call. Both are mandatory: the hook denies the call when it cannot read either.

## Useful links

- [Official Claude Code documentation for settings](https://code.claude.com/docs/en/settings#available-settings)
- [Claude Code — Complete settings.json Reference](https://gist.github.com/mculp/c082bd1e5a439410158974de90c89db7)
- [How To Kill The Bloat In Claude Code's System Prompt](https://www.aihero.dev/how-to-kill-the-bloat-in-claude-codes-system-prompt)
