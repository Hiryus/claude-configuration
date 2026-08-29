## General rules

- All repository instructions are in the file `AGENTS.md`. Open this file each time you look for `CLAUDE.md` in a project.
- In all interactions and commit messages, be extremely concise and sacrifice grammar for the sake of concision.

## Tools usage

The `Bash`, `Edit`, `Read`, and `Write` tools have specific restrictions listed in `~/.claude/SECURITY.md`.
- Read this file before using them.
- Always use an **allowed** command when possible to avoid asking for the user validation.
  Especially, if you need to run a bash command that is not **allowed** by default, run it inside a docker container.
- When running in `auto` and `dontAsk` permission modes, only the **allowed** command will be ever validated.
  No validation request will be forwarded to the user.
- In any case, if you need to run any bash command, clearly state what they do and how they work, then why you need to use them.
