## General rules

- All repository instructions are in the file `AGENTS.md`. Open this file instead of `claude.md`.
- In all interactions and commit messages, be extremely concise and sacrifice grammar for the sake of concision.
- When writing markdown, format the tables correctly so that each column border lines up.

## Tools usage

The `Bash`, `Edit`, `Read`, and `Write` tools have specific restrictions listed in scripts/rules.md.
- Read this file before using them.
- Always use an **allowed** command when possible to avoid asking for the user validation.
  Especially, if you need to run a bash command that is not **allowed** by default, run it inside a container.
- In any case, if you need to run any bash command, clearly state what they do and how they work, then why you need to use them.
