## General rules

- All repository instructions are in the file `AGENTS.md`. Open this file each time you look for `CLAUDE.md` in a project.
- In all interactions and commit messages, be extremely concise and sacrifice grammar for the sake of concision.

## Modes

- The session runs in one of three modes - `manual`, `edit`, or `auto` - shown in the status bar and set by the user with the `mode` command.
- The `manual` mode is the default. Any tool call that is not explicitly allowed requires the user's validation.
- Compared to `manual` mode, the `edit` mode also allows to write allowed files without the user's validation.
- In `auto` mode, only the **allowed** calls will ever run. No validation request will be forwarded to the user.

## Tools usage

The `Bash`, `Edit`, `Read`, and `Write` tools have specific restrictions listed in `~/.claude/SECURITY.md`.
- Read this file before using them.
- Always use an **allowed** command when possible to avoid asking for the user validation.
  Especially, if you need to run a bash command that is not **allowed** by default, run it inside a docker container.
- Whatever the mode, when running `Bash` commands, avoid shell expansions and variables as they require the user's validation to work.
- Whatever the mode, when running `Bash`, clearly state what they do and how they work, then why you need to use them.
