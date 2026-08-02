Personal configuration and scripts for claude code.

## File structure

```
├─ setings.json               - the claude code central configuration
├─ agents/                    - the agents definitions
├─ commands/                  - the commands definitions
└─ scripts/                   - the agents definitions
   ├─ statusline_command.ps1 - the script rendering the status bar in claude code
   ├─ pre_file_access.py     - a (too) complex script to control and secure bash calls
   └─ pre_shell.py           - a script to control and secure files access from the Read/Edit/Write tools
```

## Requirements

- The [uv command](https://docs.astral.sh/uv/getting-started/installation/) installed and in the PATH.

## Scripts tests

Run tests with `uv run --with bashlex --with pytest pytest scripts/tests`.

## Useful links

- [Official Claude Code documentation for settings](https://code.claude.com/docs/en/settings#available-settings)
- [Claude Code — Complete settings.json Reference](https://gist.github.com/mculp/c082bd1e5a439410158974de90c89db7)
- [How To Kill The Bloat In Claude Code's System Prompt](https://www.aihero.dev/how-to-kill-the-bloat-in-claude-codes-system-prompt)
