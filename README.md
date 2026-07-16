Personal configuraiton and scripts for claude code.

The main files are:
* `setings.json` - the claude code central configuration,
* `scripts/statusline_command.ps1` - the script rendering the status bar in claude code,
* `scripts/pre_file_access.py` - a (too) complex script to control and secure bash calls,
* `scripts/pre_shell.py` - a script to control and secure files access from the Read/Edit/Write tools.

## Scripts tests

Run tests with `uv run --with bashlex --with pytest pytest scripts/tests`.

## Useful links

- [Claude Code — Complete settings.json Reference](https://gist.github.com/mculp/c082bd1e5a439410158974de90c89db7)
- [How To Kill The Bloat In Claude Code's System Prompt](https://www.aihero.dev/how-to-kill-the-bloat-in-claude-codes-system-prompt)
