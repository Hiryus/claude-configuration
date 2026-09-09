---
name: mode
argument-hint: info|manual|edit|auto
description: Report or switch the autonomy mode of the current session.
disable-model-invocation: true
---

This body is inert on purpose and carries no instruction to act on.

`/mode` is handled by the `UserPromptSubmit` hook (`~/.claude/scripts/user_prompt_submit.py`), which
stops the prompt before this text is ever expanded. Reading it means the hook did not run: the mode
is unchanged and only the user can change it.
