---
name: mode
argument-hint: info|manual|edit|auto
description: Report or switch the autonomy mode of the current session.
disable-model-invocation: true
---

This body is inert on purpose and carries no instruction to act on.
`/mode` is handled by the `UserPromptSubmit` hook which stops the prompt before this text is ever expanded.
