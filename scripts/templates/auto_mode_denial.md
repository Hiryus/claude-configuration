**Your tool call was denied because it requires the user validation.**
{reason}

You are in auto mode. In this mode, the user will not validate tool calls.
Any tool call that is not explictely authorized, is denied.

To complete your objective, you need to only request allowed calls.
- The allowed list is described in ~/.claude/scripts/rules.md.
- If you need to run forbidden bash commands, instead run them inside a docker container with "docker run ...".
  You are allowed to mount the project directory inside the container - nothing else.
- Do not try to bypass restrictions.
  If you can't fulfil your objective, just report back to the user.
