---
name: review
argument-hint: the last commit
description: Simple and generic code review.
disallowed-tools: Edit Write NotebookEdit
disable-model-invocation: true
---

Please review $ARGUMENTS
Search for and identify any error, bug, inconsistency, or dead code.
If no target given: review the uncommitted diff - if the tree is clean, review the current branch compared to main.

Then, report to the user with, for each finding, the following information:
- A short, simple, and easy to understand summary of the issue (don't be technical here),
- The impact of the issue,
- A description of the issue, including context and root causes,
- One or more suggested fix, including potential side effects or limitations.

Your objective is for the reader to gain a good understanding of the findings, whatever his/her expert level.
- Start with high level explanations, then go into finer details.
- Be clear, precise and concise. Don't say anything false (factually or implicitly) for the sake of simplification.
- Add examples when applicable.

Constraints:
- Ground your review in the actual code — read the relevant files, run tests when applicable, do NOT speculate.
- No findings is a valid, good outcome — don't invent issues to have something to report.
- Do NOT change anything unless asked explicitly.
