---
name: security-review
description: Runs a multi-agent workflow to analyze the security of a project or repository with different lenses. Use when the user wants a thorough multi-angle security review for a feature, refactor, or piece of code, e.g. "review the security of this code base", "perform a security audit of the current application", etc.
---

# Security review

Run this workflow and don't skip steps or shortcut by answering from your own read of the code alone: the point is independent perspectives that you then reconcile.
Do not make any change unless the user ask you to explicitly.

## 1. Orient

- Spawn the `codebase-orienter` subagent with the parameter `run_in_background: false` (you need its output before continuing).
- Ask it for a compact baseline: tech stack, architecture, relevant conventions, and the files/areas relevant to the user request perimeter (the current folder if nothing is specified).
- Keep it under ~1000 words - you'll paste it into every subagent prompt below.

## 2. Fan out

In a single message, spawn these subagents in parallel, each with the parameter `run_in_background: false`:
- `security-reviewer-authentication-specialist`,
- `security-reviewer-authorization-specialist`,
- `security-reviewer-crypto-specialist`,
- `security-reviewer-generalist`,
- `security-reviewer-language-specialist`,
- `security-reviewer-logging-specialist`,
- `security-reviewer-misconfiguration-specialist`,
- `security-reviewer-sanitation-specialist`.

Do not spawn any of them until the baseline is ready.

Give each sub-agent the following prompt, replacing `BASELINE` by the baseline from step 1 and `USER_REQUEST_PERIMETER` by the actual user requested perimeter (the current folder if nothing is specified).
<sub-agent-prompt>
**Task**

Do a thorough security review of:
[USER_REQUEST_PERIMETER]

You review code from a security perspective only — leave quality and maintainability concerns to others, even if you notice them in passing.

Return findings using this format, one per finding:
- **Severity**: critical / high / medium / low (cf. below for scale hints)
- **Summary**: one sentence
- **Location**: file:line
- **Rationale**: why it's a security risk here specifically
- **Suggestion**: concrete fix

**Constraints**

1. Ground your review in the actual code — read the relevant files, don't speculate.
2. No findings is a valid, good outcome — don't invent issues to have something to report.
3. Skip generic checklist advice ("add input validation") that isn't tied to an actual gap you found in this code.
4. Use the following severity classification and icons:
  - 🔴 _Critical Severity_ - the vulnerability is directly exploitable and has a severe impact.
  - 🟠 _High Severity_ - the vulnerability is directly exploitable with moderate impact or has a severe impact.
  - 🟡 _Medium Severity_ - the vulnerability requires specific conditions to be exploitable or has a limited impact.
  - 🟢 _Low Severity_ - the vulnerability requires specific conditions to be exploitable and has a limited impact.

**Baseline**

Below is a baseline of the code base reported by another agent (tech stack, architecture, relevant conventions). Use it to bootstrap your search.
[BASELINE]
</sub-agent-prompt>

## 3. Consolidate - this is your job, not a merge

Read every finding yourself and verify it against the actual code; subagents can be wrong, redundant, or miss context.
Then:
- Drop duplicates and false positives.
- Group the surviving findings by severity (use the same scale as the subagents), not by which agent raised them.
- Where two agents' suggestions conflict, name the tension and state your recommended resolution - don't just list both.
- When relevant, cite file:line for every concrete finding.

## 4. Present, don't implement

- If there is at least one vulnerability, write a consolidated report using the provided [report template](report-template.md) at the repository root with format `security-review-YYYY-MM-DD.md`.
- Print the summary to the user and direct the user towards the written report for details.
- Do not start implementing unless they've already asked you to go ahead - this workflow produces a plan for the user to approve or redirect.
