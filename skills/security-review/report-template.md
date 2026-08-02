# Security Review Report

## Summary

- Review Date: [date of the review with format "YYYY-MM-DD"]
- Review Scope: [what was actually reviewed (ex: whole repository / last commits / ...)]
- Findings: 🔴 X | 🟠 X | 🟡 X | 🟢 X

| Severity | Vulnerability ID | Vulnerability Name                        |
|----------|------------------|-------------------------------------------|
| 🔴       | VLN-01           | Broken access control to the /admin route |
| 🔴       | VLN-02           | The application accepts expired JWT       |
| 🟡       | VLN-03           | The session cookie is not http-only       |
| 🟢       | ...              | ...                                       |

[order this table by severity, higher first - All lines are examples in this template]

## Vulnerability details

[Use the below section, once per vulnerability]

### [Vulnerability Severity Icon (🔴 | 🟠 | 🟡 | 🟢)] [Vulnerability ID]: [Vulnerability Name]

**Location:**
`src/path/file.py:45`

**Description:**
[Description of the vulnerability]

**Impact:**
- [Impact 1]
- [Impact 2]

**PoC (Proof of Concept):**
```
[Attack example]
```

**Remediation:**
```
# Before (Vulnerable)
[Vulnerable code]

# After (Safe)
[Fixed code]
```
