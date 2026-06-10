# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v5.5.x  | ✅ Current |
| v5.x    | ✅ Active  |
| < v5.0  | ❌ No longer maintained |

## Reporting a Vulnerability

If you discover a security vulnerability **in Glitchicons itself** (not a finding from running it), please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

Email: **ardanov96@gmail.com**

Subject line: `[SECURITY] Glitchicons - Brief description`

Include:
- Glitchicons version affected
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

| Step | Timeline |
|------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix + release | Within 30 days (critical: 7 days) |
| CVE request | If applicable |

### What qualifies

- Code execution via crafted input to Glitchicons itself
- Authentication bypass in `glitchagent` or `glitchorchestrator` APIs
- Path traversal in binary dispatching (`glitchd`)
- Credential exposure via log output
- `glitchimplant` engagement token forgery

### What does NOT qualify

- Findings produced by running Glitchicons against a target (that's the tool working correctly)
- Issues in third-party dependencies (report to the upstream project)
- Issues requiring physical access to the machine running Glitchicons

## Ethical Use

Glitchicons is built for **authorized penetration testing only**.

- Always obtain explicit written permission before scanning any system
- `glitchimplant` requires a signed HMAC engagement token — do not circumvent this
- `glitchcloud` requires your own cloud credentials — it cannot scan others' environments
- Unauthorized use is illegal under computer fraud laws in most jurisdictions

The maintainers are not responsible for misuse of this tool.

---

MIT License © 2026 GLITCHICONS
