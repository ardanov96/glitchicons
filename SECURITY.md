# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Full support    |
| 1.9.x   | ✅ Full support    |
| 1.x     | ⚠️ Critical only  |
| < 1.0   | ❌ No support     |

---

## Reporting a Vulnerability

If you discover a security issue **in GLITCHICONS itself**
(not in a target you are scanning), please follow responsible disclosure:

### Do NOT:
- ❌ Open a public GitHub issue
- ❌ Post on social media before a fix is released
- ❌ Exploit the issue outside your own test environment

### DO:
1. **Email directly:** ardanov96@gmail.com
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

### Response Timeline:
- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix timeline:** depends on severity (critical = < 14 days)
- **Credit:** your name will be mentioned in release notes (if desired)

---

## Scope

**In scope:**
- Code injection in any Python module or Go binary
- Privilege escalation via CLI commands
- Path traversal in output/file handling
- Dependencies with active CVEs
- Authentication bypass in the web dashboard

**Out of scope:**
- Vulnerabilities in external tools (Ollama, afl++, etc.) — report to upstream
- Issues in targets scanned using Glitchicons
- Social engineering

---

## Ethical Use

GLITCHICONS is built for **authorized security testing only**.

Users are responsible for ensuring they have explicit written permission before running any scan against any system. Unauthorized use against systems you do not own or have permission to test is illegal and strictly against the intended purpose of this project.

The maintainers are not responsible for any misuse of this tool.

---

## Acknowledgments

Security researchers who responsibly disclose vulnerabilities will be listed here.

*(None yet — be the first.)*

---

*Built in public. Security taken seriously.*
