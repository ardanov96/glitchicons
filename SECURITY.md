# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.7.x   | ✅ Yes    |
| 0.6.x   | ⚠️ Kritis only |
| < 0.6   | ❌ No     |

## Reporting a Vulnerability

Jika kamu menemukan security issue **di GLITCHICONS itu sendiri**
(bukan di target yang kamu scan), mohon ikuti proses berikut:

### Jangan:
- ❌ Buat public GitHub issue
- ❌ Post di social media sebelum fix dirilis
- ❌ Exploit issue di luar test environment sendiri

### Lakukan:
1. **Email langsung** ke: ardanov96@gmail.com
2. Subject: `[SECURITY] Deskripsi singkat`
3. Sertakan:
   - Deskripsi vulnerability
   - Langkah untuk reproduce
   - Dampak potensial
   - Saran fix (opsional)

### Response Timeline:
- **Acknowledgment**: dalam 48 jam
- **Initial assessment**: dalam 7 hari
- **Fix timeline**: tergantung severity (kritis = < 14 hari)
- **Credit**: nama kamu akan di-mention di release notes (jika diinginkan)

## Scope

Yang termasuk dalam scope:
- Code injection dalam glitchicons.py atau modul manapun
- Privilege escalation dalam CLI
- Path traversal di output handling
- Dependency dengan CVE aktif

Yang tidak termasuk:
- Vulnerability di tools external (afl++, nuclei, ollama) — report ke mereka
- Issue di target yang kamu scan dengan glitchicons
- Social engineering

---

*Built in public. Security taken seriously.*
