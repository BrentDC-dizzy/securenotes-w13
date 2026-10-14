# Week 13 Laboratory Activity: Deliverables & Peer Review Sheets

## GitHub Submission Links

- **1. GitHub Repository Link (security-fixes branch)**:  
  https://github.com/BrentDC-dizzy/securenotes-w13/tree/security-fixes

- **2. Your Pull Request Link (Authored by Brent Gabriel)**:  
  https://github.com/BrentDC-dizzy/securenotes-w13/pull/1

- **3. The PR You Reviewed Link (Authored by Kenneth Bautista)**:  
  https://github.com/BrentDC-dizzy/securenotes-w13/pull/2

---

## Part 1: Peer Review Given (Reviewer: Brent Gabriel)

**Reviewed PR**: [PR #2 — https://github.com/BrentDC-dizzy/securenotes-w13/pull/2](https://github.com/BrentDC-dizzy/securenotes-w13/pull/2)  
**Reviewer**: Brent Gabriel  
**Code authored by**: Kenneth Bautista  
**Date**: October 12, 2026  

| Check | Pass? | Note |
|---|:---:|---|
| All 6 risks found & correctly named | Y | Identified A01, A02, A04, A05, A07, and A10 mapped accurately to 2025 OWASP Top 10 |
| Every fix blocks its attack (tested) | Y | Verified: SQL injection blocked, forged tokens rejected, IDOR note access blocked, admin bypass denied |
| App still works (register/login/notes) | Y | Verified: User registration, user authentication, note creation, and note listing all work as expected |
| No plaintext passwords stored/returned | Y | Passwords salted and hashed with PBKDF2-HMAC-SHA256; password column omitted from `/admin/users` |
| No secret / stack trace left in code | Y | `SECRET_KEY` pulled from environment variable; 500 handler returns generic error without traceback |
| Permission checks fail closed | Y | Unauthenticated callers and non-admin requests are strictly denied (401/403) |

**1 strength**:  
Strong implementation of salted password hashing using PBKDF2 with 120,000 iterations and constant-time comparison via `hmac.compare_digest` to prevent timing attacks (A04).

**1 must-fix**:  
In `list_all_users`, `SELECT * FROM users` initially exposed password hashes over the API response; updated query to `SELECT id, username, is_admin FROM users` to exclude password fields entirely.

**1 suggestion**:  
In `get_note`, separated note lookup from ownership check so that requests for notes owned by other users return a distinct 403 Forbidden rather than a generic 404 Not Found.

---

## Part 2: Peer Review Received (Reviewer: Kenneth Bautista)

**Reviewed PR**: [PR #1 — https://github.com/BrentDC-dizzy/securenotes-w13/pull/1](https://github.com/BrentDC-dizzy/securenotes-w13/pull/1)  
**Reviewer**: Kenneth Bautista  
**Code authored by**: Brent Gabriel  
**Date**: October 12, 2026  

| Check | Pass? | Note |
|---|:---:|---|
| All 6 risks found & correctly named | Y | All 6 planted vulnerabilities (A01, A02, A04, A05, A07, A10) correctly documented in `FINDINGS.md` |
| Every fix blocks its attack (tested) | Y | Verified locally with exploit tests: SQL injection blocked, forged tokens rejected, notes protected against IDOR |
| App still works (register/login/notes) | Y | User registration, authentication, note creation, and viewing own notes all function cleanly |
| No plaintext passwords stored/returned | Y | Passwords stored with PBKDF2-HMAC-SHA256 (100k iterations) and salt; omitted from `/admin/users` |
| No secret / stack trace left in code | Y | Secret loaded from environment variable; 500 exception handler returns generic error without traceback |
| Permission checks fail closed | Y | Unauthenticated callers and non-admin requests are strictly denied with 401/403 |

**1 strength**:  
Clean implementation of expiring HMAC tokens (`user_id:expiry:signature`). Signing both user identity and expiration timestamp protects against token tampering and replay attacks (A07).

**1 must-fix / verification**:  
Verified that `/admin/users` was properly filtered to `SELECT id, username, is_admin FROM users` so password hashes are never exposed in the API response payload (A04).

**1 suggestion**:  
In `get_note`, returning `403 Forbidden` on ownership mismatch is clear for clients; consider whether returning `404 Not Found` in production is preferred to prevent attackers from enumerating valid note IDs (A01).
