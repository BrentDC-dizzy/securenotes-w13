# Peer Review Sheet

**Reviewer pair**: Brent Gabriel & Kenneth Bautista  
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
