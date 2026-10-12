# Vulnerability Findings — Kenneth Bautista & Brent Gabriel

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A01 Broken Access Control | `GET /notes/{note_id}` (lines 133–138) | Any user can view other users' private notes by guessing or enumerating IDs in the route parameter (IDOR). | Added ownership filter `WHERE id = ? AND owner_id = ?` to query so users can only access their own notes. |
| 2 | A02 Security Misconfiguration | App setup & error handler (lines 29, 33–37, 94–99) | Hardcoded secret string in code; wildcard CORS (`allow_origins=["*"]`) allows cross-origin requests; error handler displays full stack traces. | Switched secret key to `os.environ.get`, whitelisted local origins in CORS, and replaced debug trace with generic 500 JSON message. |
| 3 | A04 Cryptographic Failures | Users table & `/register` (lines 51, 63–65, 107) | Plaintext password storage allows anyone with database access to steal user accounts directly. | Implemented PBKDF2 password hashing using 120,000 iterations and per-user cryptographic salt. |
| 4 | A05 Injection | `POST /login` (lines 115–117) | Attacker injects SQL payloads into username string interpolation, bypassing login checks entirely. | Rewrote SQL execution using parameterized queries (`WHERE username = ?`). |
| 5 | A07 Authentication Failures | `POST /login` & auth check (lines 88–90, 118–122) | Leaks whether accounts exist via mismatched errors; generates predictable non-expiring tokens from raw user IDs. | Standardized login error responses and implemented expiring HMAC-SHA256 session tokens. |
| 6 | A10 Exceptional Conditions | `GET /admin/users` (lines 154–160) | The admin check caught all exceptions with `pass`, so errors from unauthenticated requests failed open and gave access. | Implemented strict fail-closed authorization check: verify user presence and `is_admin` flag or return 403. |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

In my opinion, A05 (SQL Injection) causes the most critical damage because it circumvents the entire authorization layer and lets an attacker run commands directly on the database engine. Through SQL injection, an attacker can extract every user record, modify sensitive notes, or elevate themselves to administrator status. When combined with A04 (storing plaintext passwords), a single injection vulnerability leads to a total compromise of all user data.
