# Vulnerability Findings — Brent Gabriel & Kenneth Bautista

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A01 Broken Access Control | `GET /notes/{note_id}` (lines 133–138) | An attacker can access any user's private note by changing the ID in the request path (IDOR / BOLA) because note ownership is never verified. | Enforce authorization check: verify `row["owner_id"] == user["id"]` and raise 403 Forbidden if not the owner. |
| 2 | A02 Security Misconfiguration | Config & error handler (lines 29, 33–37, 94–99) | Hardcoded secret key compromises signing; wildcard CORS (`allow_origins=["*"]`) allows cross-origin data exposure; 500 handler leaks full debug stack trace. | Loaded secret from environment variable, restricted CORS origins to trusted origins, and removed traceback leak from 500 error handler. |
| 3 | A04 Cryptographic Failures | Seed users, `/register`, `/admin/users` (lines 51, 63–65, 107, 160) | Passwords are stored in plaintext in the database and returned directly in the `/admin/users` endpoint response, exposing user credentials. | Salt and hash passwords using PBKDF2-HMAC-SHA256, verify via `hmac.compare_digest`, and omit password fields from query responses. |
| 4 | A05 Injection | `POST /login` (lines 115–117) | User input is concatenated directly into the SQL query string using an f-string, allowing attackers to bypass login using SQL injection payloads. | Switched to parameterized SQLite query (`WHERE username = ?`, `(creds.username,)`). |
| 5 | A07 Authentication Failures | `POST /login` & `current_user` (lines 86–90, 118–122) | Login returns distinct errors for wrong username vs wrong password (username enumeration), and issues predictable raw user ID strings as non-expiring tokens. | Return a uniform 401 "Invalid username or password" error, and issue cryptographically signed, expiring HMAC tokens. |
| 6 | A10 Exceptional Conditions | `GET /admin/users` (lines 154–160) | The admin permission check uses `try...except Exception: pass`, which catches `TypeError` when an unauthenticated caller is `None` and fails open, granting admin access. | Changed the check to fail closed: verify `if not user or not user["is_admin"]:` and deny with 403 Forbidden. |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

In a production environment, A05 (SQL Injection) represents the highest severity risk because it allows an attacker to manipulate the backend database directly without valid credentials. An attacker can use SQL injection to bypass authentication, exfiltrate the entire database contents, or modify and drop critical tables. When combined with plaintext password storage, a single SQL injection query completely compromises every account and user record across the entire platform.
