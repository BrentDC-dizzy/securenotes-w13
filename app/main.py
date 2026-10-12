"""
SecureNotes API — Week 13 Security Lab
Author: Kenneth Bautista (Partner: Brent Gabriel)
Web Systems and Technologies

Implemented security defenses for OWASP Top 10 (2025) vulnerabilities:
- A01 Broken Access Control: Added ownership query filtering to /notes/{note_id}
- A02 Security Misconfiguration: Moved secrets to environment vars, locked CORS, removed stack trace
- A04 Cryptographic Failures: Password hashing with PBKDF2-HMAC-SHA256 and unique salt
- A05 Injection: Parameterized SQLite queries to stop SQL injection
- A07 Authentication Failures: HMAC-SHA256 signed session tokens with expiry, generic login errors
- A10 Exceptional Conditions: Fail-closed checks on protected routes
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from fastapi import FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- app configuration ----------------------------------------------------
app = FastAPI(title="SecureNotes API - Kenneth Bautista", version="1.0")

# Secret key loaded from environment with fallback
AUTH_SECRET = os.environ.get("SECRET_KEY", "kbautista-securenotes-secret-key-2025")
SESSION_DURATION_SECS = 1800  # 30-minute session expiration

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- cryptographic helpers ------------------------------------------------
def make_password_hash(raw_pwd: str) -> str:
    """Salt and hash password using PBKDF2-HMAC-SHA256 with 120,000 iterations."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", raw_pwd.encode("utf-8"), salt, 120000)
    return f"pbkdf2:{salt.hex()}:{dk.hex()}"


def check_password(raw_pwd: str, stored_val: str) -> bool:
    """Validate password against stored hash using constant-time comparison."""
    try:
        parts = stored_val.split(":")
        if len(parts) != 3 or parts[0] != "pbkdf2":
            return False
        salt = bytes.fromhex(parts[1])
        expected_digest = parts[2]
        computed = hashlib.pbkdf2_hmac("sha256", raw_pwd.encode("utf-8"), salt, 120000).hex()
        return hmac.compare_digest(expected_digest, computed)
    except Exception:
        return False


def generate_session_token(uid: int) -> str:
    """Generate expiring signed session token: uid.expiry.hmac_signature."""
    exp_time = int(time.time()) + SESSION_DURATION_SECS
    body = f"{uid}.{exp_time}"
    mac = hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def validate_session_token(raw_token: str):
    """Validate token signature and expiration timestamp."""
    if not raw_token:
        return None
    token_str = raw_token.replace("Bearer ", "").strip()
    chunks = token_str.split(".")
    if len(chunks) != 3:
        return None
    uid_str, exp_str, sig = chunks
    data = f"{uid_str}.{exp_str}"
    calc_sig = hmac.new(AUTH_SECRET.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, calc_sig):
        return None
    if int(exp_str) < int(time.time()):
        return None
    return int(uid_str)


# --- database setup --------------------------------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # Seed users with hashed passwords
    admin_pw = make_password_hash("admin123")
    alice_pw = make_password_hash("alicepass")
    bob_pw = make_password_hash("bobpass")

    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (admin_pw,))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice', ?, 0)", (alice_pw,))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('bob', ?, 0)", (bob_pw,))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2, 'Alice diary', 'Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3, 'Bob plans', 'Bob secret note')")
    db.commit()


init_db()


# --- pydantic schemas ------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth dependency -------------------------------------------------------
def get_authenticated_user(authorization: str = Header(default=None)):
    """Extract and authenticate caller from Bearer token."""
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user_id = validate_session_token(authorization)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session token")
    row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account not found")
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# --- route handlers --------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    dup = db.execute("SELECT id FROM users WHERE username = ?", (creds.username,)).fetchone()
    if dup:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username is already in use")
    p_hash = make_password_hash(creds.password)
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        (creds.username, p_hash),
    )
    db.commit()
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # Parameterized query to prevent SQLi
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    if row is None or not check_password(creds.password, row["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return {"token": generate_session_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    curr = get_authenticated_user(authorization)
    records = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE owner_id = ?",
        (curr["id"],),
    ).fetchall()
    return [dict(r) for r in records]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    curr = get_authenticated_user(authorization)
    note = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    if note["owner_id"] != curr["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return dict(note)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    curr = get_authenticated_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (curr["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    curr = get_authenticated_user(authorization)
    if not curr or not bool(curr["is_admin"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Administrator access required")
    # Exclude password hashes from response
    users = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(u) for u in users]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
