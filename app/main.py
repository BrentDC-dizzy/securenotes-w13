"""
SecureNotes API  —  Week 13 Security Lab (FIXED VERSION)
Web Systems and Technologies

A secured notes service: users register, log in, and keep private notes.
Fixed all 6 OWASP Top 10 (2025) vulnerabilities:
- A01: Broken Access Control (Enforce note ownership checks)
- A02: Security Misconfiguration (Env var for secret, restricted CORS, sanitized 500 handler)
- A04: Cryptographic Failures (PBKDF2 salted password hashing, passwords excluded from user listing)
- A05: Injection (Parameterized SQL queries in login)
- A07: Authentication Failures (Expiring HMAC-signed tokens, uniform login errors)
- A10: Exceptional Conditions (Fail-closed authorization checks)
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

# --- app + config ----------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# A02: Secret key loaded from environment variable with fallback for development
SECRET_KEY = os.getenv("SECRET_KEY", "securenotes-dev-secret-key-change-in-prod-2025")
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour

# A02: CORS locked to explicit trusted origins instead of wildcard '*'
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- security helpers ------------------------------------------------------
def hash_password(password: str, salt: str = None) -> str:
    """A04: Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"{salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """A04: Verify a plain password against stored salt$hash in constant time."""
    try:
        salt, hash_val = stored_hash.split("$", 1)
        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        ).hex()
        return hmac.compare_digest(hash_val, calculated)
    except Exception:
        return False


def create_token(user_id: int) -> str:
    """A07: Create a signed, expiring token: user_id:expiry:signature."""
    expiry = int(time.time()) + TOKEN_EXPIRY_SECONDS
    payload = f"{user_id}:{expiry}"
    sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{sig}"


def verify_token(token_str: str):
    """A07: Verify signed token signature and expiry. Returns user_id or None."""
    try:
        parts = token_str.split(":")
        if len(parts) != 3:
            return None
        user_id_str, expiry_str, sig = parts
        payload = f"{user_id_str}:{expiry_str}"
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(expiry_str) < int(time.time()):
            return None
        return int(user_id_str)
    except Exception:
        return None


# --- database (SQLite, created fresh on startup) ---------------------------
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
    # A04: Seed users with salted PBKDF2 password hashes
    admin_pw = hash_password("admin123")
    alice_pw = hash_password("alicepass")
    bob_pw = hash_password("bobpass")

    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (admin_pw,))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice', ?, 0)", (alice_pw,))
    db.execute("INSERT INTO users (username, password, is_admin) VALUES ('bob', ?, 0)", (bob_pw,))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2, 'Alice diary', 'Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3, 'Bob plans', 'Bob secret note')")
    db.commit()


init_db()


# --- request models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- auth helper -----------------------------------------------------------
def current_user(authorization: str = Header(default=None)):
    """A07 & A10: Read and validate signed token from Authorization header. Fails closed."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )
    token = authorization.replace("Bearer ", "").strip()
    user_id = verify_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return row


# --- error handling --------------------------------------------------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    # A02: Pass through HTTP exceptions, but never leak internal traces for unhandled errors
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# --- routes ----------------------------------------------------------------
@app.post("/register")
def register(creds: Credentials):
    existing = db.execute("SELECT id FROM users WHERE username = ?", (creds.username,)).fetchone()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    # A04: Hash password with unique salt before storing
    hashed = hash_password(creds.password)
    db.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
        (creds.username, hashed),
    )
    db.commit()
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # A05: Parameterized query protects against SQL injection
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
    # A07: Uniform error message prevents username enumeration
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    # A07: Return signed expiring token instead of predictable user ID
    return {"token": create_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    rows = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE owner_id = ?",
        (user["id"],),
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    row = db.execute(
        "SELECT id, owner_id, title, body FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    # A01: Enforce object-level access control (prevent IDOR)
    if row["owner_id"] != user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not own this note",
        )
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    # A10: Authorization check fails closed — unauthenticated / non-admin is strictly denied
    if not user or not user["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    # A04: Exclude password hashes from response
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
