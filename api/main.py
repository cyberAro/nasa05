import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, closing
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ.get("FIELD_SHIFT_AUTH_DB", ROOT / "data" / "auth.sqlite3"))
SESSION_COOKIE = "fieldshift_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
COOKIE_SECURE = os.environ.get("FIELD_SHIFT_COOKIE_SECURE", "0") == "1"
ALLOWED_ORIGINS = frozenset(
    origin.strip().rstrip("/")
    for origin in os.environ.get(
        "FIELD_SHIFT_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 64
PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")


def normalize_phone(value: str) -> str:
    phone = re.sub(r"[\s().-]", "", value)
    if phone.startswith("00"):
        phone = phone[2:]
    if phone.startswith("0") and len(phone) == 10:
        phone = "+94" + phone[1:]
    elif phone.startswith("94") and not phone.startswith("+"):
        phone = "+" + phone
    elif len(phone) == 9 and phone.startswith("7"):
        phone = "+94" + phone
    elif not phone.startswith("+"):
        raise ValueError("Enter a phone number with its country code.")
    if not PHONE_PATTERN.fullmatch(phone):
        raise ValueError("Enter a valid international phone number.")
    return phone


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_LENGTH,
        maxmem=64 * 1024 * 1024,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, n, r, p, salt_value, digest_value = stored_hash.split("$")
        if (scheme, int(n), int(r), int(p)) != ("scrypt", SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        salt = base64.urlsafe_b64decode(salt_value.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_value.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_LENGTH,
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str
    password: str = Field(min_length=12, max_length=128)

    @field_validator("name", mode="before")
    @classmethod
    def clean_name(cls, value: str) -> str:
        if isinstance(value, str):
            value = value.strip()
        if not isinstance(value, str) or not value:
            raise ValueError("Enter your name.")
        return value

    @field_validator("phone", mode="before")
    @classmethod
    def clean_phone(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Enter a phone number.")
        return normalize_phone(value)


class LoginRequest(BaseModel):
    phone: str
    password: str = Field(min_length=12, max_length=128)

    @field_validator("phone", mode="before")
    @classmethod
    def clean_phone(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Enter a phone number.")
        return normalize_phone(value)


class SelectRoleRequest(BaseModel):
    role: Literal["farmer", "officer"]


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect_db()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                role TEXT CHECK (role IN ('farmer', 'officer') OR role IS NULL)
            );
            CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(sessions)")}
        if "role" not in columns:
            connection.execute("ALTER TABLE sessions ADD COLUMN role TEXT")
        connection.commit()


def ensure_same_origin(request: Request) -> None:
    origin = request.headers.get("origin", "").rstrip("/")
    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(
    connection: sqlite3.Connection,
    user_id: str,
    response: Response,
) -> None:
    now = int(time.time())
    connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    token = secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (token_digest(token), user_id, now + SESSION_SECONDS),
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def current_user(request: Request) -> dict[str, str | None] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with closing(connect_db()) as connection:
        row = connection.execute(
            """
            SELECT users.id, users.name, users.phone, sessions.role
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (token_digest(token), int(time.time())),
        ).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "name": row["name"], "phone": row["phone"], "role": row["role"]}


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="Aswanna.ai account service", lifespan=lifespan)
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(24))


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    del _request, _exc
    return JSONResponse(
        status_code=422,
        content={"detail": "Check the name, phone number, and password fields."},
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=201)
def register(body: RegisterRequest, request: Request, response: Response) -> dict[str, dict[str, str | None]]:
    ensure_same_origin(request)
    user_id = str(uuid.uuid4())
    now = int(time.time())
    try:
        with closing(connect_db()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO users (id, name, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, body.name, body.phone, hash_password(body.password), now),
                )
                create_session(connection, user_id, response)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with this phone number already exists.") from exc
    return {"user": {"id": user_id, "name": body.name, "phone": body.phone, "role": None}}


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, response: Response) -> dict[str, dict[str, str | None]]:
    ensure_same_origin(request)
    with closing(connect_db()) as connection:
        row = connection.execute(
            "SELECT id, name, phone, password_hash FROM users WHERE phone = ?",
            (body.phone,),
        ).fetchone()
        stored_hash = row["password_hash"] if row else DUMMY_PASSWORD_HASH
        valid = verify_password(body.password, stored_hash)
        if row is None or not valid:
            raise HTTPException(status_code=401, detail="Phone number or password is incorrect.")
        with connection:
            create_session(connection, row["id"], response)
    return {"user": {"id": row["id"], "name": row["name"], "phone": row["phone"], "role": None}}


@app.post("/api/auth/role")
def select_role(body: SelectRoleRequest, request: Request) -> dict[str, dict[str, str | None]]:
    ensure_same_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in before choosing a role.")
    with closing(connect_db()) as connection:
        with connection:
            result = connection.execute(
                "UPDATE sessions SET role = ? WHERE token_hash = ? AND expires_at > ? AND role IS NULL",
                (body.role, token_digest(token), int(time.time())),
            )
            if result.rowcount != 1:
                exists = connection.execute(
                    "SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?",
                    (token_digest(token), int(time.time())),
                ).fetchone()
                if exists:
                    raise HTTPException(status_code=409, detail="Your role is already set. Sign out to choose again.")
                raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    return {"user": user}


@app.get("/api/auth/me")
def me(request: Request) -> dict[str, dict[str, str | None] | None]:
    return {"user": current_user(request)}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    ensure_same_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with closing(connect_db()) as connection:
            with connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"ok": True}
