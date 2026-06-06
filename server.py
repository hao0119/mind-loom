#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "mind_loom.sqlite3"
COOKIE_NAME = "mind_loom_session"
ANON_COOKIE_NAME = "mind_loom_anon"
SESSION_DAYS = 30
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SECRET_KEY = os.environ.get("SECRET_KEY", "mind-loom-dev-secret").encode("utf-8")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              email TEXT UNIQUE NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
              token_hash TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS thoughts (
              id TEXT PRIMARY KEY,
              user_id TEXT,
              anonymous_id TEXT,
              title TEXT NOT NULL,
              source TEXT NOT NULL,
              mode TEXT NOT NULL,
              energy INTEGER NOT NULL,
              result_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS feedback (
              id TEXT PRIMARY KEY,
              thought_id TEXT,
              user_id TEXT,
              anonymous_id TEXT,
              rating INTEGER,
              text TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(thought_id) REFERENCES thoughts(id),
              FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_cookies(header):
    jar = cookies.SimpleCookie()
    if header:
        jar.load(header)
    return jar


def row_to_thought(row):
    result = json.loads(row["result_json"])
    result["id"] = row["id"]
    result["createdAt"] = row["created_at"]
    result["title"] = row["title"]
    result["source"] = row["source"]
    result["mode"] = row["mode"]
    result["energy"] = row["energy"]
    return result


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json({"ok": True, "time": now_iso()})
            return
        if parsed.path == "/api/session":
            self.handle_session()
            return
        if parsed.path == "/api/thoughts":
            self.handle_list_thoughts()
            return
        if parsed.path == "/privacy":
            self.path = "/privacy.html"
        elif parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            self.handle_login()
            return
        if parsed.path == "/api/logout":
            self.handle_logout()
            return
        if parsed.path == "/api/thoughts":
            self.handle_save_thought()
            return
        if parsed.path == "/api/feedback":
            self.handle_save_feedback()
            return
        self.send_json({"error": "Not found"}, status=404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/thoughts":
            self.handle_clear_thoughts()
            return
        if parsed.path.startswith("/api/thoughts/"):
            thought_id = parsed.path.rsplit("/", 1)[-1]
            self.handle_delete_thought(thought_id)
            return
        self.send_json({"error": "Not found"}, status=404)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def context(self):
        jar = parse_cookies(self.headers.get("Cookie"))
        anonymous_id = jar.get(ANON_COOKIE_NAME).value if jar.get(ANON_COOKIE_NAME) else None
        set_anon_cookie = None
        if not anonymous_id:
            anonymous_id = "anon_" + secrets.token_urlsafe(18)
            set_anon_cookie = self.cookie_header(ANON_COOKIE_NAME, anonymous_id, http_only=False)

        user = None
        session_cookie = jar.get(COOKIE_NAME)
        if session_cookie:
            hashed = token_hash(session_cookie.value)
            with db() as connection:
                row = connection.execute(
                    """
                    SELECT users.id, users.email
                    FROM sessions
                    JOIN users ON users.id = sessions.user_id
                    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                    """,
                    (hashed, int(time.time())),
                ).fetchone()
                if row:
                    user = {"id": row["id"], "email": row["email"]}

        return {"anonymous_id": anonymous_id, "user": user, "set_anon_cookie": set_anon_cookie}

    def cookie_header(self, name, value, http_only=True, max_age=SESSION_DAYS * 24 * 60 * 60):
        flags = [f"{name}={value}", "Path=/", "SameSite=Lax", f"Max-Age={max_age}"]
        if http_only:
            flags.append("HttpOnly")
        if COOKIE_SECURE:
            flags.append("Secure")
        return "; ".join(flags)

    def owner_clause(self, context):
        if context["user"]:
            return "user_id = ?", [context["user"]["id"]]
        return "anonymous_id = ? AND user_id IS NULL", [context["anonymous_id"]]

    def session_headers(self, context, extra=None):
        headers = dict(extra or {})
        if context.get("set_anon_cookie"):
            headers["Set-Cookie"] = context["set_anon_cookie"]
        return headers

    def handle_session(self):
        context = self.context()
        self.send_json(
            {"anonymousId": context["anonymous_id"], "user": context["user"]},
            extra_headers=self.session_headers(context),
        )

    def handle_login(self):
        context = self.context()
        payload = self.read_json()
        email = str(payload.get("email", "")).strip().lower()
        if not EMAIL_RE.match(email):
            self.send_json({"error": "请输入有效邮箱。"}, status=400)
            return

        user_id = "user_" + hmac.new(SECRET_KEY, email.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + SESSION_DAYS * 24 * 60 * 60
        with db() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO users (id, email, created_at) VALUES (?, ?, ?)",
                (user_id, email, now_iso()),
            )
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash(token), user_id, now_iso(), expires_at),
            )
            connection.execute(
                "UPDATE thoughts SET user_id = ?, anonymous_id = NULL WHERE anonymous_id = ? AND user_id IS NULL",
                (user_id, context["anonymous_id"]),
            )
            connection.execute(
                "UPDATE feedback SET user_id = ?, anonymous_id = NULL WHERE anonymous_id = ? AND user_id IS NULL",
                (user_id, context["anonymous_id"]),
            )

        headers = self.session_headers(context, {"Set-Cookie": self.cookie_header(COOKIE_NAME, token)})
        self.send_json({"user": {"id": user_id, "email": email}}, extra_headers=headers)

    def handle_logout(self):
        jar = parse_cookies(self.headers.get("Cookie"))
        session_cookie = jar.get(COOKIE_NAME)
        if session_cookie:
            with db() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(session_cookie.value),))
        self.send_json({"ok": True}, extra_headers={"Set-Cookie": self.cookie_header(COOKIE_NAME, "", max_age=0)})

    def handle_list_thoughts(self):
        context = self.context()
        clause, params = self.owner_clause(context)
        with db() as connection:
            rows = connection.execute(
                f"SELECT * FROM thoughts WHERE {clause} ORDER BY created_at DESC LIMIT 100",
                params,
            ).fetchall()
        self.send_json(
            {"thoughts": [row_to_thought(row) for row in rows]},
            extra_headers=self.session_headers(context),
        )

    def handle_save_thought(self):
        context = self.context()
        payload = self.read_json()
        required = ["id", "title", "source", "mode", "energy"]
        if any(not payload.get(key) for key in required):
            self.send_json({"error": "缺少必要字段。"}, status=400)
            return

        created_at = payload.get("createdAt") or now_iso()
        result_json = json.dumps(payload, ensure_ascii=False)
        user_id = context["user"]["id"] if context["user"] else None
        anonymous_id = None if user_id else context["anonymous_id"]

        with db() as connection:
            connection.execute(
                """
                INSERT INTO thoughts
                  (id, user_id, anonymous_id, title, source, mode, energy, result_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  title = excluded.title,
                  source = excluded.source,
                  mode = excluded.mode,
                  energy = excluded.energy,
                  result_json = excluded.result_json,
                  updated_at = excluded.updated_at
                """,
                (
                    payload["id"],
                    user_id,
                    anonymous_id,
                    payload["title"],
                    payload["source"],
                    payload["mode"],
                    int(payload["energy"]),
                    result_json,
                    created_at,
                    now_iso(),
                ),
            )
        self.send_json({"ok": True}, extra_headers=self.session_headers(context))

    def handle_delete_thought(self, thought_id):
        context = self.context()
        clause, params = self.owner_clause(context)
        with db() as connection:
            connection.execute(f"DELETE FROM thoughts WHERE id = ? AND {clause}", [thought_id] + params)
        self.send_json({"ok": True}, extra_headers=self.session_headers(context))

    def handle_clear_thoughts(self):
        context = self.context()
        clause, params = self.owner_clause(context)
        with db() as connection:
            connection.execute(f"DELETE FROM thoughts WHERE {clause}", params)
        self.send_json({"ok": True}, extra_headers=self.session_headers(context))

    def handle_save_feedback(self):
        context = self.context()
        payload = self.read_json()
        rating = payload.get("rating")
        if rating is not None:
            rating = int(rating)
            if rating < 1 or rating > 5:
                self.send_json({"error": "评分必须是 1 到 5。"}, status=400)
                return

        user_id = context["user"]["id"] if context["user"] else None
        anonymous_id = None if user_id else context["anonymous_id"]
        with db() as connection:
            connection.execute(
                """
                INSERT INTO feedback (id, thought_id, user_id, anonymous_id, rating, text, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.get("id") or "fb_" + secrets.token_urlsafe(16),
                    payload.get("thoughtId"),
                    user_id,
                    anonymous_id,
                    rating,
                    str(payload.get("text", ""))[:2000],
                    now_iso(),
                ),
            )
        self.send_json({"ok": True}, extra_headers=self.session_headers(context))


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8787"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Mind Loom is running at http://{host}:{port}", flush=True)
    server.serve_forever()
