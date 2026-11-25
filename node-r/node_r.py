#!/usr/bin/env python3
"""Node R — Blind Relay Service（強化版）。

店內中繼只保存密文信封，從不解密內容。裝置以 Ed25519 簽章認證。

Canonical signing format
------------------------
客戶端簽署以下 UTF-8 字串的位元組（五段以換行連接）：

    METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nSHA256_HEX(raw body bytes)

- METHOD：大寫 HTTP 方法（GET、POST、DELETE）。
- PATH：僅 URL 路徑，不含 query string，例如 /api/v2/uplink/status。
- TIMESTAMP：Unix 秒，十進位數字字串。必須落在伺服器時間加減 CLOCK_SKEW
  秒之內（預設 300）。
- NONCE：同一裝置在時間窗內不可重複；重放會被拒絕。
- SHA256_HEX：原始 request body 的小寫十六進位 SHA-256。空 body（GET
  常見）是對空位元組雜湊，即
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855。

Ed25519 簽章以十六進位放在 X-Signature（大小寫皆可）。必要標頭：
X-Device-Id、X-Timestamp、X-Nonce、X-Signature。

Clock skew
----------
GET /api/v2/health 無需認證，回傳 server_unix_ts。客戶端應計算
offset = server_unix_ts - local_unix_ts，並用 local_unix_ts + offset 簽署。

Ack flow
--------
BOSS 必須先把已提取的信封寫入自己的本地總帳，才可呼叫
POST /api/v2/uplink/ack，本文為 {"relay_ids": [...]}。請求由老闆簽章
（body 雜湊包含在 canonical string 內），因此已簽署的本文即為收據。
Node R 先寫入 ack_log，再刪除佇列中確實存在的列，並回傳已清除的 id。
技師端不可把紀錄標成已送達，直至 GET /api/v2/uplink/status 回傳
state=acked。

Roles
-----
THERAPIST：POST /api/v2/uplink/records、GET /api/v2/uplink/status
BOSS：GET /api/v2/uplink/fetch、POST /api/v2/uplink/ack
（DELETE /api/v2/uplink/purge 是 ack 的別名，同樣需要已簽署的 JSON 本文。）
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import os
import shutil
import sqlite3
import sys
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Iterable

import nacl.encoding
import nacl.exceptions
import nacl.signing
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

log = logging.getLogger("node_r")

DEFAULT_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
)
EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_NONCE_LEN = 128
MAX_DEVICE_ID_LEN = 128
MAX_CLIENT_RECORD_ID_LEN = 128
ED25519_SIG_HEX_LEN = 128
ED25519_PUB_HEX_LEN = 64
ROLES = frozenset({"THERAPIST", "BOSS"})
ACTIVE = "ACTIVE"
REVOKED = "REVOKED"


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _parse_cidrs(raw: str | None) -> tuple[str, ...]:
    if raw is None or raw.strip() == "":
        return DEFAULT_CIDRS
    parts = tuple(p.strip() for p in raw.split(",") if p.strip())
    return parts or DEFAULT_CIDRS


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: _env("NODE_R_DB", "node_r.db"))
    host: str = field(default_factory=lambda: _env("NODE_R_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("NODE_R_PORT", 8000))
    clock_skew: int = field(default_factory=lambda: _env_int("NODE_R_CLOCK_SKEW", 300))
    max_envelope: int = field(
        default_factory=lambda: _env_int("NODE_R_MAX_ENVELOPE", 64 * 1024)
    )
    pending_cap: int = field(default_factory=lambda: _env_int("NODE_R_PENDING_CAP", 5000))
    min_free_bytes: int = field(
        default_factory=lambda: _env_int("NODE_R_DISK_MIN_FREE", 200 * 1024 * 1024)
    )
    max_body: int = field(default_factory=lambda: _env_int("NODE_R_MAX_BODY", 128 * 1024))
    allowed_cidrs: tuple[str, ...] = field(
        default_factory=lambda: _parse_cidrs(os.environ.get("NODE_R_ALLOWED_CIDRS"))
    )
    enforce_cidr: bool = field(
        default_factory=lambda: _env_bool("NODE_R_ENFORCE_CIDR", True)
    )
    ssl_cert: str | None = field(
        default_factory=lambda: os.environ.get("NODE_R_SSL_CERT") or None
    )
    ssl_key: str | None = field(
        default_factory=lambda: os.environ.get("NODE_R_SSL_KEY") or None
    )
    fetch_limit_max: int = 200
    allow_testclient: bool = field(
        default_factory=lambda: _env_bool("NODE_R_ALLOW_TESTCLIENT", False)
    )


@dataclass
class AuthContext:
    device_id: str
    role: str


def canonical_message(
    method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    """組成 canonical string 的 UTF-8 位元組，供簽署與驗簽共用。"""
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")


def sign_request(
    signing_key: nacl.signing.SigningKey,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """回傳 hex 編碼的 Ed25519 簽章（不含訊息本身）。"""
    signed = signing_key.sign(canonical_message(method, path, timestamp, nonce, body))
    return signed.signature.hex()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextmanager
def connect(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(settings: Settings) -> None:
    with connect(settings.db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_registry (
                device_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                verify_pub_key TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS uplink_queue (
                relay_id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_record_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                encrypted_envelope BLOB NOT NULL,
                relay_received_at TEXT NOT NULL,
                UNIQUE (device_id, client_record_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS used_nonces (
                device_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ts INTEGER NOT NULL,
                PRIMARY KEY (device_id, nonce)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ack_log (
                ack_id INTEGER PRIMARY KEY AUTOINCREMENT,
                boss_device_id TEXT NOT NULL,
                relay_ids TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS acked_records (
                device_id TEXT NOT NULL,
                client_record_id TEXT NOT NULL,
                relay_id INTEGER,
                acked_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, client_record_id)
            )
            """
        )


def register_device(
    settings: Settings, device_id: str, role: str, pubkey_hex: str
) -> None:
    if not device_id or len(device_id) > MAX_DEVICE_ID_LEN:
        raise ValueError("invalid device_id")
    role = role.upper()
    if role not in ROLES:
        raise ValueError("role must be THERAPIST or BOSS")
    key_hex = pubkey_hex.strip().lower()
    if len(key_hex) != ED25519_PUB_HEX_LEN:
        raise ValueError("verify_pub_key must be 32-byte Ed25519 public key hex")
    try:
        nacl.signing.VerifyKey(key_hex, encoder=nacl.encoding.HexEncoder)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid Ed25519 public key") from exc

    init_db(settings)
    with connect(settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO device_registry (device_id, role, verify_pub_key, status, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(device_id) DO UPDATE SET
                role = excluded.role,
                verify_pub_key = excluded.verify_pub_key,
                status = 'ACTIVE',
                updated_at = CURRENT_TIMESTAMP
            """,
            (device_id, role, key_hex, ACTIVE),
        )
    log.info("registered device_id=%s role=%s", device_id, role)


def revoke_device(settings: Settings, device_id: str) -> bool:
    if not device_id:
        raise ValueError("invalid device_id")
    init_db(settings)
    with connect(settings.db_path) as conn:
        cur = conn.execute(
            """
            UPDATE device_registry
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
            """,
            (REVOKED, device_id),
        )
        if cur.rowcount == 0:
            return False
    log.info("revoked device_id=%s", device_id)
    return True


def _client_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host


def _ip_allowed(host: str | None, settings: Settings) -> bool:
    if not settings.enforce_cidr:
        return True
    if host is None:
        return False
    if settings.allow_testclient and host == "testclient":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in settings.allowed_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            log.warning("ignoring invalid CIDR %s", cidr)
            continue
        if ip in network:
            return True
    return False


def _disk_free(db_path: str) -> int:
    directory = os.path.dirname(os.path.abspath(db_path)) or "."
    return shutil.disk_usage(directory).free


def _purge_old_nonces(conn: sqlite3.Connection, now: int, clock_skew: int) -> None:
    cutoff = now - clock_skew
    conn.execute("DELETE FROM used_nonces WHERE ts < ?", (cutoff,))


class UplinkRecord(BaseModel):
    client_record_id: str = Field(..., min_length=1, max_length=MAX_CLIENT_RECORD_ID_LEN)
    encrypted_envelope: str


class AckRequest(BaseModel):
    relay_ids: list[int] = Field(default_factory=list, max_length=200)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        init_db(settings)
        yield

    app = FastAPI(
        title="Node R - Blind Relay Service",
        version="2.1",
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.middleware("http")
    async def gate_middleware(request: Request, call_next):
        current: Settings = request.app.state.settings
        if not _ip_allowed(_client_ip(request), current):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "client address not allowed"},
            )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "invalid content-length"},
                )
            if length > current.max_body:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={"detail": "request body too large"},
                )
        return await call_next(request)

    async def authenticate(
        request: Request,
        x_device_id: str = Header(..., alias="X-Device-Id"),
        x_timestamp: str = Header(..., alias="X-Timestamp"),
        x_nonce: str = Header(..., alias="X-Nonce"),
        x_signature: str = Header(..., alias="X-Signature"),
    ) -> AuthContext:
        current: Settings = request.app.state.settings
        body = await request.body()
        if len(body) > current.max_body:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="request body too large",
            )

        if not x_device_id or len(x_device_id) > MAX_DEVICE_ID_LEN:
            raise HTTPException(status_code=400, detail="invalid device id")
        if not x_nonce or len(x_nonce) > MAX_NONCE_LEN:
            raise HTTPException(status_code=400, detail="invalid nonce")

        try:
            ts = int(x_timestamp)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid timestamp") from exc

        now = int(time.time())
        if abs(now - ts) > current.clock_skew:
            raise HTTPException(status_code=401, detail="timestamp out of sync")

        with connect(current.db_path) as conn:
            _purge_old_nonces(conn, now, current.clock_skew)
            row = conn.execute(
                """
                SELECT verify_pub_key, status, role
                FROM device_registry
                WHERE device_id = ?
                """,
                (x_device_id,),
            ).fetchone()

        if row is None:
            raise HTTPException(status_code=401, detail="device not registered")
        if row["status"] != ACTIVE:
            raise HTTPException(status_code=403, detail="device revoked")

        try:
            verify_key = nacl.signing.VerifyKey(
                row["verify_pub_key"], encoder=nacl.encoding.HexEncoder
            )
            message = canonical_message(
                request.method, request.url.path, x_timestamp, x_nonce, body
            )
            signature = bytes.fromhex(x_signature)
            verify_key.verify(message, signature)
        except (nacl.exceptions.BadSignatureError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=401, detail="invalid signature") from exc

        try:
            with connect(current.db_path) as conn:
                conn.execute(
                    "INSERT INTO used_nonces (device_id, nonce, ts) VALUES (?, ?, ?)",
                    (x_device_id, x_nonce, ts),
                )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=401, detail="nonce replayed") from exc

        return AuthContext(device_id=x_device_id, role=row["role"])

    def require_role(*roles: str):
        async def _inner(auth: AuthContext = Depends(authenticate)) -> AuthContext:
            if auth.role not in roles:
                raise HTTPException(status_code=403, detail="forbidden role")
            return auth

        return _inner

    @app.get("/api/v2/health")
    def health_check() -> dict[str, Any]:
        return {"status": "ok", "server_unix_ts": int(time.time())}

    @app.post("/api/v2/uplink/records")
    def uplink_records(
        record: UplinkRecord,
        request: Request,
        auth: AuthContext = Depends(require_role("THERAPIST")),
    ) -> dict[str, Any]:
        current: Settings = request.app.state.settings
        try:
            envelope = base64.b64decode(record.encrypted_envelope, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail="invalid base64") from exc
        if len(envelope) > current.max_envelope:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="envelope too large",
            )

        if current.min_free_bytes > 0 and _disk_free(current.db_path) < current.min_free_bytes:
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail="insufficient storage",
            )

        received_at = str(int(time.time()))
        with connect(current.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT relay_id, encrypted_envelope
                FROM uplink_queue
                WHERE device_id = ? AND client_record_id = ?
                """,
                (auth.device_id, record.client_record_id),
            ).fetchone()
            if existing is not None:
                if bytes(existing["encrypted_envelope"]) == envelope:
                    return {"status": "success", "relay_id": existing["relay_id"]}
                raise HTTPException(status_code=409, detail="record conflict")

            pending = conn.execute(
                "SELECT COUNT(*) AS n FROM uplink_queue WHERE device_id = ?",
                (auth.device_id,),
            ).fetchone()["n"]
            if pending >= current.pending_cap:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="pending cap exceeded",
                )

            cur = conn.execute(
                """
                INSERT INTO uplink_queue (
                    client_record_id, device_id, encrypted_envelope, relay_received_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (record.client_record_id, auth.device_id, envelope, received_at),
            )
            relay_id = cur.lastrowid

        return {"status": "success", "relay_id": relay_id}

    @app.get("/api/v2/uplink/fetch")
    def fetch_uplink(
        request: Request,
        limit: int = Query(default=200, ge=1),
        auth: AuthContext = Depends(require_role("BOSS")),
    ) -> dict[str, Any]:
        current: Settings = request.app.state.settings
        fetch_limit = min(limit, current.fetch_limit_max)
        with connect(current.db_path) as conn:
            rows = conn.execute(
                """
                SELECT relay_id, client_record_id, device_id,
                       encrypted_envelope, relay_received_at
                FROM uplink_queue
                ORDER BY relay_id ASC
                LIMIT ?
                """,
                (fetch_limit,),
            ).fetchall()

        items = []
        for row in rows:
            items.append(
                {
                    "relay_id": row["relay_id"],
                    "client_record_id": row["client_record_id"],
                    "device_id": row["device_id"],
                    "encrypted_envelope": base64.b64encode(
                        bytes(row["encrypted_envelope"])
                    ).decode("ascii"),
                    "relay_received_at": row["relay_received_at"],
                }
            )
        return {"status": "success", "items": items}

    def _ack(
        req: AckRequest, request: Request, auth: AuthContext
    ) -> dict[str, Any]:
        current: Settings = request.app.state.settings
        now = int(time.time())
        # 原始本文已由 async 包裝函式放入 request.state，供收據雜湊使用。
        raw_body: bytes = request.state.raw_body
        body_hash = sha256_hex(raw_body)
        signature = request.headers.get("x-signature", "")

        relay_ids = list(dict.fromkeys(req.relay_ids))
        purged: list[int] = []
        with connect(current.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO ack_log (
                    boss_device_id, relay_ids, body_sha256, signature, ts
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (auth.device_id, json.dumps(relay_ids), body_hash, signature, now),
            )
            if relay_ids:
                placeholders = ",".join("?" for _ in relay_ids)
                rows = conn.execute(
                    f"""
                    SELECT relay_id, device_id, client_record_id
                    FROM uplink_queue
                    WHERE relay_id IN ({placeholders})
                    """,
                    relay_ids,
                ).fetchall()
                for row in rows:
                    conn.execute(
                        """
                        INSERT INTO acked_records (
                            device_id, client_record_id, relay_id, acked_at
                        )
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(device_id, client_record_id) DO UPDATE SET
                            relay_id = excluded.relay_id,
                            acked_at = excluded.acked_at
                        """,
                        (
                            row["device_id"],
                            row["client_record_id"],
                            row["relay_id"],
                            now,
                        ),
                    )
                    purged.append(int(row["relay_id"]))
                if purged:
                    purged_ph = ",".join("?" for _ in purged)
                    conn.execute(
                        f"DELETE FROM uplink_queue WHERE relay_id IN ({purged_ph})",
                        purged,
                    )

        return {
            "status": "success",
            "purged_ids": purged,
            "purged_count": len(purged),
        }

    async def _prepare_ack(
        request: Request,
        req: AckRequest,
        auth: AuthContext = Depends(require_role("BOSS")),
    ) -> dict[str, Any]:
        request.state.raw_body = await request.body()
        return _ack(req, request, auth)

    app.add_api_route(
        "/api/v2/uplink/ack",
        _prepare_ack,
        methods=["POST"],
        name="ack_uplink",
    )
    app.add_api_route(
        "/api/v2/uplink/purge",
        _prepare_ack,
        methods=["DELETE"],
        name="purge_uplink",
    )

    @app.get("/api/v2/uplink/status")
    def record_status(
        request: Request,
        client_record_id: str = Query(..., min_length=1, max_length=MAX_CLIENT_RECORD_ID_LEN),
        auth: AuthContext = Depends(require_role("THERAPIST")),
    ) -> dict[str, Any]:
        current: Settings = request.app.state.settings
        with connect(current.db_path) as conn:
            queued = conn.execute(
                """
                SELECT 1 FROM uplink_queue
                WHERE device_id = ? AND client_record_id = ?
                """,
                (auth.device_id, client_record_id),
            ).fetchone()
            if queued is not None:
                state = "queued"
            else:
                acked = conn.execute(
                    """
                    SELECT 1 FROM acked_records
                    WHERE device_id = ? AND client_record_id = ?
                    """,
                    (auth.device_id, client_record_id),
                ).fetchone()
                state = "acked" if acked is not None else "unknown"
        return {
            "status": "success",
            "client_record_id": client_record_id,
            "state": state,
        }

    return app


app = create_app()


def _settings_from_cli(args: argparse.Namespace) -> Settings:
    settings = Settings()
    if getattr(args, "db", None):
        settings.db_path = args.db
    if getattr(args, "host", None):
        settings.host = args.host
    if getattr(args, "port", None):
        settings.port = args.port
    if getattr(args, "ssl_cert", None):
        settings.ssl_cert = args.ssl_cert
    if getattr(args, "ssl_key", None):
        settings.ssl_key = args.ssl_key
    return settings


def _cmd_register(args: argparse.Namespace) -> int:
    settings = _settings_from_cli(args)
    try:
        register_device(settings, args.device_id, args.role, args.pubkey)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"registered {args.device_id} as {args.role.upper()}")
    return 0


def _cmd_revoke(args: argparse.Namespace) -> int:
    settings = _settings_from_cli(args)
    if not revoke_device(settings, args.device_id):
        print(f"error: device {args.device_id} not found", file=sys.stderr)
        return 1
    print(f"revoked {args.device_id}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = _settings_from_cli(args)
    init_db(settings)
    serve_app = create_app(settings)
    import uvicorn

    kwargs: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
        "log_level": "info",
    }
    if settings.ssl_cert and settings.ssl_key:
        kwargs["ssl_certfile"] = settings.ssl_cert
        kwargs["ssl_keyfile"] = settings.ssl_key
    elif settings.ssl_cert or settings.ssl_key:
        print("error: both --ssl-cert and --ssl-key are required", file=sys.stderr)
        return 2
    uvicorn.run(serve_app, **kwargs)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Node R blind relay")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", help="Register or update a device public key")
    reg.add_argument("--device-id", required=True)
    reg.add_argument("--role", required=True, choices=["THERAPIST", "BOSS", "therapist", "boss"])
    reg.add_argument("--pubkey", required=True, help="Ed25519 public key hex")
    reg.add_argument("--db", default=None, help="SQLite path (default NODE_R_DB or node_r.db)")
    reg.set_defaults(func=_cmd_register)

    rev = sub.add_parser("revoke", help="Revoke a registered device")
    rev.add_argument("--device-id", required=True)
    rev.add_argument("--db", default=None)
    rev.set_defaults(func=_cmd_revoke)

    srv = sub.add_parser("serve", help="Run the uvicorn server")
    srv.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    srv.add_argument("--port", type=int, default=None)
    srv.add_argument("--db", default=None)
    srv.add_argument("--ssl-cert", default=None)
    srv.add_argument("--ssl-key", default=None)
    srv.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
