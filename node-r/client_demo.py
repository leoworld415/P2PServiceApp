#!/usr/bin/env python3
"""對 Node R 做一次端到端示範：產生金鑰、登記裝置、上傳、提取、確認、查狀態。

不會把私鑰寫進工作目錄（除非指定 --key-dir，該目錄應加入 .gitignore）。
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import nacl.signing

from node_r import Settings, register_device, sign_request


def _request(
    base_url: str,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    url = base_url.rstrip("/") + path
    req = Request(url, data=body if body else None, method=method)
    req.add_header("Accept", "application/json")
    if body:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            return resp.status, payload
    except HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            payload = {"detail": raw.decode("utf-8", errors="replace")}
        return exc.code, payload


def signed_headers(
    signing_key: nacl.signing.SigningKey,
    device_id: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts = timestamp if timestamp is not None else str(int(time.time()))
    used_nonce = nonce if nonce is not None else uuid.uuid4().hex
    signature = sign_request(signing_key, method, path, ts, used_nonce, body)
    return {
        "X-Device-Id": device_id,
        "X-Timestamp": ts,
        "X-Nonce": used_nonce,
        "X-Signature": signature,
    }


def _fail(message: str) -> None:
    print(f"DEMO FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def _expect(ok: bool, message: str) -> None:
    if not ok:
        _fail(message)


def run_demo(base_url: str, db_path: str, key_dir: Path | None = None) -> int:
    settings = Settings(db_path=db_path)
    therapist_key = nacl.signing.SigningKey.generate()
    boss_key = nacl.signing.SigningKey.generate()
    therapist_id = "demo-therapist-1"
    boss_id = "demo-boss-1"

    if key_dir is not None:
        key_dir.mkdir(parents=True, exist_ok=True)
        (key_dir / "therapist.pub").write_text(therapist_key.verify_key.encode().hex())
        (key_dir / "boss.pub").write_text(boss_key.verify_key.encode().hex())
        # 私鑰僅在明確指定 key-dir 時寫出，切勿提交到版本庫。
        (key_dir / "therapist.sk").write_text(therapist_key.encode().hex())
        (key_dir / "boss.sk").write_text(boss_key.encode().hex())

    register_device(
        settings, therapist_id, "THERAPIST", therapist_key.verify_key.encode().hex()
    )
    register_device(settings, boss_id, "BOSS", boss_key.verify_key.encode().hex())
    print(f"registered {therapist_id} and {boss_id}")

    status, health = _request(base_url, "GET", "/api/v2/health")
    _expect(status == 200, f"health failed: {status} {health}")
    server_ts = int(health["server_unix_ts"])
    offset = server_ts - int(time.time())
    print(f"health ok, clock offset={offset}s")

    def now_ts() -> str:
        return str(int(time.time()) + offset)

    envelope = base64.b64encode(b"ciphertext-demo-envelope").decode("ascii")
    record_id = f"rec-{uuid.uuid4().hex[:12]}"
    uplink_body = json.dumps(
        {"client_record_id": record_id, "encrypted_envelope": envelope},
        separators=(",", ":"),
    ).encode("utf-8")

    path = "/api/v2/uplink/records"
    headers = signed_headers(
        therapist_key, therapist_id, "POST", path, uplink_body, timestamp=now_ts()
    )
    status, payload = _request(base_url, "POST", path, body=uplink_body, headers=headers)
    _expect(status == 200, f"uplink failed: {status} {payload}")
    relay_id = payload["relay_id"]
    print(f"uploaded record {record_id} -> relay_id={relay_id}")

    status_path = f"/api/v2/uplink/status?client_record_id={record_id}"
    headers = signed_headers(
        therapist_key, therapist_id, "GET", "/api/v2/uplink/status", b"", timestamp=now_ts()
    )
    status, payload = _request(base_url, "GET", status_path, headers=headers)
    _expect(status == 200 and payload.get("state") == "queued", f"status queued failed: {status} {payload}")
    print("status=queued")

    fetch_path = "/api/v2/uplink/fetch?limit=200"
    headers = signed_headers(
        boss_key, boss_id, "GET", "/api/v2/uplink/fetch", b"", timestamp=now_ts()
    )
    status, payload = _request(base_url, "GET", fetch_path, headers=headers)
    _expect(status == 200, f"fetch failed: {status} {payload}")
    items = payload.get("items") or []
    _expect(any(item["relay_id"] == relay_id for item in items), f"fetched items missing relay_id: {payload}")
    print(f"fetched {len(items)} item(s)")

    # 示範：老闆端應先寫入本地總帳，才發送 ack。
    ack_body = json.dumps({"relay_ids": [relay_id]}, separators=(",", ":")).encode("utf-8")
    headers = signed_headers(
        boss_key, boss_id, "POST", "/api/v2/uplink/ack", ack_body, timestamp=now_ts()
    )
    status, payload = _request(
        base_url, "POST", "/api/v2/uplink/ack", body=ack_body, headers=headers
    )
    _expect(
        status == 200 and relay_id in payload.get("purged_ids", []),
        f"ack failed: {status} {payload}",
    )
    print(f"acked purged_ids={payload['purged_ids']}")

    headers = signed_headers(
        therapist_key, therapist_id, "GET", "/api/v2/uplink/status", b"", timestamp=now_ts()
    )
    status, payload = _request(base_url, "GET", status_path, headers=headers)
    _expect(status == 200 and payload.get("state") == "acked", f"status acked failed: {status} {payload}")
    print("status=acked")
    print("DEMO OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Node R end-to-end demo client")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--db", default=None, help="SQLite path used by the running server")
    parser.add_argument(
        "--key-dir",
        default=None,
        help="Optional directory to write demo keys (keep out of git)",
    )
    args = parser.parse_args(argv)
    db_path = args.db or "node_r.db"
    key_dir = Path(args.key_dir) if args.key_dir else None
    try:
        return run_demo(args.base_url, db_path, key_dir)
    except URLError as exc:
        _fail(f"cannot reach {args.base_url}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
