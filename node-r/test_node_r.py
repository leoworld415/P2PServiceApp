from __future__ import annotations

import base64
import json
import time
import uuid
from pathlib import Path

import nacl.signing
import pytest
from fastapi.testclient import TestClient

from node_r import Settings, create_app, register_device, revoke_device, sign_request

ENVELOPE = base64.b64encode(b"ciphertext-one").decode("ascii")
ENVELOPE_B = base64.b64encode(b"ciphertext-two").decode("ascii")


@pytest.fixture
def ctx(tmp_path: Path):
    settings = Settings(
        db_path=str(tmp_path / "node_r.db"),
        enforce_cidr=False,
        pending_cap=3,
        max_envelope=64 * 1024,
        max_body=128 * 1024,
        min_free_bytes=0,
        clock_skew=300,
        allow_testclient=True,
    )
    app = create_app(settings)
    therapist_key = nacl.signing.SigningKey.generate()
    therapist2_key = nacl.signing.SigningKey.generate()
    boss_key = nacl.signing.SigningKey.generate()
    register_device(settings, "therapist-1", "THERAPIST", therapist_key.verify_key.encode().hex())
    register_device(settings, "therapist-2", "THERAPIST", therapist2_key.verify_key.encode().hex())
    register_device(settings, "boss-1", "BOSS", boss_key.verify_key.encode().hex())
    with TestClient(app) as client:
        yield {
            "client": client,
            "settings": settings,
            "therapist_key": therapist_key,
            "therapist2_key": therapist2_key,
            "boss_key": boss_key,
        }


def _headers(
    key: nacl.signing.SigningKey,
    device_id: str,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: str | None = None,
    nonce: str | None = None,
    signature: str | None = None,
) -> dict[str, str]:
    ts = timestamp if timestamp is not None else str(int(time.time()))
    used_nonce = nonce if nonce is not None else uuid.uuid4().hex
    sig = (
        signature
        if signature is not None
        else sign_request(key, method, path, ts, used_nonce, body)
    )
    return {
        "X-Device-Id": device_id,
        "X-Timestamp": ts,
        "X-Nonce": used_nonce,
        "X-Signature": sig,
    }


def _uplink(
    client: TestClient,
    key: nacl.signing.SigningKey,
    device_id: str,
    record_id: str,
    envelope: str = ENVELOPE,
    **header_kw,
):
    body = json.dumps(
        {"client_record_id": record_id, "encrypted_envelope": envelope},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _headers(key, device_id, "POST", "/api/v2/uplink/records", body, **header_kw)
    headers["Content-Type"] = "application/json"
    return client.post("/api/v2/uplink/records", content=body, headers=headers)


def _status(client: TestClient, key, device_id: str, record_id: str, **header_kw):
    headers = _headers(key, device_id, "GET", "/api/v2/uplink/status", b"", **header_kw)
    return client.get(
        f"/api/v2/uplink/status?client_record_id={record_id}", headers=headers
    )


def _fetch(client: TestClient, key, device_id: str = "boss-1", limit: int | None = None, **header_kw):
    path = "/api/v2/uplink/fetch"
    url = path if limit is None else f"{path}?limit={limit}"
    headers = _headers(key, device_id, "GET", path, b"", **header_kw)
    return client.get(url, headers=headers)


def _ack(client: TestClient, key, device_id: str, relay_ids: list[int], **header_kw):
    body = json.dumps({"relay_ids": relay_ids}, separators=(",", ":")).encode("utf-8")
    headers = _headers(key, device_id, "POST", "/api/v2/uplink/ack", body, **header_kw)
    headers["Content-Type"] = "application/json"
    return client.post("/api/v2/uplink/ack", content=body, headers=headers)


def test_health(ctx):
    resp = ctx["client"].get("/api/v2/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert abs(data["server_unix_ts"] - int(time.time())) <= 2


def test_unregistered_401(ctx):
    key = nacl.signing.SigningKey.generate()
    resp = _uplink(ctx["client"], key, "unknown-device", "rec-1")
    assert resp.status_code == 401
    assert "not registered" in resp.json()["detail"]


def test_revoked_403(ctx):
    assert revoke_device(ctx["settings"], "therapist-1") is True
    resp = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-1")
    assert resp.status_code == 403
    assert "revoked" in resp.json()["detail"]


def test_bad_signature_401(ctx):
    body = json.dumps(
        {"client_record_id": "rec-1", "encrypted_envelope": ENVELOPE},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _headers(
        ctx["therapist_key"],
        "therapist-1",
        "POST",
        "/api/v2/uplink/records",
        body,
        signature="00" * 64,
    )
    resp = ctx["client"].post("/api/v2/uplink/records", content=body, headers=headers)
    assert resp.status_code == 401
    assert "invalid signature" in resp.json()["detail"]


def test_tampered_body_401(ctx):
    body = json.dumps(
        {"client_record_id": "rec-1", "encrypted_envelope": ENVELOPE},
        separators=(",", ":"),
    ).encode("utf-8")
    tampered = json.dumps(
        {"client_record_id": "rec-1", "encrypted_envelope": ENVELOPE_B},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _headers(
        ctx["therapist_key"], "therapist-1", "POST", "/api/v2/uplink/records", body
    )
    resp = ctx["client"].post("/api/v2/uplink/records", content=tampered, headers=headers)
    assert resp.status_code == 401
    assert "invalid signature" in resp.json()["detail"]


def test_replayed_nonce_401(ctx):
    nonce = "replay-nonce-1"
    resp = _uplink(
        ctx["client"], ctx["therapist_key"], "therapist-1", "rec-replay", nonce=nonce
    )
    assert resp.status_code == 200
    resp2 = _uplink(
        ctx["client"], ctx["therapist_key"], "therapist-1", "rec-replay-2", nonce=nonce
    )
    assert resp2.status_code == 401
    assert "nonce" in resp2.json()["detail"]


def test_stale_timestamp_401(ctx):
    stale = str(int(time.time()) - 400)
    resp = _uplink(
        ctx["client"], ctx["therapist_key"], "therapist-1", "rec-stale", timestamp=stale
    )
    assert resp.status_code == 401
    assert "timestamp" in resp.json()["detail"]


def test_therapist_cannot_fetch_or_ack(ctx):
    resp = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-role")
    assert resp.status_code == 200
    relay_id = resp.json()["relay_id"]

    fetch = _fetch(ctx["client"], ctx["therapist_key"], device_id="therapist-1")
    assert fetch.status_code == 403
    assert "role" in fetch.json()["detail"]

    ack = _ack(ctx["client"], ctx["therapist_key"], "therapist-1", [relay_id])
    assert ack.status_code == 403
    assert "role" in ack.json()["detail"]


def test_boss_cannot_uplink(ctx):
    resp = _uplink(ctx["client"], ctx["boss_key"], "boss-1", "rec-boss")
    assert resp.status_code == 403
    assert "role" in resp.json()["detail"]


def test_idempotent_reupload_same_envelope(ctx):
    first = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-idem")
    assert first.status_code == 200
    relay_id = first.json()["relay_id"]
    second = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-idem")
    assert second.status_code == 200
    assert second.json()["relay_id"] == relay_id


def test_same_id_different_envelope_409(ctx):
    first = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-conflict")
    assert first.status_code == 200
    second = _uplink(
        ctx["client"],
        ctx["therapist_key"],
        "therapist-1",
        "rec-conflict",
        envelope=ENVELOPE_B,
    )
    assert second.status_code == 409


def test_same_client_record_id_two_devices(ctx):
    a = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "shared-rec")
    b = _uplink(ctx["client"], ctx["therapist2_key"], "therapist-2", "shared-rec")
    assert a.status_code == 200
    assert b.status_code == 200
    assert a.json()["relay_id"] != b.json()["relay_id"]


def test_oversize_envelope_413(ctx):
    huge = base64.b64encode(b"x" * (64 * 1024 + 1)).decode("ascii")
    resp = _uplink(
        ctx["client"], ctx["therapist_key"], "therapist-1", "rec-huge", envelope=huge
    )
    assert resp.status_code == 413


def test_invalid_base64_422(ctx):
    body = json.dumps(
        {"client_record_id": "rec-b64", "encrypted_envelope": "@@@not-base64@@@"},
        separators=(",", ":"),
    ).encode("utf-8")
    headers = _headers(
        ctx["therapist_key"], "therapist-1", "POST", "/api/v2/uplink/records", body
    )
    headers["Content-Type"] = "application/json"
    resp = ctx["client"].post("/api/v2/uplink/records", content=body, headers=headers)
    assert resp.status_code in {400, 422}


def test_per_device_cap(ctx):
    for i in range(3):
        resp = _uplink(
            ctx["client"], ctx["therapist_key"], "therapist-1", f"rec-cap-{i}"
        )
        assert resp.status_code == 200, resp.text
    resp = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-cap-overflow")
    assert resp.status_code == 429
    # 另一部裝置不受影響
    other = _uplink(ctx["client"], ctx["therapist2_key"], "therapist-2", "rec-cap-other")
    assert other.status_code == 200


def test_ack_deletes_only_listed_and_writes_ack_log(ctx):
    ids = []
    for i in range(3):
        resp = _uplink(
            ctx["client"], ctx["therapist_key"], "therapist-1", f"rec-ack-{i}"
        )
        assert resp.status_code == 200
        ids.append(resp.json()["relay_id"])

    ack = _ack(ctx["client"], ctx["boss_key"], "boss-1", [ids[0], ids[2]])
    assert ack.status_code == 200
    body = ack.json()
    assert sorted(body["purged_ids"]) == sorted([ids[0], ids[2]])
    assert body["purged_count"] == 2

    fetched = _fetch(ctx["client"], ctx["boss_key"])
    assert fetched.status_code == 200
    remaining = [item["relay_id"] for item in fetched.json()["items"]]
    assert remaining == [ids[1]]
    assert fetched.json()["items"][0]["device_id"] == "therapist-1"

    import sqlite3

    conn = sqlite3.connect(ctx["settings"].db_path)
    try:
        row = conn.execute(
            "SELECT boss_device_id, relay_ids, body_sha256, signature, ts FROM ack_log"
        ).fetchone()
        assert row is not None
        assert row[0] == "boss-1"
        assert json.loads(row[1]) == [ids[0], ids[2]]
        assert row[2] and row[3] and row[4]
    finally:
        conn.close()


def test_status_queued_then_acked(ctx):
    record_id = "rec-status"
    up = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", record_id)
    assert up.status_code == 200
    relay_id = up.json()["relay_id"]

    queued = _status(ctx["client"], ctx["therapist_key"], "therapist-1", record_id)
    assert queued.status_code == 200
    assert queued.json()["state"] == "queued"

    # 另一位技師看不到別人的紀錄
    other = _status(ctx["client"], ctx["therapist2_key"], "therapist-2", record_id)
    assert other.status_code == 200
    assert other.json()["state"] == "unknown"

    ack = _ack(ctx["client"], ctx["boss_key"], "boss-1", [relay_id])
    assert ack.status_code == 200

    acked = _status(ctx["client"], ctx["therapist_key"], "therapist-1", record_id)
    assert acked.status_code == 200
    assert acked.json()["state"] == "acked"

    missing = _status(ctx["client"], ctx["therapist_key"], "therapist-1", "no-such-rec")
    assert missing.status_code == 200
    assert missing.json()["state"] == "unknown"


def test_fetch_oldest_first_and_limit(ctx):
    for i in range(3):
        resp = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", f"rec-order-{i}")
        assert resp.status_code == 200

    limited = _fetch(ctx["client"], ctx["boss_key"], limit=2)
    assert limited.status_code == 200
    items = limited.json()["items"]
    assert len(items) == 2
    assert items[0]["relay_id"] < items[1]["relay_id"]
    assert items[0]["client_record_id"] == "rec-order-0"


def test_purge_alias_requires_signed_ack(ctx):
    up = _uplink(ctx["client"], ctx["therapist_key"], "therapist-1", "rec-purge-alias")
    relay_id = up.json()["relay_id"]
    body = json.dumps({"relay_ids": [relay_id]}, separators=(",", ":")).encode("utf-8")
    headers = _headers(ctx["boss_key"], "boss-1", "DELETE", "/api/v2/uplink/purge", body)
    headers["Content-Type"] = "application/json"
    resp = ctx["client"].request(
        "DELETE", "/api/v2/uplink/purge", content=body, headers=headers
    )
    assert resp.status_code == 200
    assert relay_id in resp.json()["purged_ids"]
