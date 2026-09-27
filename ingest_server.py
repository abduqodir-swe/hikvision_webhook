"""hikvision-ingest: the public endpoint the Hikvision terminal pushes to.

    Hikvision .141 ──HTTPS push (httpHosts)──► POST /hikvision/<device token>
        └─ hik_parser.read_scan (the parser proven on the real terminal)
        └─ outbox (SQLite): written BEFORE the terminal gets its 200
        └─ forwarder thread ──► intranet POST /api/integrations/hikvision/scans
                                (X-Integration-Key = HIKVISION_INTEGRATION_KEY)
        └─ Telegram notice (pilot only, fresh passes only, neutral wording)

No attendance business logic lives here (owner, 2026-09-26): no working hours,
no "in"/"out", no late/early. The intranet's Tabel decides what a scan means.

Configuration is environment only (see .env.example); nothing secret is in code.
Run: gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 "ingest_server:create_app()"
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from flask import Flask, Response, jsonify, request

import hik_parser

log = logging.getLogger("hikvision-ingest")

SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,        -- device sn + terminal serialNo + second (or person + second)
    device_label TEXT NOT NULL,
    payload TEXT NOT NULL,                 -- one scan in the intranet's shape
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL DEFAULT 0,
    sent_at TEXT,
    failed_at TEXT,                        -- the intranet refused the batch as invalid (400): kept, not retried
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox (sent_at, failed_at, next_attempt_at);
CREATE TABLE IF NOT EXISTS raw_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    device_label TEXT NOT NULL,
    accepted INTEGER NOT NULL,
    reason TEXT NOT NULL,
    event TEXT NOT NULL                    -- the terminal's JSON, never the picture
);
CREATE INDEX IF NOT EXISTS idx_raw_received ON raw_events (received_at);
CREATE TABLE IF NOT EXISTS device_seen (
    device_label TEXT PRIMARY KEY,
    last_request_at TEXT,
    last_scan_at TEXT
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Device:
    token: str                     # the secret in the push URL path
    label: str                     # "Room 1 (DS-K1T331W)"
    sn: str                        # the terminal's serial number (ISAPI deviceInfo) — the intranet's `sn`
    success_event_codes: frozenset[str] = hik_parser.DEFAULT_SUCCESS_EVENT_CODES
    digest_user: str | None = None  # when set, the terminal must authenticate (httpAuthenticationMethod=MD5digest)
    digest_pass: str | None = None
    expected_ip: str | None = None  # the terminal's LAN address, compared with the payload's ipAddress (warning only)


@dataclass
class Config:
    db_path: Path
    devices: list[Device]
    erp_url: str | None
    erp_key: str | None
    telegram_token: str | None = None
    telegram_chat_ids: list[str] = field(default_factory=list)
    telegram_max_age_s: int = 120
    max_future_skew_s: int = 600
    raw_retention_days: int = 14
    sent_retention_days: int = 60
    batch_size: int = 100
    forward_interval_s: float = 5.0
    start_forwarder: bool = True
    digest_realm: str = "phoenix-hikvision"
    nonce_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @classmethod
    def from_env(cls) -> "Config":
        raw = os.environ.get("HIK_DEVICES")
        path = os.environ.get("HIK_DEVICES_FILE")
        if not raw and path:
            raw = Path(path).read_text(encoding="utf-8")
        devices = []
        for d in json.loads(raw or "[]"):
            token = str(d.get("token", ""))
            if len(token) < 24:
                raise ValueError(f"device {d.get('label')!r}: token must be at least 24 characters")
            devices.append(Device(
                token=token, label=str(d["label"]), sn=str(d["sn"]),
                success_event_codes=frozenset(str(c) for c in d.get("success_event_codes", ["153"])),
                digest_user=d.get("digest_user") or None, digest_pass=d.get("digest_pass") or None,
                expected_ip=d.get("expected_ip") or None,
            ))
        chat_ids = [c.strip() for c in os.environ.get("TELEGRAM_CHAT_IDS", "").split(",") if c.strip()]
        secret = os.environ.get("HIK_NONCE_SECRET")
        return cls(
            db_path=Path(os.environ.get("HIK_INGEST_DB", "/data/hikvision-ingest.db")),
            devices=devices,
            erp_url=(os.environ.get("ERP_URL") or "").rstrip("/") or None,
            erp_key=os.environ.get("ERP_KEY") or None,
            telegram_token=os.environ.get("TELEGRAM_BOT_TOKEN") or None,
            telegram_chat_ids=chat_ids,
            telegram_max_age_s=_env_int("TELEGRAM_MAX_AGE_SECONDS", 120),
            max_future_skew_s=_env_int("MAX_FUTURE_SKEW_SECONDS", 600),
            raw_retention_days=_env_int("RAW_RETENTION_DAYS", 14),
            # ≤ 300: the intranet's JSON body limit is 100 KB and a scan is ~200 bytes.
            batch_size=max(1, min(_env_int("FORWARD_BATCH", 100), 300)),
            forward_interval_s=float(os.environ.get("FORWARD_INTERVAL_SECONDS", "5")),
            start_forwarder=os.environ.get("HIK_START_FORWARDER", "1") != "0",
            nonce_secret=secret.encode() if secret else secrets.token_bytes(32),
        )


class Store:
    """SQLite, one connection per call (WAL): safe across gunicorn threads."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        """One autocommit connection, always closed (sqlite3's own `with` only ends a transaction)."""
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA busy_timeout=10000")
            yield c
        finally:
            c.close()

    def record_raw(self, label: str, accepted: bool, reason: str, event: dict) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO raw_events (received_at, device_label, accepted, reason, event) VALUES (?,?,?,?,?)",
                      (_now_iso(), label, int(accepted), reason, json.dumps(event, ensure_ascii=False)[:20000]))

    def seen(self, label: str, scan: bool) -> None:
        now = _now_iso()
        with self.conn() as c:
            c.execute("INSERT INTO device_seen (device_label, last_request_at, last_scan_at) VALUES (?,?,?) "
                      "ON CONFLICT(device_label) DO UPDATE SET last_request_at=excluded.last_request_at, "
                      "last_scan_at=COALESCE(excluded.last_scan_at, device_seen.last_scan_at)",
                      (label, now, now if scan else None))

    def enqueue(self, event_key: str, label: str, payload: dict, occurred_at: datetime) -> bool:
        """True when new; a re-sent event (same key) is not queued twice."""
        with self.conn() as c:
            cur = c.execute("INSERT OR IGNORE INTO outbox (event_key, device_label, payload, occurred_at, received_at) VALUES (?,?,?,?,?)",
                            (event_key, label, json.dumps(payload, ensure_ascii=False), occurred_at.isoformat(), _now_iso()))
            return cur.rowcount == 1

    def pending(self, limit: int) -> list[sqlite3.Row]:
        with self.conn() as c:
            return c.execute("SELECT * FROM outbox WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= ? "
                             "ORDER BY id LIMIT ?", (time.time(), limit)).fetchall()

    def mark_sent(self, ids: list[int]) -> None:
        with self.conn() as c:
            c.executemany("UPDATE outbox SET sent_at=?, last_error=NULL WHERE id=?", [(_now_iso(), i) for i in ids])

    def mark_retry(self, ids: list[int], error: str) -> None:
        with self.conn() as c:
            for i in ids:
                row = c.execute("SELECT attempts FROM outbox WHERE id=?", (i,)).fetchone()
                attempts = (row["attempts"] if row else 0) + 1
                delay = min(300, 2 ** min(attempts, 8))          # 2 s … 5 min
                c.execute("UPDATE outbox SET attempts=?, next_attempt_at=?, last_error=? WHERE id=?",
                          (attempts, time.time() + delay, error[:500], i))

    def mark_failed(self, ids: list[int], error: str) -> None:
        with self.conn() as c:
            c.executemany("UPDATE outbox SET failed_at=?, last_error=? WHERE id=?", [(_now_iso(), error[:500], i) for i in ids])

    def prune(self, raw_days: int, sent_days: int) -> None:
        # Timestamps are ISO-8601 UTC strings written by _now_iso(), so they compare as text.
        now = datetime.now(timezone.utc)
        raw_cut = (now - timedelta(days=raw_days)).isoformat(timespec="seconds")
        sent_cut = (now - timedelta(days=sent_days)).isoformat(timespec="seconds")
        with self.conn() as c:
            c.execute("DELETE FROM raw_events WHERE received_at < ?", (raw_cut,))
            c.execute("DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?", (sent_cut,))

    def health(self) -> dict:
        with self.conn() as c:
            pend = c.execute("SELECT COUNT(*) n, MIN(received_at) oldest FROM outbox WHERE sent_at IS NULL AND failed_at IS NULL").fetchone()
            failed = c.execute("SELECT COUNT(*) n FROM outbox WHERE failed_at IS NOT NULL").fetchone()
            last_err = c.execute("SELECT last_error FROM outbox WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
            seen = [dict(r) for r in c.execute("SELECT * FROM device_seen ORDER BY device_label")]
            return {"pending": pend["n"], "oldestPendingReceivedAt": pend["oldest"], "failed": failed["n"],
                    "lastError": last_err["last_error"] if last_err else None, "devices": seen}


# ── Digest authentication of the terminal (optional, per device) ─────────────

def _parse_digest(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not header.lower().startswith("digest "):
        return out
    for part in _split_params(header[7:]):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().strip('"')
    return out


def _split_params(s: str) -> list[str]:
    parts, cur, quoted = [], "", False
    for ch in s:
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def make_nonce(secret: bytes, now: float | None = None) -> str:
    ts = str(int(now if now is not None else time.time()))
    return f"{ts}.{hmac.new(secret, ts.encode(), hashlib.sha256).hexdigest()[:32]}"


def nonce_ok(secret: bytes, nonce: str, max_age_s: int = 300) -> bool:
    try:
        ts, mac = nonce.split(".", 1)
        want = hmac.new(secret, ts.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(mac, want) and 0 <= time.time() - int(ts) <= max_age_s
    except (ValueError, TypeError):
        return False


def digest_ok(header: str, method: str, device: Device, realm: str, secret: bytes, path: str | None = None) -> bool:
    p = _parse_digest(header)
    if not p or p.get("username") != device.digest_user or p.get("realm") != realm:
        return False
    # The answer must be for THIS address (the push URL), not one captured elsewhere.
    if path is not None and p.get("uri", "").split("?", 1)[0] != path:
        return False
    if not nonce_ok(secret, p.get("nonce", "")):
        return False
    ha1 = _md5(f"{device.digest_user}:{realm}:{device.digest_pass}")
    ha2 = _md5(f"{method}:{p.get('uri', '')}")
    if p.get("qop") == "auth":
        want = _md5(f"{ha1}:{p['nonce']}:{p.get('nc', '')}:{p.get('cnonce', '')}:auth:{ha2}")
    else:
        want = _md5(f"{ha1}:{p['nonce']}:{ha2}")
    return hmac.compare_digest(want, p.get("response", ""))


# ── Telegram (pilot) ─────────────────────────────────────────────────────────

def telegram_notice(cfg: Config, device: Device, scan: hik_parser.Scan, picture: bytes | None) -> None:
    """A neutral notice: who, when, where. What it MEANS (came, late…) is the intranet's to say."""
    if not cfg.telegram_token or not cfg.telegram_chat_ids:
        return
    text = "\n".join([
        f"🪪 Скан — {device.label}",
        f"👤 {scan.name} (ID: {scan.employee_no})",
        f"🕐 {scan.occurred_at.astimezone(hik_parser.LOCAL_TIMEZONE).strftime('%H:%M')}",
    ])
    base = f"https://api.telegram.org/bot{cfg.telegram_token}"
    for chat_id in cfg.telegram_chat_ids:
        try:
            if picture:
                requests.post(f"{base}/sendPhoto", data={"chat_id": chat_id, "caption": text},
                              files={"photo": ("scan.jpg", picture, "image/jpeg")}, timeout=20)
            else:
                requests.post(f"{base}/sendMessage", data={"chat_id": chat_id, "text": text}, timeout=10)
        except requests.RequestException as err:
            log.warning("telegram: %s", type(err).__name__)   # never the token


# ── Forwarding to the intranet ───────────────────────────────────────────────

def forward_once(cfg: Config, store: Store, post=requests.post) -> int:
    """Send one batch. Returns how many were delivered (0 when nothing to do or it failed)."""
    if not cfg.erp_url or not cfg.erp_key:
        return 0
    rows = store.pending(cfg.batch_size)
    if not rows:
        return 0
    ids = [r["id"] for r in rows]
    scans = [json.loads(r["payload"]) for r in rows]
    try:
        res = post(f"{cfg.erp_url}/api/integrations/hikvision/scans", json={"scans": scans},
                   headers={"X-Integration-Key": cfg.erp_key}, timeout=20)
    except requests.RequestException as err:
        store.mark_retry(ids, f"network: {type(err).__name__}")
        return 0
    if res.status_code == 200:
        store.mark_sent(ids)
        try:
            unknown = res.json().get("unknown") or []
            if unknown:
                log.info("intranet: %d terminal id(s) not matched to staff yet: %s", len(unknown), ", ".join(unknown[:20]))
        except ValueError:
            pass
        return len(ids)
    body = res.text[:300]
    if res.status_code == 400:
        # The intranet says the batch itself is invalid: retrying cannot help. Kept for inspection.
        store.mark_failed(ids, f"HTTP 400: {body}")
    else:
        # 401/404 = key or address not set up yet; 413/429/5xx = try again later. Never dropped.
        store.mark_retry(ids, f"HTTP {res.status_code}: {body}")
    log.warning("intranet answered HTTP %s", res.status_code)
    return 0


def forwarder_loop(cfg: Config, store: Store, stop: threading.Event) -> None:
    last_prune = 0.0
    while not stop.is_set():
        try:
            while forward_once(cfg, store) and not stop.is_set():
                pass
            if time.time() - last_prune > 3600:
                store.prune(cfg.raw_retention_days, cfg.sent_retention_days)
                last_prune = time.time()
        except Exception:  # the loop must survive anything; the outbox keeps the scans
            log.exception("forwarder")
        stop.wait(cfg.forward_interval_s)


# ── The app ──────────────────────────────────────────────────────────────────

def create_app(cfg: Config | None = None) -> Flask:
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = cfg or Config.from_env()
    store = Store(cfg.db_path)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024   # an event with its JPEG
    app.extensions["hik"] = {"cfg": cfg, "store": store}

    def device_for(token: str) -> Device | None:
        found = None
        for d in cfg.devices:
            if hmac.compare_digest(d.token.encode(), token.encode()):
                found = d
        return found

    @app.post("/hikvision/<token>")
    def push(token: str):
        device = device_for(token)
        if device is None:
            return "", 404
        if device.digest_user:
            if not digest_ok(request.headers.get("Authorization", ""), request.method, device, cfg.digest_realm, cfg.nonce_secret, request.path):
                resp = Response("", 401)
                resp.headers["WWW-Authenticate"] = (f'Digest realm="{cfg.digest_realm}", qop="auth", '
                                                    f'nonce="{make_nonce(cfg.nonce_secret)}", algorithm=MD5')
                return resp
        event = hik_parser.extract_event_json(request)
        if not isinstance(event, dict):
            store.seen(device.label, scan=False)
            return "", 200          # a lone picture or an empty keep-alive: nothing to keep
        if hik_parser.is_heartbeat(event):
            store.seen(device.label, scan=False)
            return "", 200
        scan, reason = hik_parser.read_scan(event, success_event_codes=device.success_event_codes)
        payload_ip = hik_parser.first_value(event, hik_parser.get_access_event(event), "ipAddress")
        if device.expected_ip and payload_ip and str(payload_ip) != device.expected_ip:
            log.warning("%s: payload ipAddress %s is not the expected %s", device.label, payload_ip, device.expected_ip)
        now = datetime.now(timezone.utc)
        if scan and (scan.occurred_at - now).total_seconds() > cfg.max_future_skew_s:
            scan, reason = None, "event time too far ahead of the server clock"
        try:
            store.record_raw(device.label, scan is not None, reason, event)
            store.seen(device.label, scan=scan is not None)
            if scan is None:
                return "", 200
            # The moment is part of the key: a terminal whose event counter restarts
            # (log cleared, factory reset) reuses serial numbers for new passes.
            second = int(scan.occurred_at.timestamp())
            key = f"{device.sn}:{scan.event_serial}:{second}" if scan.event_serial else f"{device.sn}:{scan.employee_no}:{second}"
            new = store.enqueue(key, device.label, scan.to_erp(device.sn, device.label), scan.occurred_at)
        except sqlite3.Error:
            log.exception("outbox write failed")
            return "", 500          # the terminal will send it again
        age = (now - scan.occurred_at).total_seconds()
        if new and age <= cfg.telegram_max_age_s:
            picture = hik_parser.extract_picture(request)
            threading.Thread(target=telegram_notice, args=(cfg, device, scan, picture), daemon=True).start()
        return "", 200

    @app.get("/health")
    def health():
        h = store.health()
        h["ok"] = True
        h["erpConfigured"] = bool(cfg.erp_url and cfg.erp_key)
        h["devices_configured"] = [d.label for d in cfg.devices]
        return jsonify(h)

    @app.get("/")
    def root():
        return "hikvision-ingest", 200

    if cfg.start_forwarder:
        stop = threading.Event()
        threading.Thread(target=forwarder_loop, args=(cfg, store, stop), daemon=True, name="forwarder").start()
        app.extensions["hik"]["stop"] = stop
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
