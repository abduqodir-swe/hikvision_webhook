"""The cloud ingest endpoint: the terminal's push → outbox → intranet."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

import ingest_server  # noqa: E402
from tests.fixtures import HEARTBEAT, JPEG, access_event, multipart  # noqa: E402

TOKEN = "t" * 32
DIGEST_TOKEN = "d" * 32


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone(timedelta(hours=5))).isoformat(timespec="seconds")


class FakeResponse:
    def __init__(self, status: int, body: dict | str = ""):
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, dict):
            return self._body
        raise ValueError("not json")


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = ingest_server.Config(
            db_path=Path(self.tmp.name) / "ingest.db",
            devices=[
                ingest_server.Device(token=TOKEN, label="Room 1 (DS-K1T331W)", sn="DS-K1T331W-TEST", expected_ip="192.168.0.141"),
                ingest_server.Device(token=DIGEST_TOKEN, label="Digest room", sn="SN-DIGEST", digest_user="hik", digest_pass="s3cret"),
            ],
            erp_url="https://erp.test", erp_key="k" * 32,
            telegram_token="tg-token", telegram_chat_ids=["1"],
            start_forwarder=False,
        )
        self.app = ingest_server.create_app(self.cfg)
        self.client = self.app.test_client()
        self.store: ingest_server.Store = self.app.extensions["hik"]["store"]
        self.tg = mock.patch.object(ingest_server, "telegram_notice").start()

    def tearDown(self):
        mock.patch.stopall()
        self.tmp.cleanup()

    def rows(self, table="outbox"):
        with closing(sqlite3.connect(self.cfg.db_path)) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def push(self, event, token=TOKEN, picture=None, **kw):
        return self.client.post(f"/hikvision/{token}", data=multipart(event, picture), content_type="multipart/form-data", **kw)

    # ── receiving ──────────────────────────────────────────────────────────
    def test_unknown_token_is_404_and_keeps_nothing(self):
        self.assertEqual(self.push(access_event(), token="x" * 32).status_code, 404)
        self.assertEqual(self.rows(), [])

    def test_a_pass_is_queued_in_the_intranet_shape_and_a_resend_is_not_doubled(self):
        now = datetime.now(timezone.utc)
        self.assertEqual(self.push(access_event(when=iso(now)), picture=JPEG).status_code, 200)
        self.assertEqual(self.push(access_event(when=iso(now))).status_code, 200)   # the terminal re-sends
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        payload = json.loads(rows[0]["payload"])
        self.assertEqual(payload, {"id": "00000004", "ts": int(datetime.fromisoformat(iso(now)).timestamp()), "name": "Aziza Karimova",
                                   "sn": "DS-K1T331W-TEST", "status": 1, "label": "Room 1 (DS-K1T331W)", "eventId": "1234"})
        self.assertEqual(rows[0]["event_key"], f"DS-K1T331W-TEST:1234:{payload['ts']}")
        self.tg.assert_called_once()                   # a fresh pass: the pilot's Telegram notice, once

    def test_a_late_pass_is_still_a_scan_but_no_notice(self):
        old = datetime.now(timezone.utc) - timedelta(days=2)
        self.push(access_event(when=iso(old), serial=77))
        self.assertEqual(len(self.rows()), 1)
        self.tg.assert_not_called()

    def test_a_clock_far_ahead_is_refused_and_recorded(self):
        ahead = datetime.now(timezone.utc) + timedelta(hours=1)
        self.assertEqual(self.push(access_event(when=iso(ahead))).status_code, 200)
        self.assertEqual(self.rows(), [])
        raw = self.rows("raw_events")
        self.assertEqual(raw[-1]["accepted"], 0)
        self.assertIn("ahead", raw[-1]["reason"])

    def test_not_a_pass_is_kept_only_as_raw(self):
        door_two = access_event(door_no=2)
        door_two["channelID"] = 2          # channelID 1 alone would count as Door1 (the proven parser's rule)
        for event in (access_event(code=75), door_two, access_event(user_type="visitor")):
            self.assertEqual(self.push(event).status_code, 200)
        self.assertEqual(self.rows(), [])
        self.assertEqual([r["accepted"] for r in self.rows("raw_events")], [0, 0, 0])
        self.assertNotIn("Picture", self.rows("raw_events")[0]["event"])

    def test_heartbeat_and_empty_bodies_are_fine(self):
        self.assertEqual(self.push(HEARTBEAT).status_code, 200)
        self.assertEqual(self.client.post(f"/hikvision/{TOKEN}", data=b"").status_code, 200)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.rows("raw_events"), [])

    def test_json_body_is_read_too(self):
        now = datetime.now(timezone.utc)
        res = self.client.post(f"/hikvision/{TOKEN}", json=access_event(when=iso(now), serial=5))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(self.rows()), 1)

    def test_a_reused_serial_at_another_moment_is_a_new_pass(self):
        now = datetime.now(timezone.utc)
        self.push(access_event(when=iso(now - timedelta(days=1)), serial=1))
        self.push(access_event(when=iso(now), serial=1))          # the counter restarted after a log clear
        self.assertEqual(len(self.rows()), 2)

    def test_digest_answer_for_another_address_is_refused(self):
        first = self.push(access_event(), token=DIGEST_TOKEN)
        params = ingest_server._parse_digest(first.headers["WWW-Authenticate"])
        uri = "/somewhere/else"
        ha1 = ingest_server._md5(f"hik:{params['realm']}:s3cret")
        resp = ingest_server._md5(f"{ha1}:{params['nonce']}:00000001:abc:auth:{ingest_server._md5('POST:' + uri)}")
        header = (f'Digest username="hik", realm="{params["realm"]}", nonce="{params["nonce"]}", uri="{uri}", '
                  f'qop=auth, nc=00000001, cnonce="abc", response="{resp}"')
        self.assertEqual(self.push(access_event(), token=DIGEST_TOKEN, headers={"Authorization": header}).status_code, 401)

    def test_without_serial_the_person_and_second_are_the_key(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.push(access_event(when=iso(now), serial=None))
        self.push(access_event(when=iso(now), serial=None))
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_key"], f"DS-K1T331W-TEST:00000004:{int(now.timestamp())}")

    def test_an_outbox_write_failure_asks_the_terminal_to_send_again(self):
        with mock.patch.object(ingest_server.Store, "enqueue", side_effect=sqlite3.OperationalError("disk")):
            self.assertEqual(self.push(access_event()).status_code, 500)

    # ── digest (optional per device) ───────────────────────────────────────
    def test_digest_device_challenges_then_accepts_a_correct_answer(self):
        first = self.push(access_event(), token=DIGEST_TOKEN)
        self.assertEqual(first.status_code, 401)
        challenge = first.headers["WWW-Authenticate"]
        params = ingest_server._parse_digest(challenge)
        uri = f"/hikvision/{DIGEST_TOKEN}"
        ha1 = ingest_server._md5(f"hik:{params['realm']}:s3cret")
        ha2 = ingest_server._md5(f"POST:{uri}")
        resp = ingest_server._md5(f"{ha1}:{params['nonce']}:00000001:abc:auth:{ha2}")
        header = (f'Digest username="hik", realm="{params["realm"]}", nonce="{params["nonce"]}", uri="{uri}", '
                  f'qop=auth, nc=00000001, cnonce="abc", response="{resp}", algorithm=MD5')
        ok = self.push(access_event(serial=9), token=DIGEST_TOKEN, headers={"Authorization": header})
        self.assertEqual(ok.status_code, 200)
        wrong = header.replace(resp, "0" * 32)
        self.assertEqual(self.push(access_event(), token=DIGEST_TOKEN, headers={"Authorization": wrong}).status_code, 401)

    def test_a_stale_or_forged_nonce_is_refused(self):
        secret = self.cfg.nonce_secret
        self.assertTrue(ingest_server.nonce_ok(secret, ingest_server.make_nonce(secret)))
        self.assertFalse(ingest_server.nonce_ok(secret, ingest_server.make_nonce(secret, now=0)))
        self.assertFalse(ingest_server.nonce_ok(secret, "123.abc"))

    # ── forwarding ─────────────────────────────────────────────────────────
    def queue_two(self):
        now = datetime.now(timezone.utc)
        self.push(access_event(when=iso(now), serial=1))
        self.push(access_event(when=iso(now + timedelta(seconds=40)), serial=2))

    def test_forward_delivers_a_batch_with_the_key(self):
        self.queue_two()
        post = mock.Mock(return_value=FakeResponse(200, {"received": 2, "inserted": 2, "repeated": 0, "skipped": 0, "unknown": ["00000004"]}))
        self.assertEqual(ingest_server.forward_once(self.cfg, self.store, post=post), 2)
        url = post.call_args.args[0]
        self.assertEqual(url, "https://erp.test/api/integrations/hikvision/scans")
        self.assertEqual(post.call_args.kwargs["headers"], {"X-Integration-Key": "k" * 32})
        self.assertEqual([s["eventId"] for s in post.call_args.kwargs["json"]["scans"]], ["1", "2"])
        self.assertTrue(all(r["sent_at"] for r in self.rows()))
        self.assertEqual(ingest_server.forward_once(self.cfg, self.store, post=post), 0)   # nothing left

    def test_forward_keeps_scans_on_outage_and_on_a_missing_key(self):
        self.queue_two()
        for i, failure in enumerate((requests.ConnectionError("down"), FakeResponse(503, "busy"), FakeResponse(401, "Unauthorized"), FakeResponse(404, "Not found"))):
            with mock.patch.object(ingest_server.time, "time", return_value=10**10 + i * 1000):   # past the previous backoff
                post = mock.Mock(side_effect=failure) if isinstance(failure, Exception) else mock.Mock(return_value=failure)
                self.assertEqual(ingest_server.forward_once(self.cfg, self.store, post=post), 0)
        rows = self.rows()
        self.assertTrue(all(r["sent_at"] is None and r["failed_at"] is None for r in rows))
        self.assertEqual(rows[0]["attempts"], 4)
        self.assertIn("404", rows[0]["last_error"])

    def test_backoff_waits_before_the_next_try(self):
        self.queue_two()
        ingest_server.forward_once(self.cfg, self.store, post=mock.Mock(return_value=FakeResponse(503, "x")))
        post = mock.Mock(return_value=FakeResponse(200, {}))
        self.assertEqual(ingest_server.forward_once(self.cfg, self.store, post=post), 0)   # not due yet
        post.assert_not_called()

    def test_a_batch_the_intranet_calls_invalid_is_kept_as_failed(self):
        self.queue_two()
        ingest_server.forward_once(self.cfg, self.store, post=mock.Mock(return_value=FakeResponse(400, "Expected JSON")))
        self.assertTrue(all(r["failed_at"] for r in self.rows()))
        self.assertEqual(self.client.get("/health").json["failed"], 2)

    def test_without_intranet_settings_nothing_is_sent(self):
        self.queue_two()
        cfg = ingest_server.Config(db_path=self.cfg.db_path, devices=[], erp_url=None, erp_key=None, start_forwarder=False)
        post = mock.Mock()
        self.assertEqual(ingest_server.forward_once(cfg, self.store, post=post), 0)
        post.assert_not_called()

    # ── second receiver: Phoenix Employee ─────────────────────────────────
    def with_employee(self):
        self.cfg.employee_url, self.cfg.employee_key = "http://employee-api:8080", "e" * 24

    def test_the_employee_app_gets_the_same_scans_with_its_own_key_and_state(self):
        self.with_employee()
        self.queue_two()
        post = mock.Mock(return_value=FakeResponse(200, {"received": 2, "accepted": 2, "unknown": []}))
        self.assertEqual(ingest_server.forward_employee_once(self.cfg, self.store, post=post), 2)
        self.assertEqual(post.call_args.args[0], "http://employee-api:8080/api/v1/integrations/hikvision/scans")
        self.assertEqual(post.call_args.kwargs["headers"], {"X-Integration-Key": "e" * 24})
        self.assertEqual([s["eventId"] for s in post.call_args.kwargs["json"]["scans"]], ["1", "2"])
        self.assertTrue(all(r["sent_at"] for r in self.rows("employee_delivery")))
        self.assertTrue(all(r["sent_at"] is None for r in self.rows()))   # the intranet's delivery is separate
        self.assertEqual(ingest_server.forward_employee_once(self.cfg, self.store, post=post), 0)

    def test_one_receiver_down_does_not_hold_up_the_other(self):
        self.with_employee()
        self.queue_two()
        ingest_server.forward_employee_once(self.cfg, self.store, post=mock.Mock(return_value=FakeResponse(503, "down")))
        self.assertEqual(ingest_server.forward_once(self.cfg, self.store, post=mock.Mock(return_value=FakeResponse(200, {}))), 2)
        self.assertTrue(all(r["sent_at"] for r in self.rows()))
        emp = self.rows("employee_delivery")
        self.assertTrue(all(r["sent_at"] is None and r["attempts"] == 1 for r in emp))
        self.assertEqual(self.client.get("/health").json["employeePending"], 2)

    def test_scans_from_before_the_employee_app_was_configured_are_not_replayed(self):
        self.queue_two()
        self.with_employee()
        self.assertEqual(self.rows("employee_delivery"), [])
        post = mock.Mock()
        self.assertEqual(ingest_server.forward_employee_once(self.cfg, self.store, post=post), 0)
        post.assert_not_called()

    def test_prune_keeps_a_scan_the_employee_app_still_waits_for(self):
        self.with_employee()
        self.queue_two()
        with closing(sqlite3.connect(self.cfg.db_path, isolation_level=None)) as c:
            c.execute("UPDATE outbox SET sent_at='2020-01-01T00:00:00+00:00'")
            c.execute("UPDATE employee_delivery SET sent_at='2020-01-01T00:00:00+00:00' WHERE outbox_id=1")
        self.store.prune(14, 60)
        self.assertEqual([r["id"] for r in self.rows()], [2])
        self.assertEqual([r["outbox_id"] for r in self.rows("employee_delivery")], [2])

    # ── health and housekeeping ────────────────────────────────────────────
    def test_health_reports_the_backlog_and_the_devices(self):
        self.queue_two()
        h = self.client.get("/health").json
        self.assertTrue(h["ok"])
        self.assertEqual(h["pending"], 2)
        self.assertTrue(h["erpConfigured"])
        self.assertEqual(h["devices"][0]["device_label"], "Room 1 (DS-K1T331W)")
        self.assertTrue(h["devices"][0]["last_scan_at"])
        self.assertNotIn("k" * 32, json.dumps(h))
        self.assertNotIn(TOKEN, json.dumps(h))

    def test_prune_forgets_old_raw_events_and_old_delivered_scans_only(self):
        self.queue_two()
        with closing(sqlite3.connect(self.cfg.db_path, isolation_level=None)) as c:
            c.execute("UPDATE raw_events SET received_at='2020-01-01T00:00:00+00:00'")
            c.execute("UPDATE outbox SET sent_at='2020-01-01T00:00:00+00:00' WHERE id=1")
        self.store.prune(14, 60)
        self.assertEqual(self.rows("raw_events"), [])
        self.assertEqual([r["id"] for r in self.rows()], [2])     # the pending one stays


class ConfigTest(unittest.TestCase):
    def test_devices_come_from_the_environment_and_short_tokens_are_refused(self):
        env = {"HIK_DEVICES": json.dumps([{"token": "x" * 24, "label": "Room 1", "sn": "SN"}]), "ERP_URL": "https://erp.test/", "ERP_KEY": "k"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = ingest_server.Config.from_env()
        self.assertEqual(cfg.erp_url, "https://erp.test")
        self.assertIsNone(cfg.employee_url)
        with mock.patch.dict(os.environ, {**env, "EMPLOYEE_URL": "http://employee-api:8080/", "EMPLOYEE_KEY": "e" * 24}, clear=True):
            self.assertEqual(ingest_server.Config.from_env().employee_url, "http://employee-api:8080")
        self.assertEqual(cfg.devices[0].success_event_codes, frozenset({"153"}))
        with mock.patch.dict(os.environ, {"HIK_DEVICES": json.dumps([{"token": "short", "label": "R", "sn": "S"}])}, clear=True):
            with self.assertRaises(ValueError):
                ingest_server.Config.from_env()


if __name__ == "__main__":
    unittest.main()
