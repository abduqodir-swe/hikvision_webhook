"""hik_parser must read every payload exactly as the proven webhook_server.py does."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hik_parser  # noqa: E402
import webhook_server as legacy  # noqa: E402  (importing it starts nothing: its server runs only under __main__)
from tests.fixtures import PARITY_CASES  # noqa: E402

DEVICE = {"success_event_codes": {"153"}}


class ParserParity(unittest.TestCase):
    def test_every_function_agrees_with_webhook_server(self):
        for i, event in enumerate(PARITY_CASES):
            with self.subTest(case=i):
                ae_new, ae_old = hik_parser.get_access_event(event), legacy.get_access_event(event)
                self.assertEqual(ae_new, ae_old)
                self.assertEqual(hik_parser.is_heartbeat(event), legacy.is_heartbeat(event))
                self.assertEqual(hik_parser.employee_details(event, ae_new), legacy.employee_details(event, ae_old))
                self.assertEqual(hik_parser.event_code(event, ae_new), legacy.event_code(event, ae_old))
                self.assertEqual(hik_parser.event_time(event), legacy.event_time(event))
                if ae_new:
                    self.assertEqual(hik_parser.is_door_one(event, ae_new), legacy.is_door_one(event, ae_old))
                    self.assertEqual(hik_parser.combined_authentication_passed(event, ae_new, DEVICE["success_event_codes"]),
                                     legacy.combined_authentication_passed(event, ae_old, DEVICE))

    def test_read_scan_accepts_exactly_what_the_laptop_server_accepts(self):
        """Same acceptance as process_event (heartbeat, access event, person, Door1, code) — minus freshness."""
        for i, event in enumerate(PARITY_CASES):
            with self.subTest(case=i):
                ae = legacy.get_access_event(event)
                legacy_accepts = (not legacy.is_heartbeat(event) and bool(ae) and bool(legacy.employee_details(event, ae))
                                  and legacy.is_door_one(event, ae) and legacy.combined_authentication_passed(event, ae, DEVICE)
                                  and legacy.event_time(event) is not None)
                scan, _ = hik_parser.read_scan(event)
                self.assertEqual(scan is not None, legacy_accepts)


class ScanShape(unittest.TestCase):
    def test_to_erp_is_the_intranet_shape(self):
        from tests.fixtures import access_event
        scan, reason = hik_parser.read_scan(access_event(when="2026-09-26T14:03:12+05:00"))
        self.assertEqual(reason, "")
        self.assertEqual(scan.to_erp("SN-1", "Room 1"), {
            "id": "00000004", "ts": 1790413392, "name": "Aziza Karimova", "sn": "SN-1",
            "status": 1, "label": "Room 1", "eventId": "1234",
        })

    def test_the_id_is_kept_exactly_as_sent(self):
        from tests.fixtures import access_event
        scan, _ = hik_parser.read_scan(access_event(employee_no="00000004"))
        self.assertEqual(scan.employee_no, "00000004")   # never normalised to "4"

    def test_a_utc_time_is_read_as_utc(self):
        from tests.fixtures import access_event
        scan, _ = hik_parser.read_scan(access_event(when="2026-09-26T09:03:12Z"))
        self.assertEqual(scan.to_erp("s", "l")["ts"], 1790413392)


if __name__ == "__main__":
    unittest.main()
