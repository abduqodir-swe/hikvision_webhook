"""Reading Hikvision access-control pushes (ISAPI httpHosts).

The functions below are the parser that was proven against the real terminals
(DS-K1T331W at 192.168.0.141 and DS-K1T342MFWX) in ``webhook_server.py``,
moved here unchanged in behaviour so the cloud ingest service reads a payload
exactly the way the laptop server does. ``tests/test_parser_parity.py`` feeds
the same payloads to both and fails if they ever disagree.

What changed compared with ``webhook_server.py``: the settings the functions
used to read from module constants (door, accepted event codes, timezone,
allowed employee ids) are parameters with the same defaults. There is NO
attendance business logic here — no working hours, no "in"/"out", no late or
early. Deciding what a scan means belongs to the intranet (owner, 2026-09-26).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

LOCAL_TIMEZONE = ZoneInfo("Asia/Tashkent")
ALLOWED_DOOR_NAMES = frozenset({"door1"})
ALLOWED_DOOR_NUMBERS = frozenset({1})
# DS-K1T331W / DS-K1T342MFWX: "Combined Authentication Passed" (face + PIN).
DEFAULT_SUCCESS_EVENT_CODES = frozenset({"153"})


def get_access_event(event: dict) -> dict:
    """Возвращает AccessControllerEvent для разных поколений прошивки."""
    nested = event.get("AccessControllerEvent", {})
    if isinstance(nested, dict) and nested:
        return nested

    access_keys = {
        "majorEventType", "subEventType", "minorEventType", "minor",
        "employeeNoString", "employeeNo", "doorNo", "cardReaderNo",
        "currentVerifyMode",
    }
    if any(key in event for key in access_keys):
        return event

    return {}


def normalized(value: object) -> str:
    """Сравнение значений от разных прошивок без пробелов, дефисов и регистра."""
    return "".join(char for char in str(value).lower() if char.isalnum())


def first_value(event: dict, access_event: dict, *keys: str) -> object | None:
    for source in (access_event, event):
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
    return None


def is_door_one(event: dict, access_event: dict,
                door_names=ALLOWED_DOOR_NAMES, door_numbers=ALLOWED_DOOR_NUMBERS) -> bool:
    door_name = first_value(event, access_event, "doorName")
    if door_name is not None and normalized(door_name) in door_names:
        return True

    door_no = first_value(event, access_event, "doorNo")
    try:
        if int(str(door_no)) in door_numbers:
            return True
    except (TypeError, ValueError):
        pass

    # Новый DS-K1T342MFWX в webhook может не присылать doorNo,
    # зато присылает channelID=1.
    channel_id = first_value(event, access_event, "channelID")
    try:
        return int(str(channel_id)) in door_numbers
    except (TypeError, ValueError):
        return False


def event_code(event: dict, access_event: dict) -> str | None:
    value = first_value(
        event,
        access_event,
        "minorEventType",
        "subEventType",
        "minor",
        "eventDescription",
    )
    return None if value in (None, "") else str(value)


def verify_mode(event: dict, access_event: dict) -> str:
    value = first_value(event, access_event, "currentVerifyMode", "verifyMode")
    return "" if value in (None, "") else str(value)


def is_heartbeat(event: dict) -> bool:
    return normalized(event.get("eventType", "")) == "heartbeat"


def combined_authentication_passed(event: dict, access_event: dict,
                                   success_event_codes=DEFAULT_SUCCESS_EVENT_CODES,
                                   require_combined_authentication: bool = True) -> bool:
    """Проверяет успешный проход с учётом конкретного терминала."""
    if not require_combined_authentication:
        return True

    accepted_codes = {str(code) for code in success_event_codes}
    event_values = []
    for source in (access_event, event):
        for key in (
            "minorEventType",
            "subEventType",
            "minor",
            "eventDescription",
            "eventType",
        ):
            value = source.get(key)
            if value is not None:
                event_values.append(value)

    return any(
        str(value) in accepted_codes
        or "combinedauthenticationpassed" in normalized(value)
        for value in event_values
    )


def employee_details(event: dict, access_event: dict,
                     employee_ids: set[str] | frozenset[str] | None = None) -> tuple[str, str] | None:
    """Незарегистрированные лица и системные события не имеют пары имя + ID."""
    user_type = first_value(event, access_event, "userType")
    if user_type is not None and normalized(user_type) not in {"normal", "1"}:
        return None
    name = first_value(event, access_event, "name")
    employee_no = first_value(event, access_event, "employeeNoString", "employeeNo")
    if not name or not employee_no:
        return None

    employee_no = str(employee_no)
    if employee_ids and employee_no not in employee_ids:
        return None
    return str(name), employee_no


def event_time(event: dict, tz: ZoneInfo = LOCAL_TIMEZONE) -> datetime | None:
    access_event = get_access_event(event)
    raw = first_value(event, access_event, "dateTime", "time")
    if not raw:
        return None
    try:
        occurred_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=tz)
    return occurred_at.astimezone(tz)


def extract_event_json(req) -> dict | None:
    """Парсит multipart/json от обоих терминалов."""
    preferred_fields = (
        "event_log",
        "eventLog",
        "EventNotificationAlert",
        "AccessControllerEvent",
    )

    for field_name in preferred_fields:
        if field_name in req.form:
            try:
                value = json.loads(req.form[field_name])
                if isinstance(value, dict):
                    return value
            except (json.JSONDecodeError, TypeError):
                pass

    # На случай других названий multipart field.
    for field_name in req.form:
        value = req.form.get(field_name, "")
        if isinstance(value, str) and value.lstrip().startswith("{"):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

    # Иногда JSON может приехать как file-part.
    for field_name, storage in req.files.items():
        content_type = (storage.content_type or "").lower()
        if "json" not in content_type and field_name not in preferred_fields:
            continue
        data = storage.read()
        try:
            storage.stream.seek(0)
        except Exception:
            pass
        try:
            parsed = json.loads(data.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if req.is_json:
        parsed = req.get_json(silent=True)
        return parsed if isinstance(parsed, dict) else None

    raw = req.get_data(cache=True)
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            return parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    return None


def extract_picture(req) -> bytes | None:
    """Достаёт JPEG из известных или произвольных image multipart parts."""
    preferred = ("picture", "Picture", "image", "Image", "facePicture")
    ordered = []

    for name in preferred:
        if name in req.files:
            ordered.append((name, req.files[name]))
    for name, storage in req.files.items():
        if name not in preferred:
            ordered.append((name, storage))

    for _name, storage in ordered:
        content_type = (storage.content_type or "").lower()
        if (
            not content_type.startswith("image/")
            and content_type not in {"application/octet-stream", ""}
        ):
            continue
        data = storage.read()
        try:
            storage.stream.seek(0)
        except Exception:
            pass
        if len(data) > 100 and (
            data.startswith(b"\xff\xd8") or content_type.startswith("image/")
        ):
            return data

    return None


# ── One scan, as the intranet takes it ───────────────────────────────────────

@dataclass(frozen=True)
class Scan:
    """A successful pass, in the intranet's `{ scans: [...] }` shape (no meaning attached)."""
    employee_no: str          # exactly as the terminal sent it ("00000004", "5")
    name: str                 # the name stored on the terminal
    occurred_at: datetime     # the terminal's clock, timezone-aware
    event_serial: str | None  # the terminal's serialNo, for tracing and de-duplication

    def to_erp(self, sn: str, label: str) -> dict:
        return {
            "id": self.employee_no,
            "ts": int(self.occurred_at.timestamp()),
            "name": self.name,
            "sn": sn,
            "status": 1,
            "label": label,
            "eventId": self.event_serial,
        }


def read_scan(event: dict, *, success_event_codes=DEFAULT_SUCCESS_EVENT_CODES,
              door_names=ALLOWED_DOOR_NAMES, door_numbers=ALLOWED_DOOR_NUMBERS,
              employee_ids=None, tz: ZoneInfo = LOCAL_TIMEZONE) -> tuple[Scan | None, str]:
    """The same acceptance rules as ``webhook_server.process_event``, minus freshness.

    Returns (scan, "") for a successful pass by a registered person at Door1
    with the accepted event code, else (None, reason). How old the event is does
    NOT matter here: a pass the terminal re-sends after an outage is still a
    pass. (Only the Telegram notice cares about freshness.)
    """
    if is_heartbeat(event):
        return None, "heartbeat"
    access_event = get_access_event(event)
    if not access_event:
        return None, "not an access-control event"
    employee = employee_details(event, access_event, employee_ids)
    if not employee:
        return None, "no registered person (name + employee id)"
    if not is_door_one(event, access_event, door_names, door_numbers):
        return None, "not Door1/Channel1"
    if not combined_authentication_passed(event, access_event, success_event_codes):
        return None, f"event code {event_code(event, access_event)!r} is not an accepted pass"
    occurred_at = event_time(event, tz)
    if occurred_at is None:
        return None, "no event time"
    serial = first_value(event, access_event, "serialNo")
    return Scan(employee_no=employee[1], name=employee[0], occurred_at=occurred_at,
                event_serial=None if serial in (None, "") else str(serial)), ""
