"""Hikvision access-control pushes used by the tests.

SYNTHETIC: these follow the ISAPI httpHosts `event_log` structure the parser
was written against (AccessControllerEvent, subEventType/minor 153 =
"Combined Authentication Passed", employeeNoString, serialNo, doorNo/channelID)
but they are NOT captured from the real 192.168.0.141. Before deployment,
capture one real push with hikvision_probe.py and add it here (see DEPLOY.md).
"""

from __future__ import annotations

import json


def access_event(employee_no: str = "00000004", name: str = "Aziza Karimova", when: str = "2026-09-26T14:03:12+05:00",
                 serial: int | None = 1234, code: int = 153, door_no: int | None = 1, user_type: str = "normal",
                 nested: bool = True, **extra) -> dict:
    ace = {
        "deviceName": "Door1", "majorEventType": 5, "subEventType": code, "name": name,
        "cardReaderNo": 1, "employeeNoString": employee_no, "userType": user_type,
        "currentVerifyMode": "faceAndPw", "attendanceStatus": "undefined",
        "pictureURL": "http://192.168.0.141/LOCALS/pic/acsLinkCap/202609_00/26_140312_30075_0.jpeg",
    }
    if serial is not None:
        ace["serialNo"] = serial
    if door_no is not None:
        ace["doorNo"] = door_no
    ace.update(extra)
    event = {
        "ipAddress": "192.168.0.141", "portNo": 80, "protocol": "HTTP", "macAddress": "a4:d5:c2:00:00:01",
        "channelID": 1, "dateTime": when, "activePostCount": 1, "eventType": "AccessControllerEvent",
        "eventState": "active", "eventDescription": "Access Controller Event",
    }
    if nested:
        event["AccessControllerEvent"] = ace
    else:
        event.update(ace)
    return event


HEARTBEAT = {"ipAddress": "192.168.0.141", "dateTime": "2026-09-26T14:03:12+05:00", "eventType": "heartBeat", "eventState": "active"}

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 400 + b"\xff\xd9"


def multipart(event: dict, picture: bytes | None = None) -> dict:
    """Flask test-client `data=` for the terminal's multipart/form-data push."""
    import io
    data = {"event_log": json.dumps(event, ensure_ascii=False)}
    if picture is not None:
        data["Picture"] = (io.BytesIO(picture), "Picture.jpg", "image/jpeg")
    return data


# A spread of shapes the parser must read the same way as webhook_server.py.
PARITY_CASES = [
    access_event(),
    access_event(nested=False),
    access_event(code=75),                      # face verify only — not a pass
    access_event(door_no=None),                 # new model: channelID only
    access_event(door_no=2),
    access_event(user_type="visitor"),
    access_event(name=""),
    access_event(employee_no="5", when="2026-09-26T01:30:00Z"),
    access_event(when="not a time"),
    access_event(serial=None),
    {"eventType": "AccessControllerEvent", "dateTime": "2026-09-26T14:00:00+05:00", "AccessControllerEvent": {"minor": 153, "employeeNo": 19, "name": "X", "doorName": "Door 1"}},
    {"eventType": "AccessControllerEvent", "eventDescription": "Combined Authentication Passed", "AccessControllerEvent": {"employeeNoString": "7", "name": "Y", "doorNo": 1}},
    HEARTBEAT,
    {},
]
