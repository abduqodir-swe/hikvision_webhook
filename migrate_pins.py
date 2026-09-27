"""Copy employee PINs between the configured Hikvision terminals.

Read-only by default. PIN values are kept in memory and never printed or saved.
Run one employee first, verify face + PIN at the door, then explicitly opt in
to the remaining users. Existing users and face records are never recreated.
"""

from __future__ import annotations

import argparse
import hmac
import sys
import time
import uuid
from dataclasses import dataclass

import migration_fixed as migration


MODIFY_PATH = "/ISAPI/AccessControl/UserInfo/Modify?format=json"
SEARCH_PATH = "/ISAPI/AccessControl/UserInfo/Search?format=json"
PRESERVED_FIELDS = (
    "name",
    "userType",
    "Valid",
    "doorRight",
    "RightPlan",
    "userVerifyMode",
    "numOfFace",
    "numOfCard",
    "numOfFP",
)
MODIFIABLE_FIELDS_TO_PRESERVE = (
    "name",
    "Valid",
    "doorRight",
    "RightPlan",
    "userVerifyMode",
)


@dataclass(frozen=True)
class Candidate:
    employee_no: str
    source_pin: str
    status: str


def employee_no(user: dict) -> str:
    value = user.get("employeeNo")
    if not isinstance(value, (str, int)) or not str(value).strip():
        raise ValueError("Найдена запись без табельного ID")
    return str(value)


def index_users(users: list[dict]) -> dict[str, dict]:
    indexed = {}
    for user in users:
        number = employee_no(user)
        if number in indexed:
            raise ValueError(f"Повторяющийся табельный ID: {number}")
        indexed[number] = user
    return indexed


def same_pin(first: str, second: str) -> bool:
    return hmac.compare_digest(first, second)


def candidate(
    number: str,
    old: dict | None,
    new: dict | None,
    *,
    allow_name_mismatch: bool = False,
) -> Candidate:
    if old is None or new is None:
        return Candidate(number, "", "нет сотрудника на одном из терминалов")
    if old.get("userType") != "normal" or new.get("userType") != "normal":
        return Candidate(number, "", "запись не является обычным сотрудником")
    old_name = str(old.get("name", "")).strip()
    new_name = str(new.get("name", "")).strip()
    if not old_name or not new_name or (old_name != new_name and not allow_name_mismatch):
        return Candidate(number, "", "имена различаются — нужна ручная сверка")

    pin = old.get("password")
    if not isinstance(pin, str) or not pin or not pin.isascii() or not pin.isdigit():
        return Candidate(number, "", "на старом терминале нет цифрового PIN")

    current = new.get("password")
    if current:
        if not isinstance(current, str):
            return Candidate(number, "", "на новом терминале PIN в неизвестном формате")
        if same_pin(pin, current):
            return Candidate(number, "", "PIN уже совпадает")
        return Candidate(number, "", "на новом терминале уже есть другой PIN")

    return Candidate(number, pin, "готов к переносу")


def search_one(client: migration.HikvisionClient, number: str) -> dict | None:
    body = {
        "UserInfoSearchCond": {
            # A fresh ID avoids a cached pre-write result during verification.
            "searchID": uuid.uuid4().hex,
            "searchResultPosition": 0,
            "maxResults": 2,
            "EmployeeNoList": [{"employeeNo": number}],
        }
    }
    response = client.request("POST", SEARCH_PATH, json=body)
    if response.status_code != 200:
        raise RuntimeError("Поиск сотрудника на терминале не удался")
    result = response.json().get("UserInfoSearch", {})
    matches = [
        user for user in result.get("UserInfo", [])
        if employee_no(user) == number
    ]
    if len(matches) > 1:
        raise ValueError(f"Повторяющийся табельный ID: {number}")
    return matches[0] if matches else None


def preserved_snapshot(user: dict) -> dict:
    return {key: user[key] for key in PRESERVED_FIELDS if key in user}


def response_succeeded(response) -> bool:
    if response.status_code != 200:
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    status = payload.get("ResponseStatus", payload)
    return isinstance(status, dict) and str(status.get("statusCode")) == "1"


def transfer_one(
    number: str,
    expected_pin: str,
    *,
    allow_name_mismatch: bool = False,
) -> bool:
    # Re-read both records immediately before the write. Never overwrite a PIN.
    old = search_one(migration.OLD, number)
    new = search_one(migration.NEW, number)
    current = candidate(number, old, new, allow_name_mismatch=allow_name_mismatch)
    if current.status != "готов к переносу" or not same_pin(current.source_pin, expected_pin):
        print(f"[SKIP] ID {number}: данные изменились; повторите просмотр")
        return False

    before = preserved_snapshot(new)
    payload = {
        "employeeNo": number,
        "userType": new["userType"],
        "password": expected_pin,
    }
    for field in MODIFIABLE_FIELDS_TO_PRESERVE:
        if field in new:
            payload[field] = new[field]

    response = migration.NEW.request(
        "PUT",
        MODIFY_PATH,
        json={"UserInfo": payload},
    )
    if not response_succeeded(response):
        print(f"[ERROR] ID {number}: терминал отклонил изменение; перенос остановлен")
        return False

    after = search_one(migration.NEW, number)
    if after is None or not isinstance(after.get("password"), str):
        print(f"[ERROR] ID {number}: невозможно подтвердить PIN после записи; перенос остановлен")
        return False
    if not same_pin(after["password"], expected_pin):
        print(f"[ERROR] ID {number}: PIN после записи не совпал; перенос остановлен")
        return False
    if preserved_snapshot(after) != before:
        print(f"[ERROR] ID {number}: изменились другие поля сотрудника; перенос остановлен")
        return False

    print(f"[OK] ID {number}: PIN перенесён и проверен чтением")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Разрешить запись на новый терминал")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--employee-no", help="Один сотрудник по точному табельному ID")
    selection.add_argument("--all", action="store_true", help="Все подходящие сотрудники")
    parser.add_argument(
        "--allow-name-mismatch",
        action="store_true",
        help="Только с --employee-no: сверять сотрудника по ID при разных непустых именах",
    )
    parser.add_argument(
        "--pilot-id",
        help="ID уже перенесённого и проверенного проходом сотрудника; обязателен для --all --apply",
    )
    parser.add_argument(
        "--confirm-bulk",
        action="store_true",
        help="Я проверил проход пилотного сотрудника и разрешаю массовую запись",
    )
    args = parser.parse_args()
    if args.apply and not (args.employee_no or args.all):
        parser.error("для --apply укажите --employee-no или --all")
    if args.all and args.apply and not (args.pilot_id and args.confirm_bulk):
        parser.error("массовый перенос требует --pilot-id и --confirm-bulk")
    if args.pilot_id and not (args.all and args.apply):
        parser.error("--pilot-id используется только с --apply --all")
    if args.confirm_bulk and not (args.all and args.apply):
        parser.error("--confirm-bulk используется только с --apply --all")
    if args.allow_name_mismatch and not args.employee_no:
        parser.error("--allow-name-mismatch допускается только с --employee-no")
    return args


def main() -> int:
    args = parse_args()
    if migration.OLD.ip == migration.NEW.ip:
        print("[ERROR] Адреса старого и нового терминалов совпадают")
        return 1

    old = index_users(migration.get_all_users(migration.OLD))
    new = index_users(migration.get_all_users(migration.NEW))
    selected = [args.employee_no] if args.employee_no else sorted(old.keys() | new.keys())
    if args.employee_no and args.employee_no not in old.keys() | new.keys():
        print("[ERROR] Такого табельного ID нет ни на одном терминале")
        return 1

    plan = [
        candidate(
            number,
            old.get(number),
            new.get(number),
            allow_name_mismatch=args.allow_name_mismatch and number == args.employee_no,
        )
        for number in selected
    ]
    if args.allow_name_mismatch and args.employee_no in old and args.employee_no in new:
        print(f"[WARN] ID {args.employee_no}: несовпадение имени разрешено только для этого ID")
    for item in plan:
        print(f"ID {item.employee_no}: {item.status}")
    ready = [item for item in plan if item.status == "готов к переносу"]
    print(f"Готово к переносу: {len(ready)} из {len(plan)}; PIN не выводятся")

    if not args.apply:
        print("Режим просмотра: изменений нет")
        return 0
    if args.employee_no and not ready:
        return 0 if plan[0].status == "PIN уже совпадает" else 1

    if args.all:
        pilot = candidate(args.pilot_id, old.get(args.pilot_id), new.get(args.pilot_id))
        if pilot.status != "PIN уже совпадает":
            print("[ERROR] PIN пилотного сотрудника не подтверждён на новом терминале")
            return 1
        print("Пилотный PIN совпадает; начинаю массовый перенос")

    for index, item in enumerate(ready, start=1):
        started_at = time.monotonic()
        try:
            if not transfer_one(
                item.employee_no,
                item.source_pin,
                allow_name_mismatch=args.allow_name_mismatch and item.employee_no == args.employee_no,
            ):
                return 1
        except migration.HikvisionAuthError as exc:
            # This exception is built from the device label and request path,
            # never from a vendor response or the PIN-bearing request body.
            print(f"[AUTH STOP] ID {item.employee_no}: {exc}")
            print("Уже перенесённые PIN не откатываются; повторных запросов не будет")
            return 1

        # Match migration_fixed.py: at least 30 seconds from the start of one
        # employee to the start of the next; the per-device request gap remains.
        if index < len(ready):
            remaining = max(0.0, migration.BETWEEN_USERS_SECONDS - (time.monotonic() - started_at))
            if remaining > 0:
                print(f"Пауза {remaining:.0f} сек перед следующим сотрудником...")
                time.sleep(remaining)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Do not print exception strings: a vendor response may echo a PIN.
        print(f"[ERROR] Перенос остановлен ({type(exc).__name__}); PIN не выводятся")
        sys.exit(1)
