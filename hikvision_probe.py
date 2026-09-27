from flask import Flask, request
import json
import xml.etree.ElementTree as ET

app = Flask(__name__)


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


@app.post("/webhook")
def webhook():
    raw = request.get_data(cache=True)

    print("\n" + "=" * 80)
    print(f"FROM:         {request.remote_addr}")
    print(f"CONTENT-TYPE: {request.content_type}")
    print(f"LENGTH:       {len(raw)} bytes")
    print(f"FORM KEYS:    {list(request.form.keys())}")
    print(f"FILE KEYS:    {list(request.files.keys())}")

    # multipart/form-data
    for key in request.form:
        value = request.form.get(key, "")
        print(f"\n[FORM:{key}]")
        print(value[:3000])

    for key, file in request.files.items():
        data = file.read()
        print(f"\n[FILE:{key}] filename={file.filename!r} "
              f"type={file.content_type!r} size={len(data)}")
        if "json" in (file.content_type or "") or key.lower() in {
            "event_log", "eventlog", "eventnotificationalert"
        }:
            print(data[:3000].decode("utf-8", errors="replace"))

    # direct JSON
    if request.is_json:
        data = request.get_json(silent=True)
        print("\n[JSON]")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:5000])

    # raw XML / text
    elif raw and not request.files and not request.form:
        text = raw.decode("utf-8", errors="replace")
        print("\n[RAW]")
        print(text[:5000])

        if text.lstrip().startswith("<"):
            try:
                root = ET.fromstring(text)
                interesting = {}
                for elem in root.iter():
                    name = strip_ns(elem.tag)
                    if name in {
                        "eventType", "eventState", "eventDescription",
                        "dateTime", "name", "employeeNoString",
                        "minorEventType", "subEventType", "doorNo", "doorName"
                    } and elem.text:
                        interesting[name] = elem.text
                if interesting:
                    print("\n[XML SUMMARY]")
                    print(json.dumps(interesting, ensure_ascii=False, indent=2))
            except ET.ParseError:
                pass

    print("=" * 80, flush=True)
    return "", 200


@app.get("/")
def health():
    return "Hikvision probe is running", 200


if __name__ == "__main__":
    print("[*] Hikvision probe")
    print("[*] Listening: http://0.0.0.0:5002/webhook")
    print("[*] Stop webhook_server.py first if it uses port 5002.")
    app.run(host="0.0.0.0", port=5002, debug=False)
