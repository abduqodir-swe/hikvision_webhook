# Hikvision → intranet Tabel: deployment

```text
Hikvision 192.168.0.141 ──HTTPS push (HTTP Host)──► https://hik.phoenix-math.uz/hikvision/<token>
   (Caddy on the intranet VPS) ──► hikvision-ingest (ingest_server.py, this folder)
      ├─ outbox (SQLite) — written before the terminal gets its 200
      └─► http://app:5000/api/integrations/hikvision/scans  (HIKVISION_INTEGRATION_KEY)
             └─► staff_face_scans → the existing Tabel (/tabel, /team/:id/tabel)
```

No computer at the school is needed. The terminal talks to the internet; nothing
on the internet talks to the terminal. Attendance rules (first scan = arrival,
last = departure, grace, working day from 05:00) live only in the intranet.

What the cloud path cannot do (the terminal is not reachable from the VPS): no
journal catch-up polling and no photo download by `pictureURL`. Recovery after an
outage relies on the terminal re-sending its backlog (seen on this terminal, see
README); the ingest service and the intranet accept late passes and never double
a re-sent one.

## 0. Before anything (read-only, on the school LAN)

1. **Capabilities of .141** — does its HTTP Host support HTTPS and a hostname?
   ```bash
   read -s -p "admin password of .141: " HIK_PASS; echo; for p in /ISAPI/System/deviceInfo /ISAPI/Event/notification/httpHosts/capabilities /ISAPI/Event/notification/httpHosts /ISAPI/System/Network/interfaces/1/ipAddress; do echo "===== $p"; curl -s --digest -u "admin:$HIK_PASS" --max-time 10 "http://192.168.0.141$p"; echo; done > ~/hik141-capabilities.txt; unset HIK_PASS
   ```
   Look for: `protocolType` options (`HTTPS`), `addressingFormatType` options
   (`hostname`), how many `HttpHostNotification` entries are allowed (a second
   host for the pilot), `httpAuthenticationMethod` options (`MD5digest`), the
   `serialNumber` (→ `sn` in `HIK_DEVICES`), and that a DNS server is set.
2. **One real push** for the tests: run `python hikvision_probe.py` on the laptop
   while the terminal's current HTTP Host points at it, do one face + PIN pass,
   and save the printed `event_log` JSON as `tests/real_push_141.json`. The test
   fixtures are synthetic until then (see `tests/fixtures.py`).

## 1. Intranet

1. Deploy the intranet branch `feature/hikvision-tabel` (migration `0067` is additive:
   new tables, new columns; it re-reads the working day of already kept scans so
   00:00–04:59 scans belong to the day before).
2. Set `HIKVISION_INTEGRATION_KEY` in `.env.docker` (16+ random characters) and
   restart `app`. Until it is set the door answers 404.

## 2. The ingest service (on the intranet VPS)

1. Copy this folder to `/opt/hikvision_webhook` on the VPS.
2. `cp deploy/.env.example deploy/.env` and fill it: a new random `token`, the
   terminal's `sn`, `ERP_KEY` = the intranet's `HIKVISION_INTEGRATION_KEY`. For the
   pilot Telegram notice use a **new** bot token (see Security below).
3. Start it next to the intranet:
   ```bash
   docker compose --env-file .env.docker -f docker-compose.yml -f /opt/hikvision_webhook/deploy/docker-compose.hikvision.yml up -d --build hikvision-ingest
   ```
4. DNS: `A hik.phoenix-math.uz → 37.27.249.132`. Put the HTTPS block of
   `deploy/Caddyfile.snippet` into the intranet's `caddy-sites/hik.caddy` (server
   only; the intranet `Caddyfile` imports `caddy-sites/*.caddy` and already sets
   `default_sni hik.phoenix-math.uz` for clients without SNI). Validate, then
   recreate Caddy once (see `caddy-sites/README.md` in the intranet).
5. Check from anywhere:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://hik.phoenix-math.uz/hikvision/wrong-token   # 404
   ```

## 3. The terminal (only after the owner's go-ahead — this changes the device)

Add a **second** HTTP Host (keep the laptop's one until the pilot is over):
protocol HTTPS, address type hostname, `hik.phoenix-math.uz`, port 443, URL
`/hikvision/<token>`, format JSON, authentication none (or MD5digest with the
`digest_user`/`digest_pass` of this device). Via the web UI (Configuration →
Network → Advanced → HTTP Listening / Event Alarm) or ISAPI
`PUT /ISAPI/Event/notification/httpHosts`.

Then one face + PIN pass and check:
- `docker compose exec hikvision-ingest python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"`
  → `devices[].last_scan_at` set, `pending` back to 0;
- intranet → Tabel → **Hikvision ids**: the id appears as not matched → match it
  to the staff member (from the first day) → the scan shows on their Tabel.

### 3b. If HTTPS does not arrive

Nothing in `/health` and no Caddy log line for the host = the TLS handshake
failed. `default_sni` is already set (no-SNI clients get the RSA certificate).
First collect the cause (Caddy log with `debug`, `openssl s_client` from a LAN
machine with the terminal's likely settings) and decide with the owner —
never switch to plain HTTP silently. Options, in order:
1. TLS details (protocol version / cipher / CA list of the firmware): adjust the
   `tls` block of `hik.caddy` (e.g. `protocols tls1.2 tls1.3`), retest.
2. Fallback (only with the owner's go-ahead): uncomment the `http://hik.phoenix-math.uz` block of the snippet,
   switch the terminal's HTTP Host to HTTP/80 **with MD5digest** authentication,
   and turn off picture upload in the push if the firmware allows it (the body
   then travels over the internet unencrypted: name and terminal id).
3. If neither works: a small always-on device on the school LAN (or a router VPN)
   running this same container, with `ERP_URL=https://intranet.phoenix-math.uz`.

## 4. Pilot, then switch off the old paths

1. Run one to two weeks with both HTTP Hosts. Compare the Tabel with the laptop's
   Telegram messages.
2. Then remove the laptop's HTTP Host from the terminal and stop `webhook_server.py`.
3. **phoenix-phone-code** (`hikvision.py` polling .141 from the Redmi phone into the
   Google Sheet, and `telegram_bot.py`) is deprecated (owner, 2026-09-26): stop both
   on the phone once the Tabel is trusted. Nothing in the new path reads the Sheet.

## Security

- `webhook_server.py` and `configure_httphost.py` carry a Telegram bot token and the
  terminals' admin password in plain text. **Revoke that bot token** (BotFather →
  /revoke) and change the terminals' admin password once the laptop path is
  retired. The ingest service reads its secrets only from `deploy/.env`.
- The push token is a credential: keep it out of chat and screenshots; rotate it
  by changing `HIK_DEVICES` and the terminal's URL together.
- `/health` is not routed publicly.
