# Drain

A small, privacy-conscious usage counter for Forest, Nabu, Enkii, and Argus.

Drain counts anonymous installations and active instances. It does not identify people.

## What is stored

Each client creates a random local instance ID. Drain stores a one-way HMAC hash of that ID, plus:

- project
- event (`install`, `heartbeat`, `upgrade`, or `uninstall`)
- version
- platform/runtime labels
- server-side timestamp

The application does not store IP addresses, usernames, machine names, paths, command arguments, or event payloads beyond these fields. Reverse-proxy access logging should remain disabled or privacy-configured at the host level.

For the blog, Drain also accepts `POST /v1/article-views` with an article slug. It derives the visitor IP at the edge, stores only an HMAC hash scoped to that article, and returns the aggregate unique-reader count. The public response never contains an IP address or hash. Repeated reads from the same IP count once per article; this is an approximate audience metric, not an identity system.

## Local development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
DRAIN_ADMIN_PASSWORD=dev-password python app.py
```

Open `http://localhost:8080/` with HTTP Basic Auth (`admin` / `dev-password`).

Run tests:

```bash
pytest -q
```

## Sending an event

```bash
curl -i https://drain.timi.click/v1/events \
  -H 'Content-Type: application/json' \
  --data '{
    "project": "nabu",
    "event": "heartbeat",
    "event_id": "00000000-0000-4000-8000-000000000001",
    "instance_id": "00000000-0000-4000-8000-000000000002",
    "version": "0.1.0",
    "platform": "linux",
    "runtime": "bun"
  }'
```

Clients must make reporting opt-out and must not block the main tool if Drain is unavailable. Use a short timeout and swallow network errors.

## Deployment

The production deployment is a Dokploy-managed Compose application with a persistent Docker volume at `/data/drain.sqlite3`. The dashboard is protected with HTTP Basic Auth. The ingest endpoint is public but accepts only the small validated event schema above.
