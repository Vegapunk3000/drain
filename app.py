from __future__ import annotations

import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

PROJECTS = {"forest", "nabu", "enkii", "argus", "dotmd"}
EVENTS = {"install", "heartbeat", "upgrade", "uninstall"}
ARTICLE_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,119}$")
MAX_VERSION_LENGTH = 80
MAX_PLATFORM_LENGTH = 40
MAX_RUNTIME_LENGTH = 80


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


@contextmanager
def get_db(path: str):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        conn.close()


def init_db(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with get_db(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                project TEXT NOT NULL,
                event TEXT NOT NULL,
                version TEXT NOT NULL,
                instance_hash TEXT NOT NULL,
                platform TEXT NOT NULL,
                runtime TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_project_created
                ON events(project, created_at);
            CREATE INDEX IF NOT EXISTS idx_events_instance_created
                ON events(instance_hash, created_at);
            CREATE TABLE IF NOT EXISTS article_views (
                article TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hits INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (article, ip_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_article_views_article
                ON article_views(article);
            """
        )


def basic_auth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.authorization
        expected_user = request.app_config["admin_user"] if hasattr(request, "app_config") else None
        expected_password = request.app_config["admin_password"] if hasattr(request, "app_config") else None
        if not auth or not expected_user or not expected_password:
            return _auth_challenge()
        user_ok = hmac.compare_digest(auth.username or "", expected_user)
        password_ok = hmac.compare_digest(auth.password or "", expected_password)
        if not (user_ok and password_ok):
            return _auth_challenge()
        return view(*args, **kwargs)

    return wrapped


def _auth_challenge() -> Response:
    response = Response("Authentication required", status=401)
    response.headers["WWW-Authenticate"] = 'Basic realm="Drain dashboard"'
    return response


def _limited_string(value: Any, default: str, limit: int) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError("must be a string")
    value = value.strip()
    if not value or len(value) > limit:
        raise ValueError("has an invalid length")
    return value


def _validate_payload(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise ValueError("JSON object required")

    project = payload.get("project")
    event = payload.get("event")
    instance_id = payload.get("instance_id")
    event_id = payload.get("event_id") or str(uuid.uuid4())

    if project not in PROJECTS:
        raise ValueError("unknown project")
    if event not in EVENTS:
        raise ValueError("unknown event")
    if not isinstance(instance_id, str):
        raise ValueError("instance_id is required")
    try:
        uuid.UUID(instance_id)
        uuid.UUID(event_id)
    except (ValueError, AttributeError):
        raise ValueError("instance_id and event_id must be UUIDs") from None

    return {
        "project": project,
        "event": event,
        "instance_id": instance_id,
        "event_id": event_id,
        "version": _limited_string(payload.get("version"), "unknown", MAX_VERSION_LENGTH),
        "platform": _limited_string(payload.get("platform"), "unknown", MAX_PLATFORM_LENGTH),
        "runtime": _limited_string(payload.get("runtime"), "unknown", MAX_RUNTIME_LENGTH),
    }


def _instance_hash(instance_id: str, salt: str) -> str:
    return hmac.new(salt.encode("utf-8"), instance_id.encode("utf-8"), hashlib.sha256).hexdigest()


def _article_ip_hash(article: str, ip_address: str, salt: str) -> str:
    message = f"article:{article}\x00ip:{ip_address}".encode("utf-8")
    return hmac.new(salt.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _validate_article(value: Any) -> str:
    if not isinstance(value, str) or not ARTICLE_SLUG.fullmatch(value):
        raise ValueError("article must be a valid slug")
    return value


def _article_ip() -> str:
    # ProxyFix below trusts exactly one reverse proxy. The app is not directly
    # exposed; never accept arbitrary client-supplied forwarding headers here.
    return request.remote_addr or "unknown"


def _article_summary(path: str) -> list[dict[str, Any]]:
    with get_db(path) as conn:
        return [
            dict(row)
            for row in conn.execute(
                """
                SELECT article, COUNT(*) AS unique_readers, SUM(hits) AS total_reads,
                       MAX(last_seen) AS last_read
                FROM article_views GROUP BY article ORDER BY unique_readers DESC, article
                """
            ).fetchall()
        ]


def _summary(path: str, now: datetime) -> dict[str, Any]:
    with get_db(path) as conn:
        total = conn.execute("SELECT COUNT(DISTINCT instance_hash) FROM events").fetchone()[0]
        installs = conn.execute("SELECT COUNT(*) FROM events WHERE event = 'install'").fetchone()[0]
        projects: dict[str, Any] = {}
        for project in sorted(PROJECTS):
            row = conn.execute(
                """
                SELECT
                    COUNT(DISTINCT instance_hash) AS total,
                    COUNT(DISTINCT CASE WHEN created_at >= ? THEN instance_hash END) AS active_7d,
                    COUNT(DISTINCT CASE WHEN created_at >= ? THEN instance_hash END) AS active_30d,
                    COUNT(DISTINCT CASE WHEN created_at >= ? THEN instance_hash END) AS active_90d,
                    COUNT(CASE WHEN event = 'install' THEN 1 END) AS installs,
                    MAX(created_at) AS last_event
                FROM events WHERE project = ?
                """,
                (
                    (now - timedelta(days=7)).isoformat(timespec="seconds"),
                    (now - timedelta(days=30)).isoformat(timespec="seconds"),
                    (now - timedelta(days=90)).isoformat(timespec="seconds"),
                    project,
                ),
            ).fetchone()
            versions = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT version, COUNT(DISTINCT instance_hash) AS instances
                    FROM events WHERE project = ?
                    GROUP BY version ORDER BY instances DESC, version DESC LIMIT 8
                    """,
                    (project,),
                ).fetchall()
            ]
            projects[project] = {**dict(row), "versions": versions}
        recent = [
            dict(row)
            for row in conn.execute(
                """
                SELECT project, event, version, platform, runtime, created_at
                FROM events ORDER BY id DESC LIMIT 20
                """
            ).fetchall()
        ]
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "total_instances": total,
        "total_install_events": installs,
        "projects": projects,
        "articles": _article_summary(path),
        "recent_events": recent,
    }


def _dashboard_html(summary: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else "—"))

    cards = "".join(
        f"<article><span>{esc(name)}</span><strong>{esc(data['active_30d'])}</strong><small>active in 30 days · {esc(data['total'])} total</small></article>"
        for name, data in summary["projects"].items()
    )
    rows = "".join(
        f"<tr><td>{esc(row['project'])}</td><td>{esc(row['event'])}</td><td>{esc(row['version'])}</td><td>{esc(row['platform'])}</td><td>{esc(row['created_at'])}</td></tr>"
        for row in summary["recent_events"]
    ) or '<tr><td colspan="5">No events yet.</td></tr>'
    article_rows = "".join(
        f"<tr><td>{esc(row['article'])}</td><td>{esc(row['unique_readers'])}</td><td>{esc(row['total_reads'])}</td><td>{esc(row['last_read'])}</td></tr>"
        for row in summary["articles"]
    ) or '<tr><td colspan="4">No article reads yet.</td></tr>'
    version_sections = "".join(
        f"<section><h3>{esc(name)}</h3><ul>" + "".join(
            f"<li><code>{esc(v['version'])}</code><span>{esc(v['instances'])} instances</span></li>" for v in data["versions"]
        ) + "</ul></section>"
        for name, data in summary["projects"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Drain · usage</title><style>
:root{{color-scheme:dark;--bg:#101113;--panel:#191b20;--line:#2d3038;--muted:#9da3af;--accent:#8ee3b0}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:#f5f7fa;font:15px/1.5 system-ui,sans-serif}}main{{max-width:1100px;margin:0 auto;padding:44px 22px}}header{{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:26px}}h1,h2,h3,p{{margin-top:0}}h1{{font-size:34px;margin-bottom:4px}}h2{{font-size:18px;margin:34px 0 14px}}.muted,small{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}article,section,.table-wrap{{background:var(--panel);border:1px solid var(--line);border-radius:12px}}article{{padding:18px}}article span,article small{{display:block;color:var(--muted)}}article strong{{display:block;font-size:38px;line-height:1.15;color:var(--accent);margin:8px 0}}.versions{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}section{{padding:16px}}section h3{{margin-bottom:8px}}ul{{list-style:none;padding:0;margin:0}}li{{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:7px 0;color:var(--muted)}}code{{color:#f5f7fa}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:650px}}th,td{{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line)}}th{{color:var(--muted);font-weight:500}}@media(max-width:760px){{.cards,.versions{{grid-template-columns:repeat(2,1fr)}}header{{display:block}}}}@media(max-width:450px){{.cards{{grid-template-columns:1fr 1fr}}article strong{{font-size:29px}}}}
</style></head><body><main><header><div><h1>Drain</h1><p class="muted">Anonymous usage, not user surveillance.</p></div><small>Updated {esc(summary['generated_at'])}</small></header>
<div class="cards">{cards}</div><h2>Articles</h2><div class="table-wrap"><table><thead><tr><th>Article</th><th>Unique readers</th><th>Total reads</th><th>Last read</th></tr></thead><tbody>{article_rows}</tbody></table></div><h2>Versions</h2><div class="versions">{version_sections}</div><h2>Recent events</h2><div class="table-wrap"><table><thead><tr><th>Project</th><th>Event</th><th>Version</th><th>Platform</th><th>Received</th></tr></thead><tbody>{rows}</tbody></table></div></main></body></html>"""


def create_app(config: dict[str, str] | None = None) -> Flask:
    config = config or {}
    db_path = config.get("db_path", os.environ.get("DRAIN_DB_PATH", "/data/drain.sqlite3"))
    admin_user = config.get("admin_user", os.environ.get("DRAIN_ADMIN_USER", "admin"))
    admin_password = config.get("admin_password", os.environ.get("DRAIN_ADMIN_PASSWORD", ""))
    instance_salt = config.get("instance_salt", os.environ.get("DRAIN_INSTANCE_SALT", "development-only-salt"))

    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    app.config.update(db_path=db_path, admin_user=admin_user, admin_password=admin_password, instance_salt=instance_salt)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    init_db(db_path)

    @app.after_request
    def headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path == "/v1/events":
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        elif request.path == "/v1/article-views" and request.headers.get("Origin") == "https://timi.click":
            response.headers["Access-Control-Allow-Origin"] = "https://timi.click"
            response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Vary"] = "Origin"
        return response

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    @app.get("/about")
    def about():
        return Response(
            "Drain receives anonymous install and heartbeat counts for Forest, Nabu, Enkii, and Argus. "
            "Clients generate a random instance ID; the server stores only a one-way hash of it. "
            "Disable reporting with the project's documented usage-reporting opt-out setting or environment variable.",
            mimetype="text/plain",
        )

    @app.route("/v1/events", methods=["OPTIONS"])
    def events_options():
        return Response(status=204)

    @app.post("/v1/events")
    def events():
        payload = request.get_json(silent=True)
        try:
            event = _validate_payload(payload)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        with get_db(db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, project, event, version, instance_hash, platform, runtime, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"], event["project"], event["event"], event["version"],
                    _instance_hash(event["instance_id"], instance_salt), event["platform"],
                    event["runtime"], iso_now(),
                ),
            )
        return Response(status=204)

    @app.route("/v1/article-views", methods=["OPTIONS"])
    def article_views_options():
        return Response(status=204)

    @app.get("/v1/article-views")
    def article_views_count():
        try:
            article = _validate_article(request.args.get("article"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        with get_db(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM article_views WHERE article = ?", (article,)
            ).fetchone()[0]
        return jsonify(article=article, count=count)

    @app.post("/v1/article-views")
    def article_views():
        payload = request.get_json(silent=True) or {}
        try:
            article = _validate_article(payload.get("article"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        now = iso_now()
        ip_hash = _article_ip_hash(article, _article_ip(), instance_salt)
        with get_db(db_path) as conn:
            conn.execute(
                """
                INSERT INTO article_views(article, ip_hash, first_seen, last_seen, hits)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(article, ip_hash) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    hits = article_views.hits + 1
                """,
                (article, ip_hash, now, now),
            )
            count = conn.execute(
                "SELECT COUNT(*) FROM article_views WHERE article = ?", (article,)
            ).fetchone()[0]
        return jsonify(article=article, count=count)

    def require_basic_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            auth = request.authorization
            if not auth or not hmac.compare_digest(auth.username or "", admin_user) or not hmac.compare_digest(auth.password or "", admin_password):
                return _auth_challenge()
            return view(*args, **kwargs)
        return wrapped

    @app.get("/")
    @require_basic_auth
    def dashboard():
        return Response(_dashboard_html(_summary(db_path, utc_now())), mimetype="text/html")

    @app.get("/v1/summary")
    @require_basic_auth
    def summary():
        return jsonify(_summary(db_path, utc_now()))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
