import tempfile
import uuid
from pathlib import Path

import pytest

from app import create_app


@pytest.fixture()
def client():
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app({
            "db_path": str(Path(tmp) / "drain.sqlite3"),
            "admin_user": "admin",
            "admin_password": "secret",
            "instance_salt": "test-salt",
        })
        app.config.update(TESTING=True)
        with app.test_client() as test_client:
            yield test_client


def event(**overrides):
    payload = {
        "project": "nabu",
        "event": "install",
        "instance_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()),
        "version": "1.2.3",
        "platform": "linux",
        "runtime": "python",
    }
    payload.update(overrides)
    return payload


def auth():
    return {"Authorization": "Basic YWRtaW46c2VjcmV0"}


def test_health_is_public(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json == {"ok": True}


def test_valid_event_is_accepted_and_duplicate_is_idempotent(client):
    payload = event()
    assert client.post("/v1/events", json=payload).status_code == 204
    assert client.post("/v1/events", json=payload).status_code == 204

    summary = client.get("/v1/summary", headers=auth())
    assert summary.status_code == 200
    assert summary.json["total_instances"] == 1
    assert summary.json["total_install_events"] == 1
    assert summary.json["projects"]["nabu"]["active_30d"] == 1


def test_invalid_project_and_instance_are_rejected(client):
    assert client.post("/v1/events", json=event(project="unknown")).status_code == 400
    assert client.post("/v1/events", json=event(instance_id="not-a-uuid")).status_code == 400


def test_dashboard_requires_auth_and_renders_counts(client):
    client.post("/v1/events", json=event())
    assert client.get("/").status_code == 401
    response = client.get("/", headers=auth())
    assert response.status_code == 200
    assert b"Anonymous usage" in response.data
    assert b"nabu" in response.data


def test_article_views_count_unique_ips_without_returning_ip(client):
    headers = {"Origin": "https://timi.click"}
    first = client.post(
        "/v1/article-views", json={"article": "how-i-ship-without-reading-code"},
        headers=headers, environ_base={"REMOTE_ADDR": "203.0.113.10"},
    )
    repeat = client.post(
        "/v1/article-views", json={"article": "how-i-ship-without-reading-code"},
        headers=headers, environ_base={"REMOTE_ADDR": "203.0.113.10"},
    )
    second = client.post(
        "/v1/article-views", json={"article": "how-i-ship-without-reading-code"},
        headers=headers, environ_base={"REMOTE_ADDR": "203.0.113.11"},
    )

    assert first.status_code == 200
    assert first.json == {"article": "how-i-ship-without-reading-code", "count": 1}
    assert repeat.json["count"] == 1
    assert second.json["count"] == 2
    assert "203.0.113" not in first.get_data(as_text=True)


def test_article_views_reject_bad_slugs_and_foreign_origins(client):
    assert client.post("/v1/article-views", json={"article": "../../etc"}).status_code == 400
    response = client.post(
        "/v1/article-views", json={"article": "hello-world"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_forwarded_client_ip_is_taken_from_trusted_proxy(client):
    response = client.post(
        "/v1/article-views", json={"article": "hello-world"},
        headers={"X-Forwarded-For": "203.0.113.12"},
        environ_base={"REMOTE_ADDR": "10.0.0.2"},
    )
    assert response.status_code == 200
    repeat = client.post(
        "/v1/article-views", json={"article": "hello-world"},
        headers={"X-Forwarded-For": "203.0.113.12"},
        environ_base={"REMOTE_ADDR": "10.0.0.2"},
    )
    assert repeat.json["count"] == 1
