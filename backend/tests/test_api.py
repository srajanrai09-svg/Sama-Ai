import asyncio
from contextlib import asynccontextmanager
import re
import shutil
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pgvector.sqlalchemy import Vector
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main


@asynccontextmanager
async def test_lifespan(app):
    yield


@compiles(Vector, "sqlite")
def compile_vector_sqlite(type_, compiler, **kwargs):
    return "TEXT"


@pytest.fixture
def test_app(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    main.Base.metadata.create_all(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)

    def override_db():
        with session_factory() as session:
            yield session

    main.app.dependency_overrides[main.get_db] = override_db
    monkeypatch.setattr(main.settings, "jwt_secret", "test-secret-that-is-long-enough-123456789")
    upload_root = Path(__file__).resolve().parents[1] / ".test-uploads" / uuid4().hex
    monkeypatch.setattr(main.settings, "upload_dir", str(upload_root))
    monkeypatch.setattr(main.settings, "max_upload_mb", 1)
    monkeypatch.setattr(main.app.router, "lifespan_context", test_lifespan)
    yield main.app, session_factory
    shutil.rmtree(upload_root, ignore_errors=True)
    main.app.dependency_overrides.clear()
    engine.dispose()


def test_login_protection_and_refresh_cookie(test_app):
    app, sessions = test_app
    with sessions() as db:
        db.add(main.Officer(id="officer-1", email="officer@example.gov.in", password_hash=main.password_hasher.hash("correct-horse-battery"), role="officer"))
        db.commit()
    with TestClient(app) as client:
        assert client.get("/api/cases").status_code == 401
        bad = client.post("/api/auth/login", json={"email": "officer@example.gov.in", "password": "wrong"})
        assert bad.status_code == 401
        good = client.post("/api/auth/login", json={"email": "OFFICER@example.gov.in", "password": "correct-horse-battery"})
        assert good.status_code == 200
        assert "httponly" in good.headers.get("set-cookie", "").lower()
        assert client.get("/api/auth/me").json()["role"] == "officer"
        assert client.post("/api/auth/refresh").status_code == 200


def test_staff_access_request_requires_admin_review_and_invitation(test_app, monkeypatch):
    app, sessions = test_app
    monkeypatch.setattr(main.settings, "gov_email_domains", ".gov.in,.nic.in")
    with sessions() as db:
        db.add(main.Officer(id="admin-1", email="admin@example.gov.in", password_hash=main.password_hasher.hash("admin-test-password"), role="admin"))
        db.commit()
    with TestClient(app) as applicant:
        request = applicant.post("/api/auth/staff-access-requests", json={"fullName":"Asha Rao", "email":"asha@department.gov.in", "department":"Revenue Department", "position":"Case Officer", "reason":"I need to review applications assigned to my department."})
        assert request.status_code == 202
        assert applicant.get("/api/admin/staff-access-requests").status_code == 401
        assert applicant.post("/api/auth/staff-access-requests", json={"fullName":"Asha Rao", "email":"asha@gmail.com", "department":"Revenue Department", "position":"Case Officer", "reason":"I need to review applications assigned to my department."}).status_code == 422
    with TestClient(app) as admin:
        assert admin.post("/api/auth/login", json={"email":"admin@example.gov.in", "password":"admin-test-password"}).status_code == 200
        rows = admin.get("/api/admin/staff-access-requests").json()
        assert len(rows) == 1 and rows[0]["status"] == "Pending"
        reviewed = admin.patch(f"/api/admin/staff-access-requests/{rows[0]['id']}/review", json={"status":"Approved", "note":"Department confirmed"})
        assert reviewed.status_code == 200
        invitation = reviewed.json()["invitationToken"]
    with TestClient(app) as invited:
        accepted = invited.post("/api/auth/staff-invitations/accept", json={"email":"asha@department.gov.in", "token":invitation, "password":"a-long-secure-password"})
        assert accepted.status_code == 200
        assert accepted.json()["role"] == "officer"
        assert invited.get("/api/auth/me").json()["email"] == "asha@department.gov.in"
        assert invited.post("/api/auth/staff-invitations/accept", json={"email":"asha@department.gov.in", "token":invitation, "password":"a-long-secure-password"}).status_code == 400


def test_guest_isolation_and_status_update(test_app):
    app, _ = test_app
    first, second = TestClient(app), TestClient(app)
    assert first.post("/api/auth/guest").status_code == 200
    own = first.get("/api/cases").json()
    assert len(own) == 2
    assert own[0]["citizen"].startswith("Guest example:")
    assert second.post("/api/auth/guest").status_code == 200
    other = second.get("/api/cases").json()
    assert {case["id"] for case in own}.isdisjoint({case["id"] for case in other})
    updated = first.patch(f"/api/cases/{own[0]['id']}/status", json={"status": "Completed"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "Completed"
    assert second.get(f"/api/cases/{own[0]['id']}").status_code == 404


def test_upload_limit_and_content_validation(test_app):
    app, _ = test_app
    client = TestClient(app)
    client.post("/api/auth/guest")
    case_id = client.get("/api/cases").json()[0]["id"]
    too_large = client.post(f"/api/cases/{case_id}/documents", files={"file": ("big.pdf", b"%PDF-" + b"x" * (1024 * 1024), "application/pdf")})
    assert too_large.status_code == 413
    wrong_type = client.post(f"/api/cases/{case_id}/documents", files={"file": ("wrong.pdf", b"not a pdf", "application/pdf")})
    assert wrong_type.status_code == 415


def test_chat_stream_when_model_available_and_missing(test_app, monkeypatch):
    app, _ = test_app
    monkeypatch.setattr(main, "embed", lambda _text: asyncio.sleep(0, result=None))
    original_client = main.httpx.AsyncClient

    def available_client(*args, **kwargs):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'{"message":{"content":"Use the sample notice."}}\n{"done":true}\n'))
        return original_client(transport=transport, *args, **kwargs)

    client = TestClient(app)
    client.post("/api/auth/guest")
    case_id = client.get("/api/cases").json()[0]["id"]
    monkeypatch.setattr(main.httpx, "AsyncClient", available_client)
    available = client.post("/api/assistant/stream", json={"question": "What does the sample notice say?", "caseId": case_id})
    assert available.status_code == 200
    assert "Use the sample notice." in available.text
    assert "event: sources" in available.text
    assert "Guest sandbox notice" in available.text

    def unavailable_client(*args, **kwargs):
        return original_client(transport=httpx.MockTransport(lambda request: httpx.Response(404)), *args, **kwargs)

    monkeypatch.setattr(main.httpx, "AsyncClient", unavailable_client)
    missing = client.post("/api/assistant/stream", json={"question": "Is Ollama ready?", "caseId": case_id})
    assert missing.status_code == 200
    assert "AI model is still downloading" in missing.text


def test_citizen_otp_submission_and_private_case_scope(test_app, capsys):
    app, sessions = test_app
    with sessions() as db:
        db.add(main.ServiceDefinition(id="income-certificate", name="Income Certificate", category="Certificates", description="Confirm requirements with the department.", requirements_json="[]", fee="", timeline="", source_url="", verified=False))
        db.add(main.Officer(id="officer-citizen-test", email="officer@example.gov.in", password_hash=main.password_hasher.hash("secure-test-password"), role="officer"))
        db.commit()
    first, second, officer = TestClient(app), TestClient(app), TestClient(app)
    requested = first.post("/api/auth/citizen/request-otp", json={"phone": "+919876543210"})
    assert requested.status_code == 200
    code = re.search(r"Mock OTP for .*: (\d{6})", capsys.readouterr().out).group(1)
    verified = first.post("/api/auth/citizen/verify-otp", json={"phone": "+919876543210", "code": code, "name": "Citizen One", "language": "en"})
    assert verified.status_code == 200
    submitted = first.post("/api/citizen/requests", json={"serviceId": "income-certificate", "district": "Mysuru", "name": "Citizen One", "summary": "Please review my request", "consent": True})
    assert submitted.status_code == 201
    case_id = submitted.json()["id"]
    assert "source" not in submitted.json()
    with sessions() as db:
        assert db.get(main.Case, case_id).source == "Citizen portal"
    assert first.get(f"/api/cases/{case_id}").status_code == 200
    assert first.get(f"/api/cases/{case_id}/messages").status_code == 200
    assert second.post("/api/auth/citizen/request-otp", json={"phone": "+919876543211"}).status_code == 200
    code2 = re.search(r"Mock OTP for .*: (\d{6})", capsys.readouterr().out).group(1)
    assert second.post("/api/auth/citizen/verify-otp", json={"phone": "+919876543211", "code": code2}).status_code == 200
    assert second.get(f"/api/cases/{case_id}").status_code == 404
    assert second.get(f"/api/cases/{case_id}/messages").status_code == 404
    signed_in = officer.post("/api/auth/login", json={"email": "officer@example.gov.in", "password": "secure-test-password"})
    assert signed_in.status_code == 200
    assert any(row["id"] == case_id for row in officer.get("/api/cases").json())
