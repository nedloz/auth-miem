"""Сценарии HTTP и гонки на настоящей PostgreSQL в уникальной временной схеме.

TEST_DATABASE_URL=postgresql+asyncpg://... python -m pytest tests/test_email_verification.py
Без TEST_DATABASE_URL интеграционные проверки пропускаются.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app import verification
from app.database import Base, get_db
from app.models import EmailVerification, User
from app.routers import auth, internal
from app.security import get_password_hash, verify_password


@pytest.fixture
def scenario(monkeypatch):
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for PostgreSQL integration tests")
    schema = f"verification_test_{uuid.uuid4().hex}"
    engine = create_async_engine(
        url, poolclass=NullPool, execution_options={"schema_translate_map": {"auth": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            await connection.run_sync(Base.metadata.create_all)

    asyncio.run(setup())
    sent = []

    async def send(recipient, url):
        sent.append((recipient, url))

    monkeypatch.setattr(verification, "send_verification_email", AsyncMock(side_effect=send))
    monkeypatch.setattr(verification, "cache_one_time_token", AsyncMock())
    monkeypatch.setattr(verification, "delete_cached_one_time_token", AsyncMock())
    monkeypatch.setattr(verification.settings, "FRONTEND_BASE_URL", "https://mentor.example.org")
    monkeypatch.setattr(verification.settings, "EMAIL_VERIFY_RESEND_COOLDOWN_SECONDS", 60)

    async def database():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(auth.router, prefix="/auth")
    app.include_router(internal.router, prefix="/internal")
    app.dependency_overrides[get_db] = database

    def client(peer="127.0.0.1"):
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(peer, 10000)), base_url="http://test",
        )

    async def seed_user(**overrides):
        async with sessions() as session:
            user = User(email="student@edu.hse.ru", password_hash=get_password_hash("original-password"), **overrides)
            session.add(user)
            await session.commit()
            return user.id

    async def seed_token(user_id, raw="test-secret", age=0, email="student@edu.hse.ru", used=False):
        async with sessions() as session:
            session.add(EmailVerification(
                user_id=user_id, email=email, token_hash=verification.hash_token(raw),
                created_at=datetime.now(timezone.utc) - timedelta(minutes=age),
                used_at=datetime.now(timezone.utc) if used else None,
            ))
            await session.commit()
        return raw

    yield SimpleNamespace(client=client, sessions=sessions, sent=sent, seed_user=seed_user, seed_token=seed_token)

    async def cleanup():
        async with engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await engine.dispose()

    asyncio.run(cleanup())


def token_from_sent(scenario):
    return parse_qs(urlsplit(scenario.sent[-1][1]).query)["token"][0]


def test_registration_confirmation_and_login(scenario):
    async def run():
        async with scenario.client() as client:
            body = {"email": "student@edu.hse.ru", "password": "original-password"}
            response = await client.post("/auth/register", json=body)
            assert response.status_code == 201, response.text
            assert response.json()["is_email_verified"] is False
            assert len(scenario.sent) == 1
            assert scenario.sent[0][0] == body["email"]
            token = token_from_sent(scenario)
            assert scenario.sent[0][1].startswith("https://mentor.example.org/verify-email?token=")
            async with scenario.sessions() as db:
                record = (await db.execute(select(EmailVerification))).scalar_one()
                assert record.token_hash == verification.hash_token(token)
                assert record.token_hash != token
            assert (await client.post("/auth/login", json=body)).status_code == 403
            response = await client.get("/auth/verify-email", params={"token": token})
            assert response.status_code == 200, response.text
            assert (await client.get("/auth/verify-email", params={"token": token})).status_code == 400
            assert (await client.post("/auth/login", json=body)).status_code == 200
            assert token not in response.text

    asyncio.run(run())


def test_repeat_registration_cannot_replace_password(scenario):
    async def run():
        user_id = await scenario.seed_user()
        async with scenario.client() as client:
            response = await client.post("/auth/register", json={
                "email": "student@edu.hse.ru", "password": "attacker-password",
            })
            assert response.status_code == 400
        async with scenario.sessions() as db:
            user = await db.get(User, user_id)
            assert verify_password("original-password", user.password_hash)
        assert not scenario.sent

    asyncio.run(run())


@pytest.mark.parametrize("reason", ["expired", "used", "inactive", "changed_email", "unknown"])
def test_invalid_link_cannot_verify_user(scenario, reason):
    async def run():
        user_id = await scenario.seed_user(is_active=reason != "inactive")
        token = await scenario.seed_token(
            user_id, age=1441 if reason == "expired" else 0,
            used=reason == "used", email="old@edu.hse.ru" if reason == "changed_email" else "student@edu.hse.ru",
        )
        async with scenario.client() as client:
            response = await client.get("/auth/verify-email", params={"token": "unknown" if reason == "unknown" else token})
            assert response.status_code == 400
            assert response.json()["detail"] == "Invalid or expired token"
        async with scenario.sessions() as db:
            assert (await db.get(User, user_id)).is_email_verified is False

    asyncio.run(run())


@pytest.mark.parametrize("same_token", [True, False])
def test_only_one_parallel_confirmation_succeeds(scenario, same_token):
    async def run():
        user_id = await scenario.seed_user()
        first = await scenario.seed_token(user_id, "first-link")
        second = first if same_token else await scenario.seed_token(user_id, "second-link")
        async with scenario.client() as client:
            results = await asyncio.gather(*[
                client.get("/auth/verify-email", params={"token": token}) for token in (first, second)
            ])
        assert sorted(r.status_code for r in results) == [200, 400]
        async with scenario.sessions() as db:
            records = (await db.execute(select(EmailVerification))).scalars().all()
            assert all(record.used_at is not None for record in records)

    asyncio.run(run())


def test_parallel_resends_send_one_email_with_retry_after(scenario):
    async def run():
        await scenario.seed_user()
        async with scenario.client() as client:
            results = await asyncio.gather(*[
                client.post("/auth/resend-verification", json={"email": "student@edu.hse.ru"}) for _ in range(2)
            ])
        assert sorted(r.status_code for r in results) == [200, 429]
        limited = next(r for r in results if r.status_code == 429)
        assert 1 <= int(limited.headers["Retry-After"]) <= 60
        assert len(scenario.sent) == 1

    asyncio.run(run())


def test_smtp_failure_allows_retry_without_new_registration(scenario, monkeypatch):
    async def broken(*args):
        raise verification.EmailDeliveryError("smtp unavailable")

    async def run():
        sender = verification.send_verification_email
        monkeypatch.setattr(verification, "send_verification_email", broken)
        async with scenario.client() as client:
            response = await client.post("/auth/register", json={"email": "student@edu.hse.ru", "password": "secret-pass"})
            assert response.status_code == 503
            assert "Account created" in response.json()["detail"]
            monkeypatch.setattr(verification, "send_verification_email", sender)
            response = await client.post("/auth/resend-verification", json={"email": "student@edu.hse.ru"})
            assert response.status_code == 200, response.text
            token = token_from_sent(scenario)
            assert (await client.get("/auth/verify-email", params={"token": token})).status_code == 200

    asyncio.run(run())


@pytest.mark.parametrize("state", ["unknown", "verified", "inactive"])
def test_resend_skips_ineligible_accounts_with_generic_response(scenario, state):
    async def run():
        if state != "unknown":
            await scenario.seed_user(is_email_verified=state == "verified", is_active=state != "inactive")
        async with scenario.client() as client:
            response = await client.post("/auth/resend-verification", json={"email": "student@edu.hse.ru"})
        assert response.status_code == 200
        assert "If the account exists" in response.json()["detail"]
        assert not scenario.sent

    asyncio.run(run())


def test_internal_route_sends_only_for_db_service_and_uses_stored_email(scenario):
    async def run():
        user_id = await scenario.seed_user()
        async with scenario.client() as client:
            response = await client.post("/internal/notifications/email-verification", json={"user_id": str(user_id)}, headers={"X-Caller-Identity": "db-svc"})
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "sent"}
        assert scenario.sent[0][0] == "student@edu.hse.ru"

    asyncio.run(run())


@pytest.mark.parametrize("caller,peer", [
    (None, "127.0.0.1"), ("nginx", "127.0.0.1"), ("chat-svc", "127.0.0.1"),
    ("db-svc", "10.0.0.8"),
])
def test_internal_route_rejects_untrusted_callers(scenario, caller, peer):
    async def run():
        async with scenario.client(peer) as client:
            response = await client.post(
                "/internal/notifications/email-verification", json={"user_id": str(uuid.uuid4())},
                headers={"X-Caller-Identity": caller} if caller else {},
            )
        assert response.status_code == 403
        assert not scenario.sent

    asyncio.run(run())


def test_internal_route_rejects_arbitrary_email_and_content(scenario):
    async def run():
        async with scenario.client() as client:
            response = await client.post(
                "/internal/notifications/email-verification",
                json={"user_id": str(uuid.uuid4()), "email": "other@example.org", "html": "arbitrary"},
                headers={"X-Caller-Identity": "db-svc"},
            )
        assert response.status_code == 422
        assert not scenario.sent

    asyncio.run(run())


@pytest.mark.parametrize("state", ["unknown", "verified", "inactive"])
def test_internal_route_skips_ineligible_accounts(scenario, state):
    async def run():
        user_id = uuid.uuid4() if state == "unknown" else await scenario.seed_user(
            is_email_verified=state == "verified", is_active=state != "inactive",
        )
        async with scenario.client() as client:
            response = await client.post(
                "/internal/notifications/email-verification", json={"user_id": str(user_id)},
                headers={"X-Caller-Identity": "db-svc"},
            )
        assert response.status_code == 200
        assert response.json() == {"status": "skipped"}
        assert not scenario.sent

    asyncio.run(run())


def test_failed_resend_does_not_revoke_previously_delivered_link(scenario, monkeypatch):
    async def broken(*args):
        raise verification.EmailDeliveryError("smtp unavailable")

    async def run():
        user_id = await scenario.seed_user()
        token = await scenario.seed_token(user_id, age=2)
        monkeypatch.setattr(verification, "send_verification_email", broken)
        async with scenario.client() as client:
            assert (await client.post("/auth/resend-verification", json={"email": "student@edu.hse.ru"})).status_code == 503
            assert (await client.get("/auth/verify-email", params={"token": token})).status_code == 200

    asyncio.run(run())


def test_concurrent_registrations_do_not_create_duplicate_accounts(scenario):
    async def run():
        async with scenario.client() as client:
            responses = await asyncio.gather(*[
                client.post("/auth/register", json={"email": "student@edu.hse.ru", "password": "secret-pass"})
                for _ in range(2)
            ])
        assert sorted(response.status_code for response in responses) == [201, 400]
        assert len(scenario.sent) == 1
        async with scenario.sessions() as db:
            assert len((await db.execute(select(User))).scalars().all()) == 1

    asyncio.run(run())
