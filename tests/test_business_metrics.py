import asyncio
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pytest  # noqa: E402
from fastapi import HTTPException, Response  # noqa: E402
from prometheus_client import REGISTRY  # noqa: E402

from app import mail  # noqa: E402
from app.routers import auth  # noqa: E402
from app.schemas import UserLogin  # noqa: E402
from app.security import get_password_hash  # noqa: E402


def sample(name: str, **labels) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


class FakeResult:
    def __init__(self, user):
        self._user = user

    def scalars(self):
        return self

    def first(self):
        return self._user


class FakeDB:
    def __init__(self, user=None):
        self.user = user

    async def execute(self, _stmt):
        return FakeResult(self.user)

    def add(self, _obj):
        pass

    async def commit(self):
        pass


def make_user(**overrides):
    fields = dict(
        id="u1", role="student", is_active=True, is_email_verified=True,
        password_hash=get_password_hash("secret-pass"), last_login_at=None,
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


def login(user, password="secret-pass"):
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    return asyncio.run(auth.login(UserLogin(email="a@b.ru", password=password), Response(), request, FakeDB(user)))


def test_login_with_unknown_user_counts_invalid_credentials():
    before = sample("pochemuchnik_logins_total", result="invalid_credentials")
    with pytest.raises(HTTPException) as exc:
        login(None)
    assert exc.value.status_code == 401
    assert sample("pochemuchnik_logins_total", result="invalid_credentials") == before + 1


def test_login_with_wrong_password_counts_invalid_credentials():
    before = sample("pochemuchnik_logins_total", result="invalid_credentials")
    with pytest.raises(HTTPException):
        login(make_user(), password="wrong-password")
    assert sample("pochemuchnik_logins_total", result="invalid_credentials") == before + 1


def test_login_of_deactivated_user_counts_deactivated():
    before = sample("pochemuchnik_logins_total", result="deactivated")
    with pytest.raises(HTTPException) as exc:
        login(make_user(is_active=False))
    assert exc.value.status_code == 403
    assert sample("pochemuchnik_logins_total", result="deactivated") == before + 1


def test_login_with_unverified_email_counts_email_not_verified():
    before = sample("pochemuchnik_logins_total", result="email_not_verified")
    with pytest.raises(HTTPException):
        login(make_user(is_email_verified=False))
    assert sample("pochemuchnik_logins_total", result="email_not_verified") == before + 1


def test_successful_login_counts_success():
    before = sample("pochemuchnik_logins_total", result="success")
    login(make_user())
    assert sample("pochemuchnik_logins_total", result="success") == before + 1


def test_refresh_without_cookie_counts_missing():
    before = sample("pochemuchnik_token_refresh_total", result="missing")
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    with pytest.raises(HTTPException):
        asyncio.run(auth.refresh_tokens(Response(), request, None, FakeDB(None)))
    assert sample("pochemuchnik_token_refresh_total", result="missing") == before + 1


def test_refresh_with_unknown_token_counts_invalid():
    before = sample("pochemuchnik_token_refresh_total", result="invalid")
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={})
    with pytest.raises(HTTPException):
        asyncio.run(auth.refresh_tokens(Response(), request, "no-such-token", FakeDB(None)))
    assert sample("pochemuchnik_token_refresh_total", result="invalid") == before + 1


def test_failed_smtp_counts_failed_email_and_still_raises(monkeypatch):
    def broken(*_args):
        raise mail.EmailDeliveryError("boom")

    monkeypatch.setattr(mail, "_send_email_sync", broken)
    before = sample("pochemuchnik_emails_sent_total", kind="verification", result="failed")
    with pytest.raises(mail.EmailDeliveryError):
        asyncio.run(mail.send_email("a@b.ru", "s", "t", kind="verification"))
    assert sample("pochemuchnik_emails_sent_total", kind="verification", result="failed") == before + 1


def test_sent_email_counts_sent_by_kind(monkeypatch):
    monkeypatch.setattr(mail, "_send_email_sync", lambda *args: None)
    before = sample("pochemuchnik_emails_sent_total", kind="password_reset", result="sent")
    asyncio.run(mail.send_email("a@b.ru", "s", "t", kind="password_reset"))
    assert sample("pochemuchnik_emails_sent_total", kind="password_reset", result="sent") == before + 1
