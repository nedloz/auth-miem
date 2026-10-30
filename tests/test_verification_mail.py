import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app import mail
from app.config import Settings


@pytest.fixture
def template_db(monkeypatch):
    session = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = session
    monkeypatch.setattr(mail, "AsyncSessionLocal", lambda: context)

    def set_template(subject, body):
        from unittest.mock import Mock

        result = Mock()
        result.first.return_value = SimpleNamespace(subject_template=subject, body_html=body)
        session.execute.return_value = result

    return set_template, session


@pytest.mark.parametrize("event,variable", [
    ("email_verification", "verification_url"),
    ("password_reset", "reset_url"),
])
def test_database_template_has_safe_html_and_plain_text_link(template_db, event, variable):
    set_template, _ = template_db
    set_template("Письмо", f'<p>Нажмите <a href="{{{variable}}}">сюда</a></p>')
    url = 'https://example.org/action?token=abc&next="quoted"'
    result = asyncio.run(mail._customized_content(event, ("default", "text", "html"), **{variable: url}))
    assert result[0] == "Письмо"
    assert '&amp;next=&quot;quoted&quot;' in result[2]
    assert url in result[1]
    assert "Нажмите" in result[1]


@pytest.mark.parametrize("subject,body", [
    ("Письмо", ""),
    ("", '<a href="{verification_url}">Подтвердить</a>'),
    ("Письмо", "<p>Ссылку забыли</p>"),
    ("Письмо", '<a href="{verificaton_url}">Опечатка</a>'),
    ("Письмо", '<a href="{verification_url}">{unknown}</a>'),
    ("Письмо\nBcc: other@example.org", '<a href="{verification_url}">Ссылка</a>'),
    ("Письмо", '<a href="https://wrong.example/">{verification_url}</a>'),
])
def test_broken_database_template_falls_back_without_logging_token(template_db, caplog, subject, body):
    set_template, _ = template_db
    set_template(subject, body)
    fallback = ("default subject", "default text", "default html")
    result = asyncio.run(mail._customized_content(
        "email_verification", fallback, verification_url="https://example.org/?token=secret-token",
    ))
    assert result == fallback
    assert "secret-token" not in caplog.text


def test_database_outage_uses_builtin_verification_email(template_db, monkeypatch):
    _, session = template_db
    session.execute.side_effect = RuntimeError("database unavailable")
    send = AsyncMock()
    monkeypatch.setattr(mail, "send_email", send)
    url = "https://example.org/verify-email?token=one-time-secret"
    asyncio.run(mail.send_verification_email("a@b.ru", url))
    message = send.call_args.kwargs
    assert url in message["text_body"]
    assert f'href="{url}"' in message["html_body"]
    assert message["kind"] == "verification"


def test_verification_smtp_message_is_multipart(template_db, monkeypatch):
    set_template, _ = template_db
    set_template("Подтвердите почту", '<a href="{verification_url}">Подтвердить</a>')
    from unittest.mock import MagicMock

    smtp_factory = MagicMock()
    smtp = smtp_factory.return_value.__enter__.return_value
    monkeypatch.setattr(mail.smtplib, "SMTP", smtp_factory)
    for key, value in {
        "SMTP_HOST": "smtp.test", "SMTP_USER": "test", "SMTP_PASSWORD": "test",
        "EMAIL_FROM": "sender@example.org", "SMTP_USE_SSL": False, "SMTP_USE_TLS": True,
    }.items():
        monkeypatch.setattr(mail.settings, key, value)
    asyncio.run(mail.send_verification_email("recipient@example.org", "https://example.org/verify-email?token=secret"))
    message = smtp.send_message.call_args.args[0]
    assert message["To"] == "recipient@example.org"
    assert message["Subject"] == "Подтвердите почту"
    assert message.get_body(preferencelist=("plain",)).get_content_type() == "text/plain"
    assert message.get_body(preferencelist=("html",)).get_content_type() == "text/html"
    smtp.starttls.assert_called_once()


@pytest.mark.parametrize("value", [
    "javascript:alert(1)", "https://user:pass@example.org", "https://example.org/?token=x",
    "https://example.org/#fragment", "https://example.org/\r\nInjected", "example.org",
])
def test_bad_frontend_url_is_rejected(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, FRONTEND_BASE_URL=value)


def test_verification_url_supports_frontend_path(monkeypatch):
    from app.verification import build_frontend_url

    monkeypatch.setattr(mail.settings, "FRONTEND_BASE_URL", "https://example.org/app/")
    assert build_frontend_url("/verify-email", "a+b&c") == "https://example.org/app/verify-email?token=a%2Bb%26c"
