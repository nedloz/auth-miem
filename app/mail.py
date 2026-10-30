import asyncio
import html
import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from html.parser import HTMLParser

from sqlalchemy import text

from app.metrics import EMAILS_SENT
from app.config import settings
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """
    Ошибка отправки письма.

    Выделяем её отдельно, чтобы auth-роуты могли
    отличать проблемы SMTP от обычных ошибок БД.
    """


_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")
_BLOCK_TAGS = {"p", "div", "br", "h1", "h2", "h3", "h4", "li", "tr", "table"}
_ACTION_URLS = {"email_verification": "verification_url", "password_reset": "reset_url"}


class _ActionLinkParser(HTMLParser):
    def __init__(self, url: str) -> None:
        super().__init__()
        self.url = url
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag == "a" and dict(attrs).get("href") == self.url:
            self.found = True


class _HtmlToText(HTMLParser):
    """Текстовая часть письма из HTML: ссылки остаются видимыми, блоки — отдельными строками."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._href: str | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "title"):
            self._skip += 1
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a":
            self._href = dict(attrs).get("href")

    def handle_endtag(self, tag):
        if tag in ("style", "script", "title"):
            self._skip = max(0, self._skip - 1)
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "a" and self._href:
            self.parts.append(f" ({self._href})")
            self._href = None

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html_body: str) -> str:
    parser = _HtmlToText()
    parser.feed(html_body)
    lines = (re.sub(r"[ \t]+", " ", line).strip() for line in "".join(parser.parts).splitlines())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


def render_template(template: str, values: dict[str, str], *, escape: bool) -> str:
    """Подставляет {имя} только из values; прочие фигурные скобки (CSS и т.п.) не трогает."""
    return _PLACEHOLDER_RE.sub(
        lambda m: (html.escape(values[m.group(1)], quote=True) if escape else values[m.group(1)])
        if m.group(1) in values
        else m.group(0),
        template,
    )


async def _customized_content(
    event_type: str,
    default: tuple[str, str, str],
    **values: str,
) -> tuple[str, str, str]:
    """Текст письма, отредактированный в админке (core.email_templates).

    Любой сбой чтения или пустая строка — не повод не отправить письмо о смене пароля или
    подтверждении почты, поэтому тогда уходит встроенный текст.
    """
    try:
        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT subject_template, body_html FROM core.email_templates "
                        "WHERE event_type = :event_type"
                    ),
                    {"event_type": event_type},
                )
            ).first()
    except Exception:
        logger.exception("Не удалось прочитать шаблон письма %s, отправляется встроенный текст", event_type)
        return default
    if row is None or not (row.subject_template or "").strip() or not (row.body_html or "").strip():
        return default

    subject = render_template(row.subject_template, values, escape=False)
    html_body = render_template(row.body_html, values, escape=True)
    unknown = (
        set(_PLACEHOLDER_RE.findall(row.subject_template + row.body_html))
        - values.keys()
    )
    action_variable = _ACTION_URLS.get(event_type)
    valid_link = True
    if action_variable is not None:
        parser = _ActionLinkParser(values[action_variable])
        parser.feed(html_body)
        valid_link = parser.found
    if unknown or "\r" in subject or "\n" in subject or not valid_link:
        # Не отправляем письмо с опечаткой в переменной, без кнопки действия или
        # с переносом строки в теме. Не логируем содержимое письма и секретную ссылку.
        logger.warning("Некорректный шаблон %s, отправляется встроенный текст", event_type)
        return default
    return subject, html_to_text(html_body), html_body


def _validate_smtp_settings() -> None:
    """
    Проверяем SMTP-конфигурацию перед отправкой.
    """

    required = {
        "SMTP_HOST": settings.SMTP_HOST,
        "SMTP_USER": settings.SMTP_USER,
        "SMTP_PASSWORD": settings.SMTP_PASSWORD,
        "EMAIL_FROM": settings.EMAIL_FROM,
    }

    missing = [
        name
        for name, value in required.items()
        if not value
    ]

    if missing:
        raise EmailDeliveryError(
            "SMTP is not configured. Missing: "
            + ", ".join(missing)
        )

    if settings.SMTP_USE_SSL and settings.SMTP_USE_TLS:
        raise EmailDeliveryError(
            "SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled"
        )


def _send_email_sync(
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> None:
    """
    Синхронная SMTP-отправка.

    smtplib синхронный, поэтому наружу этот код вызывается
    через asyncio.to_thread().
    """

    _validate_smtp_settings()

    message = EmailMessage()

    message["From"] = settings.EMAIL_FROM
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(text_body)

    if html_body:
        message.add_alternative(
            html_body,
            subtype="html",
        )

    context = ssl.create_default_context()

    try:
        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                timeout=20,
                context=context,
            ) as smtp:
                smtp.login(
                    settings.SMTP_USER,
                    settings.SMTP_PASSWORD,
                )
                smtp.send_message(message)

            return

        with smtplib.SMTP(
            settings.SMTP_HOST,
            settings.SMTP_PORT,
            timeout=20,
        ) as smtp:

            smtp.ehlo()

            if settings.SMTP_USE_TLS:
                smtp.starttls(context=context)
                smtp.ehlo()

            smtp.login(
                settings.SMTP_USER,
                settings.SMTP_PASSWORD,
            )

            smtp.send_message(message)

    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError(
            "Failed to send email"
        ) from exc


async def send_email(
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    *,
    kind: str = "other",
) -> None:
    """
    Запускаем синхронный smtplib вне event loop.

    kind попадает в метрику отправленных писем (verification, password_reset).
    """

    try:
        await asyncio.to_thread(
            _send_email_sync,
            recipient,
            subject,
            text_body,
            html_body,
        )
    except Exception:
        EMAILS_SENT.labels(kind=kind, result="failed").inc()
        raise
    EMAILS_SENT.labels(kind=kind, result="sent").inc()


def _verification_email_content(
    verification_url: str,
) -> tuple[str, str, str]:
    """
    Формируем subject + text + HTML для verification email.
    """

    subject = "Подтверждение электронной почты"

    text_body = f"""Здравствуйте!

Для подтверждения адреса электронной почты перейдите по ссылке:

{verification_url}

Ссылка действует ограниченное время.

Если вы не регистрировались в системе, просто проигнорируйте это письмо.
"""

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>{subject}</title>
</head>
<body>
    <h2>Подтверждение электронной почты</h2>

    <p>
        Для подтверждения адреса электронной почты
        нажмите на кнопку ниже.
    </p>

    <p>
        <a
            href="{verification_url}"
            style="
                display:inline-block;
                padding:12px 20px;
                background:#2563eb;
                color:#ffffff;
                text-decoration:none;
                border-radius:6px;
            "
        >
            Подтвердить почту
        </a>
    </p>

    <p>
        Если вы не регистрировались в системе,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
"""

    return subject, text_body, html_body


async def send_verification_email(
    recipient: str,
    verification_url: str,
) -> None:
    """
    Отправляет письмо подтверждения.
    """

    subject, text_body, html_body = await _customized_content(
        "email_verification",
        _verification_email_content(verification_url),
        verification_url=verification_url,
    )

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        kind="verification",
    )


def _password_reset_email_content(
    reset_url: str,
) -> tuple[str, str, str]:
    """
    Формируем письмо сброса пароля.
    """

    subject = "Сброс пароля"

    text_body = f"""Здравствуйте!

Для смены пароля перейдите по ссылке:

{reset_url}

Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.
"""

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>{subject}</title>
</head>
<body>
    <h2>Сброс пароля</h2>

    <p>
        Для создания нового пароля нажмите на кнопку ниже.
    </p>

    <p>
        <a
            href="{reset_url}"
            style="
                display:inline-block;
                padding:12px 20px;
                background:#2563eb;
                color:#ffffff;
                text-decoration:none;
                border-radius:6px;
            "
        >
            Сбросить пароль
        </a>
    </p>

    <p>
        Если вы не запрашивали сброс пароля,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
"""

    return subject, text_body, html_body


async def send_password_reset_email(
    recipient: str,
    reset_url: str,
) -> None:
    """
    Отправляет письмо восстановления пароля.
    """

    subject, text_body, html_body = await _customized_content(
        "password_reset",
        _password_reset_email_content(reset_url),
        reset_url=reset_url,
    )

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        kind="password_reset",
    )
