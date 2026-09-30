import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings


class EmailDeliveryError(RuntimeError):
    """
    Ошибка отправки письма.

    Выделяем её отдельно, чтобы auth-роуты могли
    отличать проблемы SMTP от обычных ошибок БД.
    """


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
) -> None:
    """
    Запускаем синхронный smtplib вне event loop.
    """

    await asyncio.to_thread(
        _send_email_sync,
        recipient,
        subject,
        text_body,
        html_body,
    )


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

    subject, text_body, html_body = (
        _verification_email_content(
            verification_url
        )
    )

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
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

    subject, text_body, html_body = (
        _password_reset_email_content(
            reset_url
        )
    )

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )
