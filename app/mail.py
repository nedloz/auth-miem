import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings


class EmailDeliveryError(RuntimeError):
    """
    Ошибка отправки письма через SMTP.
    """


def _validate_smtp_settings() -> None:
    """
    Проверяем SMTP-конфигурацию непосредственно перед отправкой.

    Для локального SMTP-сервера вроде Mailpit authentication
    может отсутствовать.

    Если SMTP_USER задан, SMTP_PASSWORD тоже должен быть задан.
    """

    if not settings.SMTP_HOST:
        raise EmailDeliveryError(
            "SMTP_HOST is not configured"
        )

    if not settings.EMAIL_FROM:
        raise EmailDeliveryError(
            "EMAIL_FROM is not configured"
        )

    if (
        settings.SMTP_USE_TLS
        and settings.SMTP_USE_SSL
    ):
        raise EmailDeliveryError(
            "SMTP_USE_TLS and SMTP_USE_SSL "
            "cannot both be enabled"
        )

    if bool(settings.SMTP_USER) != bool(
        settings.SMTP_PASSWORD
    ):
        raise EmailDeliveryError(
            "SMTP_USER and SMTP_PASSWORD "
            "must be specified together"
        )


def _send_email_sync(
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> None:
    """
    Синхронная SMTP-отправка.

    Вызов идёт через asyncio.to_thread(),
    поэтому smtplib не блокирует event loop FastAPI.
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

    ssl_context = ssl.create_default_context()

    try:
        # =====================================================
        # SMTPS
        # =====================================================

        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                timeout=20,
                context=ssl_context,
            ) as smtp:

                if settings.SMTP_USER:
                    smtp.login(
                        settings.SMTP_USER,
                        settings.SMTP_PASSWORD,
                    )

                smtp.send_message(message)

            return

        # =====================================================
        # SMTP + STARTTLS
        # =====================================================

        with smtplib.SMTP(
            settings.SMTP_HOST,
            settings.SMTP_PORT,
            timeout=20,
        ) as smtp:

            smtp.ehlo()

            if settings.SMTP_USE_TLS:
                smtp.starttls(
                    context=ssl_context
                )
                smtp.ehlo()

            if settings.SMTP_USER:
                smtp.login(
                    settings.SMTP_USER,
                    settings.SMTP_PASSWORD,
                )

            smtp.send_message(message)

    except (
        OSError,
        smtplib.SMTPException,
    ) as exc:
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
    Асинхронная обёртка над smtplib.
    """

    await asyncio.to_thread(
        _send_email_sync,
        recipient,
        subject,
        text_body,
        html_body,
    )


# =========================================================
# VERIFICATION EMAIL
# =========================================================

async def send_verification_email(
    recipient: str,
    verification_url: str,
) -> None:
    subject = "Подтверждение электронной почты"

    text_body = f"""
Здравствуйте!

Для подтверждения электронной почты перейдите по ссылке:

{verification_url}

Ссылка действует ограниченное время.

Если вы не регистрировались в системе,
просто проигнорируйте это письмо.
""".strip()

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Подтверждение электронной почты</title>
</head>

<body>
    <h2>Подтверждение электронной почты</h2>

    <p>
        Для подтверждения электронной почты
        перейдите по ссылке:
    </p>

    <p>
        <a href="{verification_url}">
            Подтвердить электронную почту
        </a>
    </p>

    <p>
        Ссылка действует ограниченное время.
    </p>

    <p>
        Если вы не регистрировались в системе,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
""".strip()

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


# =========================================================
# PASSWORD RESET EMAIL
# =========================================================

async def send_password_reset_email(
    recipient: str,
    reset_url: str,
) -> None:
    subject = "Сброс пароля"

    text_body = f"""
Здравствуйте!

Для смены пароля перейдите по ссылке:

{reset_url}

Ссылка действует ограниченное время.

Если вы не запрашивали сброс пароля,
просто проигнорируйте это письмо.
""".strip()

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Сброс пароля</title>
</head>

<body>
    <h2>Сброс пароля</h2>

    <p>
        Для смены пароля перейдите по ссылке:
    </p>

    <p>
        <a href="{reset_url}">
            Сбросить пароль
        </a>
    </p>

    <p>
        Ссылка действует ограниченное время.
    </p>

    <p>
        Если вы не запрашивали сброс пароля,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
""".strip()

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )        settings.SMTP_USE_TLS
        and settings.SMTP_USE_SSL
    ):
        raise EmailDeliveryError(
            "SMTP_USE_TLS and SMTP_USE_SSL "
            "cannot both be enabled"
        )

    if bool(settings.SMTP_USER) != bool(
        settings.SMTP_PASSWORD
    ):
        raise EmailDeliveryError(
            "SMTP_USER and SMTP_PASSWORD "
            "must be specified together"
        )


def _send_email_sync(
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> None:
    """
    Синхронная отправка email через smtplib.

    FastAPI работает асинхронно, поэтому эта функция
    вызывается через asyncio.to_thread().
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

    ssl_context = ssl.create_default_context()

    try:
        # -----------------------------------------------------
        # SMTPS
        # -----------------------------------------------------

        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                timeout=20,
                context=ssl_context,
            ) as smtp:

                if settings.SMTP_USER:
                    smtp.login(
                        settings.SMTP_USER,
                        settings.SMTP_PASSWORD,
                    )

                smtp.send_message(message)

            return

        # -----------------------------------------------------
        # SMTP
        # -----------------------------------------------------

        with smtplib.SMTP(
            settings.SMTP_HOST,
            settings.SMTP_PORT,
            timeout=20,
        ) as smtp:

            smtp.ehlo()

            if settings.SMTP_USE_TLS:
                smtp.starttls(
                    context=ssl_context
                )
                smtp.ehlo()

            if settings.SMTP_USER:
                smtp.login(
                    settings.SMTP_USER,
                    settings.SMTP_PASSWORD,
                )

            smtp.send_message(message)

    except (
        OSError,
        smtplib.SMTPException,
    ) as exc:
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
    Асинхронная обёртка над smtplib.
    """

    await asyncio.to_thread(
        _send_email_sync,
        recipient,
        subject,
        text_body,
        html_body,
    )


# =========================================================
# VERIFICATION EMAIL
# =========================================================

async def send_verification_email(
    recipient: str,
    verification_url: str,
) -> None:
    """
    Отправка письма подтверждения email.
    """

    subject = "Подтверждение электронной почты"

    text_body = f"""
Здравствуйте!

Для подтверждения электронной почты перейдите по ссылке:

{verification_url}

Ссылка действует ограниченное время.

Если вы не регистрировались в системе,
просто проигнорируйте это письмо.
""".strip()

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Подтверждение электронной почты</title>
</head>

<body>
    <h2>Подтверждение электронной почты</h2>

    <p>
        Для подтверждения электронной почты
        перейдите по ссылке:
    </p>

    <p>
        <a href="{verification_url}">
            Подтвердить электронную почту
        </a>
    </p>

    <p>
        Ссылка действует ограниченное время.
    </p>

    <p>
        Если вы не регистрировались в системе,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
""".strip()

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )


# =========================================================
# PASSWORD RESET EMAIL
# =========================================================

async def send_password_reset_email(
    recipient: str,
    reset_url: str,
) -> None:
    """
    Отправка письма для восстановления пароля.
    """

    subject = "Сброс пароля"

    text_body = f"""
Здравствуйте!

Для смены пароля перейдите по ссылке:

{reset_url}

Ссылка действует ограниченное время.

Если вы не запрашивали сброс пароля,
просто проигнорируйте это письмо.
""".strip()

    html_body = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Сброс пароля</title>
</head>

<body>
    <h2>Сброс пароля</h2>

    <p>
        Для смены пароля перейдите по ссылке:
    </p>

    <p>
        <a href="{reset_url}">
            Сбросить пароль
        </a>
    </p>

    <p>
        Ссылка действует ограниченное время.
    </p>

    <p>
        Если вы не запрашивали сброс пароля,
        просто проигнорируйте это письмо.
    </p>
</body>
</html>
""".strip()

    await send_email(
        recipient=recipient,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )        raise EmailDeliveryError(
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
