"""Метрики Prometheus: HTTP-метрики приложения и бизнес-метрики сервиса.

/metrics отдаёт только prometheus (политика прокси, infra/mtls/*.conf); наружу через шлюз его
нет. HTTP-метрики группируются по шаблону маршрута, а не по реальному пути, поэтому число
значений метки handler ограничено числом маршрутов.
"""

from fastapi import FastAPI
from prometheus_client import Counter
from prometheus_fastapi_instrumentator import Instrumentator


def setup_metrics(app: FastAPI) -> None:
    """Подключает сбор HTTP-метрик и маршрут GET /metrics."""
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/metrics"],
    )
    instrumentator.instrument(app).expose(app, include_in_schema=False, should_gzip=False)


REGISTRATIONS = Counter(
    "pochemuchnik_registrations_total",
    "Созданные учётные записи",
)
LOGINS = Counter(
    "pochemuchnik_logins_total",
    "Попытки входа по результату",
    ["result"],  # success | invalid_credentials | deactivated | email_not_verified
)
TOKEN_REFRESH = Counter(
    "pochemuchnik_token_refresh_total",
    "Обновления токена по результату",
    ["result"],  # success | missing | invalid | revoked | expired | user_inactive
)
EMAILS_SENT = Counter(
    "pochemuchnik_emails_sent_total",
    "Письма по виду и результату",
    ["kind", "result"],  # kind: verification | password_reset; result: sent | failed
)
ADMIN_SESSIONS = Counter(
    "pochemuchnik_admin_sessions_total",
    "Открытые сессии админ-панели",
)
