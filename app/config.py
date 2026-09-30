from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Конфигурация параметров, связанных с:
    - SMTP;
    - временем жизни auth-токенов;
    - Redis;
    - URL frontend.

    DATABASE_URL, SECRET_KEY и остальные существующие
    настройки проекта здесь специально не дублируются:
    текущий database.py/security.py продолжают работать
    как раньше.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # =========================================================
    # TOKEN LIFETIMES
    # =========================================================

    # 30 дней
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 43200

    # 24 часа
    EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES: int = 1440

    # 1 час
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 60

    # =========================================================
    # FRONTEND
    # =========================================================

    # Публичный URL frontend.
    #
    # В текущем compose по умолчанию nginx слушает localhost:80,
    # поэтому для локального запуска это:
    # http://localhost
    FRONTEND_BASE_URL: str = "http://localhost"

    # =========================================================
    # SMTP
    # =========================================================

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587

    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""

    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False

    EMAIL_FROM: str = ""

    # =========================================================
    # REDIS
    # =========================================================

    # В docker-compose auth-svc уже получает
    # REDIS_URL=redis://redis:6379/0.
    REDIS_URL: str = "redis://redis:6379/0"

    # Минимальный интервал между повторной отправкой
    # verification/reset email.
    EMAIL_SEND_COOLDOWN_SECONDS: int = 60


settings = Settings()
