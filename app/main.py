import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from app.database import engine
from app.redis import close_redis
from app.routers import (
    auth,
    internal,
    profile,
)


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s - "
        "%(levelname)s - "
        "%(message)s"
    ),
)

logger = logging.getLogger(__name__)


# =========================================================
# LIFESPAN
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info(
        "⏳ Пытаемся подключиться "
        "к базе данных PostgreSQL..."
    )

    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("SELECT 1")
            )

        logger.info(
            "✅ Успешное подключение к БД!"
        )

    except Exception as e:
        logger.error(
            "❌ Не удалось подключиться к БД! "
            f"Ошибка: {e}"
        )

        logger.warning(
            "⚠️ Приложение запущено, "
            "но запросы к БД будут выдавать "
            "ошибки, пока база не поднимется."
        )

    yield

    # =====================================================
    # SHUTDOWN
    # =====================================================

    logger.info(
        "🛑 Завершение работы auth-svc..."
    )

    await engine.dispose()

    await close_redis()

    logger.info(
        "✅ Соединения PostgreSQL и Redis закрыты."
    )


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title="Auth Service",
    description=(
        "Микросервис авторизации "
        "(REST API)"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# =========================================================
# ROUTERS
# =========================================================

app.include_router(
    auth.router,
    prefix="/auth",
    tags=["Auth"],
)

app.include_router(
    profile.router,
    prefix="/users",
    tags=["Profile"],
)

app.include_router(
    internal.router,
    prefix="/internal",
    tags=["Internal"],
)


# =========================================================
# HEALTH
# =========================================================

@app.get(
    "/health",
    tags=["System"],
)
async def health_check():
    return {
        "status": "ok",
        "service": "auth",
    }
