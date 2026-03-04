import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlalchemy import text

# Импортируем роутеры и движок БД
from app.routers import auth
from app.routers import profile
from app.database import engine

# Настраиваем красивый вывод логов в консоль
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Механизм lifespan выполняется один раз при запуске (и остановке) приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("⏳ Пытаемся подключиться к базе данных PostgreSQL...")
    try:
        # Пробуем открыть соединение и выполнить простейший запрос
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("✅ Успешное подключение к базе данных!")
    except Exception as e:
        # Перехватываем любую ошибку (неверный пароль, хост недоступен и т.д.)
        logger.error(f"❌ Не удалось подключиться к БД! Ошибка: {e}")
        logger.warning("⚠️ Приложение запущено, но запросы к БД будут выдавать ошибку 500, пока база не поднимется.")
        # Заметь: мы не делаем raise e, поэтому uvicorn не упадет

    yield # Здесь приложение начинает обрабатывать входящие HTTP-запросы
    
    # Этот блок выполнится при остановке контейнера
    logger.info("🛑 Завершение работы. Закрываем соединения с БД...")
    await engine.dispose()

# Создаем само приложение FastAPI, передавая ему наш lifespan
app = FastAPI(
    title="Auth Service",
    description="Микросервис авторизации (REST API)",
    version="1.0.0",
    lifespan=lifespan
)

# Подключаем наши роуты
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(profile.router, prefix="/users", tags=["Profile"])

# Эндпоинт для проверки жизнеспособности (Health Check)
@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "auth"}
