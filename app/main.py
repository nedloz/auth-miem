from fastapi import FastAPI
from app.api.routes import auth, users
from app.db.session import engine
from app.db.base import Base

# Ensure models are imported so metadata is populated
from app import models  # noqa: F401

app = FastAPI(
    title="Auth Microservice",
    version="0.2.0",
)

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/", summary="Health check")
async def health():
    return {"status": "ok"}

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
