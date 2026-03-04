from fastapi import FastAPI
from app.routers import auth
from app.routers import profile 

app = FastAPI(
    title="Auth Service",
    description="Микросервис авторизации (REST API)",
    version="1.0.0"
)

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(profile.router, prefix="/users", tags=["Profile"])

@app.get("/health")
async def health_check():
    return {"status": "ok"}
