from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.access import router as access_router
from backend.app.api.routes.arpqi import router as arpqi_router
from backend.app.api.routes.dashboard import router as dashboard_router
from backend.app.api.routes.mfa import router as mfa_router
from backend.app.api.routes.recovery import router as recovery_router
from backend.app.api.routes.student_documents import router as student_documents_router
from backend.app.core.config import settings

from backend.app.api.routes.conversations import (
    router as conversations_router,
)
from backend.app.api.routes.chat import router as chat_router
from backend.app.api.routes.health import router as health_router
from backend.app.db.models import Base
from backend.app.db.session import engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)
    if "owner_id" not in {
        column["name"] for column in inspect(engine).get_columns("conversations")
    }:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE conversations ADD COLUMN owner_id "
                    "VARCHAR(32) REFERENCES users(id)"
                )
            )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_conversations_owner_id "
                    "ON conversations (owner_id)"
                )
            )
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="MindIA API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(access_router, prefix="/api")
app.include_router(arpqi_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(mfa_router, prefix="/api")
app.include_router(recovery_router, prefix="/api")
app.include_router(student_documents_router, prefix="/api/student/documents")
app.include_router(chat_router, prefix="/api")
app.include_router(conversations_router, prefix="/api")
