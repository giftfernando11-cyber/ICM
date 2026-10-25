from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.core.config import settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    ai_configured: bool
    auth_configured: bool
    phone_configured: bool
    google_configured: bool
    facebook_configured: bool
    arpqi_configured: bool
    demo_mode: bool


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        ai_configured=settings.openai_api_key is not None,
        auth_configured=settings.auth_configured,
        phone_configured=bool(
            settings.twilio_account_sid
            and settings.twilio_auth_token
            and settings.twilio_from_number
        ),
        google_configured=bool(
            settings.google_client_id
            and settings.google_client_secret
            and settings.google_redirect_uri
        ),
        facebook_configured=bool(
            settings.facebook_client_id
            and settings.facebook_client_secret
            and settings.facebook_redirect_uri
        ),
        arpqi_configured=settings.arpqi_configured,
        demo_mode=settings.auth_demo_mode,
    )
