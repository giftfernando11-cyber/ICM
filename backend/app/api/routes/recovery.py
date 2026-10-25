from datetime import datetime, timezone
import secrets
import string
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from itsdangerous import BadSignature

from backend.app.api.routes.auth import (
    OTP_MAX_AGE,
    OTP_MAX_ATTEMPTS,
    _code_digest,
    _password_hash,
    _send_email_code,
    _serializer,
)
from backend.app.core.config import settings
from backend.app.db.models import (
    LoginSession,
    PasswordRecoveryChallenge,
    SecurityEvent,
    User,
)
from backend.app.db.session import get_db

router = APIRouter()
PENDING_RECOVERY_COOKIE = "mindia_password_recovery"
RESEND_INTERVAL_SECONDS = 60


class RecoveryRequest(BaseModel):
    email: EmailStr


class RecoveryCompletion(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")
    new_password: str = Field(min_length=12, max_length=256)


class RecoveryResponse(BaseModel):
    detail: str


def _set_pending_cookie(response: Response, challenge_id: str) -> None:
    response.set_cookie(
        key=PENDING_RECOVERY_COOKIE,
        value=_serializer().dumps({"challenge": challenge_id, "purpose": "reset"}),
        max_age=OTP_MAX_AGE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )


@router.post(
    "/auth/recovery",
    response_model=RecoveryResponse,
    status_code=202,
)
def request_password_recovery(
    request: RecoveryRequest,
    response: Response,
    session: Session = Depends(get_db),
) -> RecoveryResponse:
    if not settings.smtp_host or not settings.smtp_from:
        raise HTTPException(
            status_code=503, detail="A recuperação por e-mail não está configurada."
        )
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    normalized_email = str(request.email).lower()
    user = session.scalar(select(User).where(User.email == normalized_email))
    challenge_id = uuid4().hex
    if user is not None:
        latest = session.scalar(
            select(PasswordRecoveryChallenge)
            .where(PasswordRecoveryChallenge.user_id == user.id)
            .order_by(PasswordRecoveryChallenge.created_at.desc())
        )
        if latest is not None and latest.created_at is not None:
            latest_time = latest.created_at.replace(tzinfo=timezone.utc)
            if (
                datetime.now(timezone.utc) - latest_time
            ).total_seconds() < RESEND_INTERVAL_SECONDS:
                _set_pending_cookie(response, latest.id)
                return RecoveryResponse(
                    detail="Se a conta existir, receberás instruções para recuperar o acesso."
                )
        code = "".join(secrets.choice(string.digits) for _ in range(6))
        challenge = PasswordRecoveryChallenge(
            id=challenge_id,
            user_id=user.id,
            code_digest=_code_digest(code),
            attempts=0,
            consumed=False,
        )
        session.add(challenge)
        session.flush()
        try:
            _send_email_code(normalized_email, code)
            session.commit()
        except (HTTPException, SQLAlchemyError):
            session.rollback()
            raise
    else:
        challenge_id = secrets.token_hex(16)
    _set_pending_cookie(response, challenge_id)
    return RecoveryResponse(
        detail="Se a conta existir, receberás instruções para recuperar o acesso."
    )


@router.post(
    "/auth/recovery/complete",
    response_model=RecoveryResponse,
)
def complete_password_recovery(
    request: RecoveryCompletion,
    response: Response,
    pending_token: Annotated[
        str | None, Cookie(alias=PENDING_RECOVERY_COOKIE)
    ] = None,
    session: Session = Depends(get_db),
) -> RecoveryResponse:
    if pending_token is None:
        raise HTTPException(
            status_code=401, detail="Pede novamente as instruções de recuperação."
        )
    try:
        payload = _serializer().loads(pending_token, max_age=OTP_MAX_AGE)
    except BadSignature:
        raise HTTPException(status_code=401, detail="O pedido de recuperação expirou.") from None
    challenge_id = (
        payload.get("challenge")
        if isinstance(payload, dict) and payload.get("purpose") == "reset"
        else None
    )
    challenge = (
        session.get(PasswordRecoveryChallenge, challenge_id)
        if isinstance(challenge_id, str)
        else None
    )
    if challenge is None or challenge.consumed:
        raise HTTPException(status_code=401, detail="Código de recuperação inválido.")
    if challenge.created_at is None or (
        datetime.now(timezone.utc)
        - challenge.created_at.replace(tzinfo=timezone.utc)
    ).total_seconds() > OTP_MAX_AGE:
        challenge.consumed = True
        session.commit()
        raise HTTPException(status_code=401, detail="Código de recuperação inválido.")
    if challenge.attempts >= OTP_MAX_ATTEMPTS:
        challenge.consumed = True
        session.commit()
        raise HTTPException(status_code=429, detail="Demasiadas tentativas.")
    challenge.attempts += 1
    if not secrets.compare_digest(
        challenge.code_digest, _code_digest(request.code)
    ):
        session.commit()
        raise HTTPException(status_code=401, detail="Código de recuperação inválido.")
    user = session.get(User, challenge.user_id)
    if user is None:
        session.rollback()
        raise HTTPException(status_code=401, detail="Código de recuperação inválido.")
    challenge.consumed = True
    user.password_hash = _password_hash(request.new_password)
    revoked = session.scalars(
        select(LoginSession).where(
            LoginSession.user_id == user.id,
            LoginSession.revoked_at.is_(None),
        )
    )
    now = datetime.now(timezone.utc)
    for login_session in revoked:
        login_session.revoked_at = now
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=user.id,
            event_type="password_recovered",
            detail="Palavra-passe redefinida; sessões activas revogadas.",
        )
    )
    session.commit()
    response.delete_cookie(
        key=PENDING_RECOVERY_COOKIE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    return RecoveryResponse(detail="Palavra-passe redefinida. Inicia sessão novamente.")
