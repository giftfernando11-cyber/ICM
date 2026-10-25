from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import (
    OTP_MAX_AGE,
    PENDING_MFA_COOKIE,
    AuthSession,
    _issue_authenticated_session,
    _password_matches,
    _serializer,
    get_current_user,
)
from backend.app.core.mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    new_recovery_codes,
    new_totp_secret,
    provisioning_qr_data_url,
    provisioning_uri,
    recovery_code_digest,
    verify_totp,
)
from backend.app.db.models import (
    MfaCredential,
    MfaLoginChallenge,
    RecoveryCode,
    SecurityEvent,
    User,
)
from backend.app.db.session import get_db
from backend.app.core.config import settings
from itsdangerous import BadSignature

router = APIRouter()


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class AuthenticatorLoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class MfaEnrollment(BaseModel):
    provisioning_uri: str
    qr_code_data_url: str


class RecoveryCodes(BaseModel):
    codes: list[str]


def _record_event(session: Session, user_id: str, event: str, detail: str) -> None:
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=user_id,
            event_type=event,
            detail=detail,
        )
    )


def _consume_recovery_code(
    session: Session, user_id: str, code: str
) -> bool:
    digest = recovery_code_digest(code)
    stored = session.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.code_digest == digest,
            RecoveryCode.consumed.is_(False),
        )
    )
    if stored is None:
        return False
    stored.consumed = True
    return True


@router.post("/auth/mfa/login", response_model=AuthSession)
def start_authenticator_login(
    request: AuthenticatorLoginRequest,
    response: Response,
    session: Session = Depends(get_db),
) -> AuthSession:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    identifier = request.identifier.strip().lower()
    user = session.scalar(
        select(User).where((User.email == identifier) | (User.phone == identifier))
    )
    if (
        user is None
        or not user.email_verified
        or not _password_matches(request.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas ou aplicação autenticadora indisponível nesta conta.",
        )
    credential = session.get(MfaCredential, user.id)
    if credential is None or not credential.enabled:
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas ou aplicação autenticadora indisponível nesta conta.",
        )

    challenge = MfaLoginChallenge(
        id=uuid4().hex,
        user_id=user.id,
        attempts=0,
        consumed=False,
    )
    session.add(challenge)
    _record_event(
        session,
        user.id,
        "authenticator_login_started",
        "Início de sessão por palavra-passe e aplicação autenticadora.",
    )
    session.commit()
    response.set_cookie(
        key=PENDING_MFA_COOKIE,
        value=_serializer().dumps({"challenge": challenge.id, "purpose": "mfa"}),
        max_age=OTP_MAX_AGE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    return AuthSession(
        authenticated=False,
        username=user.name,
        roles=[],
        mfa_required=True,
        mfa_enabled=True,
    )


@router.post("/auth/mfa/enroll", response_model=MfaEnrollment)
def enroll_mfa(
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> MfaEnrollment:
    user = session.get(User, current_user)
    if user is None:
        raise HTTPException(status_code=401, detail="Inicia sessão para continuar.")
    credential = session.get(MfaCredential, current_user)
    if credential is not None and credential.enabled:
        raise HTTPException(status_code=409, detail="MFA já está activo.")

    secret = new_totp_secret()
    if credential is None:
        credential = MfaCredential(
            user_id=current_user,
            encrypted_secret=encrypt_totp_secret(secret),
            enabled=False,
            last_used_step=0,
        )
        session.add(credential)
    else:
        credential.encrypted_secret = encrypt_totp_secret(secret)
        credential.enabled = False
        credential.last_used_step = 0
    _record_event(session, current_user, "mfa_enrollment_started", "Configuração TOTP iniciada.")
    session.commit()
    uri = provisioning_uri(secret, user.email)
    return MfaEnrollment(
        provisioning_uri=uri,
        qr_code_data_url=provisioning_qr_data_url(uri),
    )


@router.post("/auth/mfa/confirm", response_model=RecoveryCodes)
def confirm_mfa(
    request: MfaCode,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> RecoveryCodes:
    credential = session.get(MfaCredential, current_user)
    if credential is None or credential.enabled:
        raise HTTPException(
            status_code=409, detail="Não há uma configuração MFA pendente."
        )
    if credential.enrollment_attempts >= 5:
        session.delete(credential)
        session.commit()
        raise HTTPException(
            status_code=429,
            detail="Demasiadas tentativas. Inicia novamente a configuração MFA.",
        )
    credential.enrollment_attempts += 1
    secret = decrypt_totp_secret(credential.encrypted_secret)
    step = verify_totp(secret, request.code)
    if step is None:
        session.commit()
        raise HTTPException(status_code=401, detail="Código de autenticação inválido.")
    credential.enabled = True
    credential.last_used_step = step
    codes = new_recovery_codes()
    session.add_all(
        RecoveryCode(
            id=uuid4().hex,
            user_id=current_user,
            code_digest=recovery_code_digest(code),
            consumed=False,
        )
        for code in codes
    )
    _record_event(session, current_user, "mfa_enabled", "MFA TOTP activado.")
    session.commit()
    return RecoveryCodes(codes=codes)


@router.post("/auth/mfa/verify-login", response_model=AuthSession)
def verify_mfa_login(
    request: MfaCode,
    response: Response,
    pending_token: Annotated[
        str | None, Cookie(alias=PENDING_MFA_COOKIE)
    ] = None,
    session: Session = Depends(get_db),
) -> AuthSession:
    if pending_token is None:
        raise HTTPException(status_code=401, detail="Inicia novamente.")
    try:
        payload = _serializer().loads(pending_token, max_age=OTP_MAX_AGE)
    except BadSignature:
        raise HTTPException(status_code=401, detail="O pedido MFA expirou.") from None
    challenge_id = (
        payload.get("challenge")
        if isinstance(payload, dict) and payload.get("purpose") == "mfa"
        else None
    )
    challenge = (
        session.get(MfaLoginChallenge, challenge_id)
        if isinstance(challenge_id, str)
        else None
    )
    if challenge is None or challenge.consumed:
        raise HTTPException(status_code=401, detail="Inicia novamente.")
    if challenge.attempts >= 5:
        challenge.consumed = True
        session.commit()
        raise HTTPException(status_code=429, detail="Demasiadas tentativas MFA.")
    user = session.get(User, challenge.user_id)
    credential = session.get(MfaCredential, challenge.user_id)
    if user is None or credential is None or not credential.enabled:
        raise HTTPException(status_code=401, detail="Inicia novamente.")

    secret = decrypt_totp_secret(credential.encrypted_secret)
    step = verify_totp(secret, request.code)
    if step is not None:
        if step <= credential.last_used_step:
            challenge.attempts += 1
            session.commit()
            raise HTTPException(
                status_code=401, detail="Este código já foi utilizado."
            )
        credential.last_used_step = step
    elif not _consume_recovery_code(session, user.id, request.code):
        challenge.attempts += 1
        session.commit()
        raise HTTPException(status_code=401, detail="Código MFA inválido.")

    challenge.consumed = True
    _record_event(session, user.id, "mfa_verified", "Segundo factor validado.")
    session.commit()
    response.delete_cookie(
        key=PENDING_MFA_COOKIE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    return _issue_authenticated_session(
        session, response, user, mfa_verified=True
    )


@router.post("/auth/mfa/recovery-codes/regenerate", response_model=RecoveryCodes)
def regenerate_recovery_codes(
    request: MfaCode,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> RecoveryCodes:
    credential = session.get(MfaCredential, current_user)
    if credential is None or not credential.enabled:
        raise HTTPException(status_code=409, detail="MFA não está activo.")
    step = verify_totp(decrypt_totp_secret(credential.encrypted_secret), request.code)
    if step is None or step <= credential.last_used_step:
        raise HTTPException(
            status_code=401,
            detail="É necessário um código TOTP válido e ainda não utilizado.",
        )
    credential.last_used_step = step
    for stored in session.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == current_user,
            RecoveryCode.consumed.is_(False),
        )
    ):
        stored.consumed = True
    codes = new_recovery_codes()
    session.add_all(
        RecoveryCode(
            id=uuid4().hex,
            user_id=current_user,
            code_digest=recovery_code_digest(code),
            consumed=False,
        )
        for code in codes
    )
    _record_event(session, current_user, "mfa_recovery_codes_regenerated", "Códigos regenerados.")
    session.commit()
    return RecoveryCodes(codes=codes)
