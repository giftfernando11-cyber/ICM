import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import smtplib
import string
from urllib.parse import urlparse
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from email.message import EmailMessage
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.models import (
    Conversation,
    ArpqiAccessSlot,
    LoginSession,
    MfaCredential,
    MfaLoginChallenge,
    OtpChallenge,
    SecurityEvent,
    User,
    UserRole,
)
from backend.app.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()
SESSION_COOKIE = "mindia_session"
PENDING_COOKIE = "mindia_verification"
PENDING_MFA_COOKIE = "mindia_mfa_verification"
OAUTH_STATE_COOKIE = "mindia_oauth_state"
SESSION_MAX_AGE = 60 * 60 * 24 * 30
OTP_MAX_AGE = 60 * 5
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
PASSWORD_ITERATIONS = 600_000


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    phone: str | None = Field(default=None, min_length=8, max_length=16)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("O nome não pode estar vazio.")
        return value

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.startswith("+") or not value[1:].isdigit()
        ):
            raise ValueError("Usa o formato internacional, por exemplo +351912345678.")
        return value


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class VerifyRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class AuthSession(BaseModel):
    authenticated: bool
    username: str | None = None
    roles: list[str] = Field(default_factory=list)
    mfa_required: bool = False
    mfa_enabled: bool = False


InstitutionalRole = Literal[
    "student",
    "teacher",
    "staff",
    "administrative_services",
    "direction",
    "institutional_admin",
    "technical_admin",
    "arpqi",
]

ICM_AUTO_ASSIGNABLE_ROLES = {"student", "teacher", "staff"}


class VerificationResponse(BaseModel):
    detail: str
    destination: str
    demo_code: str | None = None


class LoginSessionView(BaseModel):
    id: str
    created_at: datetime
    expires_at: datetime
    current: bool


class RevokeSessionResponse(BaseModel):
    revoked: bool


def _serializer() -> URLSafeTimedSerializer:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    return URLSafeTimedSerializer(
        settings.auth_secret_key.get_secret_value(), salt="mindia-session-v2"
    )


def _user_roles(session: Session, user_id: str) -> list[str]:
    return list(
        session.scalars(select(UserRole.role_key).where(UserRole.user_id == user_id))
    )


def _has_privileged_role(session: Session, user_id: str) -> bool:
    return bool(
        set(_user_roles(session, user_id))
        & {"direction", "institutional_admin", "technical_admin"}
    )


def _ensure_arpqi_owner_role(session: Session, user: User) -> None:
    if (
        settings.arpqi_owner_email is None
        or user.email.lower() != settings.arpqi_owner_email
    ):
        return
    owner_slot = session.get(ArpqiAccessSlot, 1)
    if owner_slot is not None and owner_slot.user_id != user.id:
        raise HTTPException(
            status_code=409,
            detail="O espaço do titular ARPQI já está associado a outra conta.",
        )
    if session.get(UserRole, (user.id, "arpqi")) is None:
        session.add(
            UserRole(
                user_id=user.id,
                role_key="arpqi",
                assigned_by="verified-arpqi-owner-email",
            )
        )
        session.add(
            SecurityEvent(
                id=uuid4().hex,
                user_id=user.id,
                event_type="arpqi_owner_access_assigned",
                detail="Acesso ARPQI atribuído após confirmação do email titular.",
            )
        )
    if owner_slot is None:
        session.add(ArpqiAccessSlot(slot_number=1, user_id=user.id))


def _issue_authenticated_session(
    session: Session,
    response: Response,
    user: User,
    mfa_verified: bool = False,
) -> AuthSession:
    session_id = uuid4().hex
    session.add(
        LoginSession(
            id=session_id,
            user_id=user.id,
            mfa_verified=mfa_verified,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=SESSION_MAX_AGE),
        )
    )
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=user.id,
            event_type="session_created",
            detail="Sessão iniciada.",
        )
    )
    session.commit()
    session_expires = datetime.now(timezone.utc) + timedelta(seconds=SESSION_MAX_AGE)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=_serializer().dumps({"sub": user.id, "sid": session_id}),
        max_age=SESSION_MAX_AGE,
        expires=session_expires,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    return AuthSession(
        authenticated=True,
        username=user.name,
        roles=_user_roles(session, user.id),
        mfa_enabled=(
            session.get(MfaCredential, user.id) is not None
            and session.get(MfaCredential, user.id).enabled
        ),
    )


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS
    )
    salt_text = base64.urlsafe_b64encode(salt).decode()
    digest_text = base64.urlsafe_b64encode(digest).decode()
    return f"{salt_text}:{digest_text}"


def _password_matches(password: str, stored: str) -> bool:
    try:
        salt_text, digest_text = stored.split(":", maxsplit=1)
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


def _code_digest(code: str) -> str:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    return hmac.new(
        settings.auth_secret_key.get_secret_value().encode(),
        code.encode(),
        hashlib.sha256,
    ).hexdigest()


def _redact_destination(destination: str, channel: str) -> str:
    if channel == "email":
        name, _, domain = destination.partition("@")
        return f"{name[:1]}***@{domain}"
    return f"{destination[:3]}***{destination[-2:]}"


def _send_email_code(address: str, code: str) -> None:
    if not settings.smtp_host or not settings.smtp_from:
        raise HTTPException(
            status_code=503, detail="O envio de e-mail ainda não está configurado."
        )
    message = EmailMessage()
    message["Subject"] = "O teu código de confirmação MindIA"
    message["From"] = settings.smtp_from
    message["To"] = address
    message.set_content(
        f"O teu código de confirmação é {code}. "
        f"É válido durante {OTP_MAX_AGE // 60} minutos."
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(
                    settings.smtp_username,
                    settings.smtp_password.get_secret_value(),
                )
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        logger.exception("Não foi possível enviar o código de confirmação por e-mail.")
        raise HTTPException(
            status_code=502,
            detail="Não foi possível enviar o código por e-mail. Tenta novamente.",
        ) from None


def _demo_mode_is_local() -> bool:
    hostname = urlparse(settings.frontend_base_url).hostname
    return settings.auth_demo_mode and hostname in {"localhost", "127.0.0.1", "::1"}


def _require_local_demo_access(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    try:
        client_is_local = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        client_is_local = False
    if not _demo_mode_is_local() or not client_is_local:
        raise HTTPException(
            status_code=404, detail="Modo de demonstração não está ativo."
        )


def _send_sms_code(phone: str, code: str) -> None:
    required = (
        settings.twilio_account_sid,
        settings.twilio_auth_token,
        settings.twilio_from_number,
    )
    if not all(required):
        raise HTTPException(
            status_code=503, detail="O envio de SMS ainda não está configurado."
        )
    endpoint = (
        "https://api.twilio.com/2010-04-01/Accounts/"
        f"{settings.twilio_account_sid}/Messages.json"
    )
    payload = urllib.parse.urlencode(
        {
            "To": phone,
            "From": settings.twilio_from_number,
            "Body": f"O teu código de confirmação MindIA é {code}. "
            f"É válido durante {OTP_MAX_AGE // 60} minutos.",
        }
    ).encode()
    credentials = (
        f"{settings.twilio_account_sid}:{settings.twilio_auth_token.get_secret_value()}"
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Authorization": f"Basic {base64.b64encode(credentials).decode()}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in (200, 201):
                raise OSError(f"Twilio respondeu com {response.status}.")
    except (OSError, urllib.error.URLError):
        logger.exception("Não foi possível enviar o código de confirmação por SMS.")
        raise HTTPException(
            status_code=502,
            detail="Não foi possível enviar o código por SMS. Tenta novamente.",
        ) from None


def _issue_challenge(
    session: Session, response: Response, user: User, channel: Literal["email", "phone"]
) -> VerificationResponse:
    destination = user.email if channel == "email" else user.phone
    if destination is None:
        raise HTTPException(
            status_code=400, detail="A conta não tem um telefone associado."
        )
    latest = session.scalar(
        select(OtpChallenge)
        .where(
            OtpChallenge.user_id == user.id,
            OtpChallenge.channel == channel,
            OtpChallenge.consumed.is_(False),
        )
        .order_by(OtpChallenge.created_at.desc())
    )
    if latest is not None and latest.created_at is not None:
        age = (
            datetime.now(timezone.utc)
            - latest.created_at.replace(tzinfo=timezone.utc)
        ).total_seconds()
        if age < OTP_RESEND_SECONDS:
            raise HTTPException(
                status_code=429,
                detail="Espera um minuto antes de pedir outro código.",
            )

    code = "".join(secrets.choice(string.digits) for _ in range(6))
    challenge = OtpChallenge(
        id=uuid4().hex,
        user_id=user.id,
        channel=channel,
        code_digest=_code_digest(code),
        attempts=0,
        consumed=False,
    )
    session.add(challenge)
    session.flush()
    if _demo_mode_is_local():
        demo_code = code
    elif channel == "email":
        _send_email_code(destination, code)
    else:
        _send_sms_code(destination, code)
    session.commit()
    response.set_cookie(
        key=PENDING_COOKIE,
        value=_serializer().dumps({"challenge": challenge.id}),
        max_age=OTP_MAX_AGE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    return VerificationResponse(
        detail="Enviámos um código de confirmação.",
        destination=_redact_destination(destination, channel),
        demo_code=demo_code if _demo_mode_is_local() else None,
    )


def get_current_user(
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    session: Session = Depends(get_db),
) -> str:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    if token is None:
        raise HTTPException(status_code=401, detail="Inicia sessão para continuar.")
    try:
        payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        raise HTTPException(
            status_code=401, detail="A sessão expirou. Inicia sessão novamente."
        ) from None
    user_id = payload.get("sub") if isinstance(payload, dict) else None
    session_id = payload.get("sid") if isinstance(payload, dict) else None
    user = session.get(User, user_id) if isinstance(user_id, str) else None
    login_session = (
        session.get(LoginSession, session_id)
        if isinstance(session_id, str)
        else None
    )
    if (
        user is None
        or login_session is None
        or login_session.user_id != user.id
        or login_session.revoked_at is not None
        or login_session.expires_at.replace(tzinfo=timezone.utc)
        <= datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=401, detail="Inicia sessão para continuar.")
    if _has_privileged_role(session, user.id) and not login_session.mfa_verified:
        raise HTTPException(
            status_code=401,
            detail="Conclui a verificação multifactor para continuar.",
        )
    return user.id


def require_roles(*role_keys: InstitutionalRole) -> Callable[..., str]:
    if not role_keys:
        raise ValueError("É necessário indicar pelo menos uma função institucional.")

    def verify_role(
        current_user: str = Depends(get_current_user),
        session: Session = Depends(get_db),
    ) -> str:
        assigned_roles = set(_user_roles(session, current_user))
        if assigned_roles.isdisjoint(role_keys):
            raise HTTPException(
                status_code=403,
                detail="Não tens uma função institucional autorizada para esta operação.",
            )
        return current_user

    return verify_role


class ICMAreaSelectionRequest(BaseModel):
    role_key: InstitutionalRole


class ICMAreaSelectionResponse(BaseModel):
    role_key: InstitutionalRole
    assigned: bool
    roles: list[str]


@router.post("/auth/area-selection", response_model=ICMAreaSelectionResponse)
def assign_icm_area_role(
    request: ICMAreaSelectionRequest,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> ICMAreaSelectionResponse:
    requested_role = request.role_key
    if requested_role not in ICM_AUTO_ASSIGNABLE_ROLES:
        raise HTTPException(
            status_code=403,
            detail="Só as funções básicas do app do ICM podem ser atribuídas automaticamente.",
        )

    existing = session.get(UserRole, (current_user, requested_role))
    if existing is not None:
        current_roles = _user_roles(session, current_user)
        return ICMAreaSelectionResponse(
            role_key=requested_role,
            assigned=False,
            roles=current_roles,
        )

    session.add(
        UserRole(
            user_id=current_user,
            role_key=requested_role,
            assigned_by="app:icm-area-selection",
        )
    )
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=current_user,
            event_type="icm_area_role_assigned",
            detail=f"Função atribuída automaticamente via área do ICM: {requested_role}",
        )
    )
    session.commit()
    current_roles = _user_roles(session, current_user)
    return ICMAreaSelectionResponse(
        role_key=requested_role,
        assigned=True,
        roles=current_roles,
    )


@router.post("/auth/register", response_model=VerificationResponse, status_code=202)
def register(
    request: RegisterRequest,
    response: Response,
    http_request: Request,
    session: Session = Depends(get_db),
) -> VerificationResponse:
    if settings.auth_demo_mode:
        _require_local_demo_access(http_request)
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    email = str(request.email).lower()
    if session.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(status_code=409, detail="Este e-mail já tem uma conta.")
    if request.phone and session.scalar(
        select(User).where(User.phone == request.phone)
    ) is not None:
        raise HTTPException(status_code=409, detail="Este telefone já tem uma conta.")
    if (
        settings.arpqi_owner_phone
        and request.phone == settings.arpqi_owner_phone
        and email != settings.arpqi_owner_email
    ):
        raise HTTPException(
            status_code=409,
            detail="Este telefone está reservado para a conta titular ARPQI.",
        )
    phone = request.phone
    if (
        email == settings.arpqi_owner_email
        and settings.arpqi_owner_phone
        and phone is not None
        and phone != settings.arpqi_owner_phone
    ):
        raise HTTPException(
            status_code=422,
            detail="A conta titular deve utilizar o telefone configurado para ARPQI.",
        )
    if email == settings.arpqi_owner_email and phone is None:
        phone = settings.arpqi_owner_phone
    user = User(
        id=uuid4().hex,
        name=request.name.strip(),
        email=email,
        phone=phone,
        password_hash=_password_hash(request.password),
        email_verified=False,
        phone_verified=False,
    )
    session.add(user)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409, detail="Já existe uma conta com esses dados."
        ) from None
    session.execute(
        Conversation.__table__.update()
        .where(Conversation.owner_id.is_(None))
        .values(owner_id=user.id)
    )
    try:
        return _issue_challenge(session, response, user, "email")
    except Exception:
        session.rollback()
        raise


@router.post("/auth/login", response_model=VerificationResponse)
def login(
    request: LoginRequest,
    response: Response,
    http_request: Request,
    session: Session = Depends(get_db),
) -> VerificationResponse:
    if settings.auth_demo_mode:
        _require_local_demo_access(http_request)
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    identifier = request.identifier.strip().lower()
    user = session.scalar(
        select(User).where((User.email == identifier) | (User.phone == identifier))
    )
    if user is None or not _password_matches(request.password, user.password_hash):
        raise HTTPException(
            status_code=401, detail="E-mail/telefone ou palavra-passe inválidos."
        )
    channel: Literal["email", "phone"] = (
        "phone" if identifier == user.phone else "email"
    )
    return _issue_challenge(session, response, user, channel)


@router.post("/auth/verify", response_model=AuthSession)
def verify_code(
    request: VerifyRequest,
    response: Response,
    http_request: Request,
    pending_token: Annotated[
        str | None, Cookie(alias=PENDING_COOKIE)
    ] = None,
    session: Session = Depends(get_db),
) -> AuthSession:
    if settings.auth_demo_mode:
        _require_local_demo_access(http_request)
    if pending_token is None:
        raise HTTPException(
            status_code=401, detail="Pede um novo código de confirmação."
        )
    try:
        payload = _serializer().loads(pending_token, max_age=OTP_MAX_AGE)
    except BadSignature:
        raise HTTPException(
            status_code=401, detail="O código expirou. Inicia novamente."
        ) from None
    challenge_id = payload.get("challenge") if isinstance(payload, dict) else None
    challenge = (
        session.get(OtpChallenge, challenge_id)
        if isinstance(challenge_id, str)
        else None
    )
    if challenge is None or challenge.consumed:
        raise HTTPException(
            status_code=401, detail="Pede um novo código de confirmação."
        )
    if challenge.attempts >= OTP_MAX_ATTEMPTS:
        challenge.consumed = True
        session.commit()
        raise HTTPException(
            status_code=429, detail="Demasiadas tentativas. Pede um novo código."
        )
    challenge.attempts += 1
    if not hmac.compare_digest(challenge.code_digest, _code_digest(request.code)):
        session.commit()
        raise HTTPException(status_code=401, detail="O código de confirmação é inválido.")
    challenge.consumed = True
    user = session.get(User, challenge.user_id)
    if user is None:
        session.rollback()
        raise HTTPException(status_code=401, detail="A conta já não está disponível.")
    if challenge.channel == "email":
        user.email_verified = True
        if (
            settings.arpqi_owner_email == user.email.lower()
            and settings.arpqi_owner_phone
            and not user.phone_verified
            and user.phone != settings.arpqi_owner_phone
        ):
            phone_owner = session.scalar(
                select(User).where(User.phone == settings.arpqi_owner_phone)
            )
            if phone_owner is None or phone_owner.id == user.id:
                user.phone = settings.arpqi_owner_phone
        _ensure_arpqi_owner_role(session, user)
    else:
        user.phone_verified = True
    session.commit()
    response.delete_cookie(
        key=PENDING_COOKIE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/api",
    )
    if _has_privileged_role(session, user.id):
        credential = session.get(MfaCredential, user.id)
        if credential is None or not credential.enabled:
            raise HTTPException(
                status_code=403,
                detail="A função privilegiada requer MFA configurado. Contacta a administração.",
            )
        mfa_challenge = MfaLoginChallenge(
            id=uuid4().hex,
            user_id=user.id,
            attempts=0,
            consumed=False,
        )
        session.add(mfa_challenge)
        session.commit()
        response.set_cookie(
            key=PENDING_MFA_COOKIE,
            value=_serializer().dumps(
                {"challenge": mfa_challenge.id, "purpose": "mfa"}
            ),
            max_age=OTP_MAX_AGE,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/api",
        )
        return AuthSession(
            authenticated=False,
            username=user.name,
            roles=_user_roles(session, user.id),
            mfa_required=True,
            mfa_enabled=True,
        )
    return _issue_authenticated_session(session, response, user)


@router.post("/auth/resend", response_model=VerificationResponse)
def resend_code(
    response: Response,
    http_request: Request,
    pending_token: Annotated[
        str | None, Cookie(alias=PENDING_COOKIE)
    ] = None,
    session: Session = Depends(get_db),
) -> VerificationResponse:
    if settings.auth_demo_mode:
        _require_local_demo_access(http_request)
    if pending_token is None:
        raise HTTPException(
            status_code=401, detail="Inicia novamente para pedir outro código."
        )
    try:
        payload = _serializer().loads(pending_token, max_age=OTP_MAX_AGE)
    except BadSignature:
        raise HTTPException(
            status_code=401, detail="O código expirou. Inicia novamente."
        ) from None
    challenge_id = payload.get("challenge") if isinstance(payload, dict) else None
    challenge = (
        session.get(OtpChallenge, challenge_id)
        if isinstance(challenge_id, str)
        else None
    )
    if challenge is None or challenge.consumed:
        raise HTTPException(
            status_code=401, detail="Inicia novamente para pedir outro código."
        )
    user = session.get(User, challenge.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="A conta já não está disponível.")
    channel: Literal["email", "phone"] = (
        "email" if challenge.channel == "email" else "phone"
    )
    return _issue_challenge(session, response, user, channel)


@router.get("/auth/session", response_model=AuthSession)
def get_session(
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    session: Session = Depends(get_db),
) -> AuthSession:
    if token is None or settings.auth_secret_key is None:
        return AuthSession(authenticated=False)
    try:
        payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return AuthSession(authenticated=False)
    user_id = payload.get("sub") if isinstance(payload, dict) else None
    user = session.get(User, user_id) if isinstance(user_id, str) else None
    session_id = payload.get("sid") if isinstance(payload, dict) else None
    login_session = (
        session.get(LoginSession, session_id)
        if isinstance(session_id, str)
        else None
    )
    active = (
        user is not None
        and login_session is not None
        and login_session.user_id == user.id
        and login_session.revoked_at is None
        and login_session.expires_at.replace(tzinfo=timezone.utc)
        > datetime.now(timezone.utc)
    )
    mfa = session.get(MfaCredential, user.id) if active and user else None
    roles = _user_roles(session, user.id) if active and user else []
    return AuthSession(
        authenticated=bool(
            active
            and user is not None
            and login_session is not None
            and (
                not (_has_privileged_role(session, user.id))
                or login_session.mfa_verified
            )
        ),
        username=user.name if active and user is not None else None,
        roles=roles,
        mfa_enabled=mfa.enabled if mfa is not None else False,
    )


@router.post("/auth/logout", response_model=AuthSession)
def logout(
    response: Response,
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    session: Session = Depends(get_db),
) -> AuthSession:
    if token is not None and settings.auth_secret_key is not None:
        try:
            payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
        except BadSignature:
            payload = {}
        session_id = payload.get("sid") if isinstance(payload, dict) else None
        login_session = (
            session.get(LoginSession, session_id)
            if isinstance(session_id, str)
            else None
        )
        if login_session is not None and login_session.revoked_at is None:
            login_session.revoked_at = datetime.now(timezone.utc)
            session.add(
                SecurityEvent(
                    id=uuid4().hex,
                    user_id=login_session.user_id,
                    event_type="session_revoked",
                    detail="Sessão terminada pelo utilizador.",
                )
            )
            session.commit()
    for cookie_name in (SESSION_COOKIE, PENDING_COOKIE, PENDING_MFA_COOKIE):
        response.delete_cookie(
            key=cookie_name,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/api",
        )
    return AuthSession(authenticated=False)


@router.get("/auth/sessions", response_model=list[LoginSessionView])
def list_login_sessions(
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> list[LoginSessionView]:
    current_session_id: str | None = None
    if token is not None:
        payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
        current_session_id = (
            payload.get("sid") if isinstance(payload, dict) else None
        )
    now = datetime.now(timezone.utc)
    active_sessions = session.scalars(
        select(LoginSession).where(
            LoginSession.user_id == current_user,
            LoginSession.revoked_at.is_(None),
            LoginSession.expires_at > now,
        )
    )
    return [
        LoginSessionView(
            id=login_session.id,
            created_at=login_session.created_at,
            expires_at=login_session.expires_at,
            current=login_session.id == current_session_id,
        )
        for login_session in active_sessions
    ]


@router.delete(
    "/auth/sessions/{session_id}", response_model=RevokeSessionResponse
)
def revoke_login_session(
    session_id: str,
    response: Response,
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> RevokeSessionResponse:
    login_session = session.get(LoginSession, session_id)
    if login_session is None or login_session.user_id != current_user:
        raise HTTPException(status_code=404, detail="Sessão não encontrada.")
    if login_session.revoked_at is None:
        login_session.revoked_at = datetime.now(timezone.utc)
        session.add(
            SecurityEvent(
                id=uuid4().hex,
                user_id=current_user,
                event_type="session_revoked",
                detail="Sessão revogada pelo utilizador.",
            )
        )
        session.commit()
    current_session_id = None
    if token is not None:
        try:
            payload = _serializer().loads(token, max_age=SESSION_MAX_AGE)
        except BadSignature:
            payload = {}
        current_session_id = (
            payload.get("sid") if isinstance(payload, dict) else None
        )
    if session_id == current_session_id:
        response.delete_cookie(
            key=SESSION_COOKIE,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/api",
        )
    return RevokeSessionResponse(revoked=True)


def _oauth_settings(provider: str) -> tuple[str, str, str, str, str]:
    if provider == "google":
        values = (
            settings.google_client_id,
            settings.google_client_secret,
            settings.google_redirect_uri,
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        )
    elif provider == "facebook":
        values = (
            settings.facebook_client_id,
            settings.facebook_client_secret,
            settings.facebook_redirect_uri,
            "https://www.facebook.com/v21.0/dialog/oauth",
            "https://graph.facebook.com/v21.0/oauth/access_token",
        )
    else:
        raise HTTPException(
            status_code=404, detail="Este provedor não é suportado."
        )
    if not all(values):
        raise HTTPException(
            status_code=503,
            detail=f"O início de sessão com {provider.title()} não está configurado.",
        )

    def reveal(value: str | SecretStr | None) -> str:
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return value or ""

    return (
        reveal(values[0]),
        reveal(values[1]),
        reveal(values[2]),
        reveal(values[3]),
        reveal(values[4]),
    )


@router.get("/auth/oauth/{provider}")
def oauth_start(provider: Literal["google", "facebook"]) -> Response:
    if _demo_mode_is_local():
        raise HTTPException(
            status_code=400,
            detail="Usa o endpoint de demonstração para testar este provedor.",
        )
    client_id, _, redirect_uri, authorization_url, _ = _oauth_settings(provider)
    nonce = secrets.token_urlsafe(24)
    state = _serializer().dumps({"provider": provider, "nonce": nonce})
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
        "scope": "openid email profile" if provider == "google" else "email,public_profile",
    }
    response = Response(
        status_code=302,
        headers={"Location": f"{authorization_url}?{urllib.parse.urlencode(params)}"},
    )
    response.set_cookie(
        key=OAUTH_STATE_COOKIE,
        value=nonce,
        max_age=600,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
        path="/api/auth/oauth",
    )
    return response


@router.post(
    "/auth/demo/{provider}",
    response_model=VerificationResponse,
    status_code=202,
)
def demo_oauth(
    provider: Literal["google", "facebook"],
    response: Response,
    http_request: Request,
    session: Session = Depends(get_db),
) -> VerificationResponse:
    _require_local_demo_access(http_request)
    email = f"demo-{provider}@mindia.local"
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            id=uuid4().hex,
            name=f"Demonstração {provider.title()}",
            email=email,
            phone=None,
            password_hash=_password_hash(secrets.token_urlsafe(32)),
            email_verified=False,
            phone_verified=False,
        )
        session.add(user)
        session.flush()
    return _issue_challenge(session, response, user, "email")


@router.get("/auth/oauth/{provider}/callback")
def oauth_callback(
    provider: Literal["google", "facebook"],
    response: Response,
    code: str = Query(min_length=1),
    state: str = Query(min_length=1),
    oauth_nonce: Annotated[
        str | None, Cookie(alias=OAUTH_STATE_COOKIE)
    ] = None,
    session: Session = Depends(get_db),
) -> Response:
    try:
        state_data = _serializer().loads(state, max_age=600)
    except BadSignature:
        raise HTTPException(
            status_code=400, detail="O pedido de início de sessão expirou."
        ) from None
    if (
        not isinstance(state_data, dict)
        or state_data.get("provider") != provider
        or not isinstance(state_data.get("nonce"), str)
        or oauth_nonce is None
        or not hmac.compare_digest(state_data["nonce"], oauth_nonce)
    ):
        raise HTTPException(
            status_code=400, detail="Pedido de início de sessão inválido."
        )
    client_id, client_secret, redirect_uri, _, token_url = _oauth_settings(provider)
    token_params = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
            "grant_type": "authorization_code",
        }
    )
    if provider == "facebook":
        token_request = urllib.request.Request(f"{token_url}?{token_params}")
    else:
        token_request = urllib.request.Request(
            token_url,
            data=token_params.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
    try:
        with urllib.request.urlopen(token_request, timeout=15) as token_response:
            token_data = json.loads(token_response.read())
        access_token = token_data["access_token"]
        userinfo_url = (
            "https://www.googleapis.com/oauth2/v2/userinfo"
            if provider == "google"
            else "https://graph.facebook.com/me?fields=id,name,email"
        )
        userinfo_request = urllib.request.Request(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(userinfo_request, timeout=15) as userinfo_response:
            identity = json.loads(userinfo_response.read())
    except (OSError, urllib.error.URLError, KeyError, ValueError):
        logger.exception("Não foi possível validar a identidade via %s.", provider)
        raise HTTPException(
            status_code=502, detail="Não foi possível validar a conta no provedor."
        ) from None
    email = identity.get("email")
    if (
        not isinstance(email, str)
        or (provider == "google" and identity.get("verified_email") is not True)
    ):
        raise HTTPException(
            status_code=400,
            detail="O provedor não confirmou um endereço de e-mail válido.",
        )
    email = email.lower()
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            id=uuid4().hex,
            name=str(identity.get("name") or email.split("@", maxsplit=1)[0])[:100],
            email=email,
            phone=None,
            password_hash=_password_hash(secrets.token_urlsafe(32)),
            email_verified=False,
            phone_verified=False,
        )
        session.add(user)
        session.flush()
        session.execute(
            Conversation.__table__.update()
            .where(Conversation.owner_id.is_(None))
            .values(owner_id=user.id)
        )
    verification = _issue_challenge(session, response, user, "email")
    callback_url = f"{settings.frontend_base_url}/?verify=1&destination={urllib.parse.quote(verification.destination)}"
    response.status_code = 302
    response.headers["Location"] = callback_url
    response.delete_cookie(
        key=OAUTH_STATE_COOKIE,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
        path="/api/auth/oauth",
    )
    return response
