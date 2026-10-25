from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets
import smtplib
from email.message import EmailMessage
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import get_current_user
from backend.app.core.config import settings
from backend.app.db.models import (
    ArpqiAccessRequest,
    ArpqiAccessSlot,
    SecurityEvent,
    User,
    UserRole,
)
from backend.app.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()
APPROVAL_TOKEN_MAX_AGE = timedelta(hours=24)


class ArpqiRequestResponse(BaseModel):
    status: str
    detail: str


class ArpqiApprovalRequest(BaseModel):
    token: str = Field(min_length=40, max_length=100)


def _require_arpqi_configuration() -> str:
    if not settings.arpqi_configured or settings.arpqi_owner_email is None:
        raise HTTPException(
            status_code=503,
            detail="A área ARPQI requer email titular e SMTP configurados no servidor.",
        )
    return settings.arpqi_owner_email


def _send_approval_email(
    owner_email: str, requester_name: str, requester_email: str, token: str
) -> None:
    if not settings.smtp_host or not settings.smtp_from:
        raise HTTPException(
            status_code=503,
            detail="O email de aprovação ARPQI ainda não está configurado.",
        )
    approval_url = (
        f"{settings.frontend_base_url}/?arpqi_approval={token}"
    )
    message = EmailMessage()
    message["Subject"] = "Pedido de acesso restrito à área ARPQI"
    message["From"] = settings.smtp_from
    message["To"] = owner_email
    message.set_content(
        f"{requester_name} ({requester_email}) pediu acesso à área restrita ARPQI.\n\n"
        "Para aprovar este pedido, abre o link abaixo. A aprovação expira em "
        "24 horas e só pode ser utilizada uma vez:\n"
        f"{approval_url}\n\n"
        "Se não reconheces este pedido, ignora esta mensagem."
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
        logger.exception("Não foi possível enviar o pedido de acesso ARPQI.")
        raise HTTPException(
            status_code=502,
            detail="Não foi possível enviar o pedido de aprovação por email.",
        ) from None


@router.post("/auth/arpqi/access-request", response_model=ArpqiRequestResponse)
def request_arpqi_access(
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> ArpqiRequestResponse:
    owner_email = _require_arpqi_configuration()
    user = session.get(User, current_user)
    if user is None:
        raise HTTPException(status_code=401, detail="Inicia sessão para continuar.")

    if session.get(UserRole, (current_user, "arpqi")) is not None:
        return ArpqiRequestResponse(
            status="approved", detail="Esta conta já tem acesso à área ARPQI."
        )
    if not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Confirma o email da tua conta antes de pedir acesso ARPQI.",
        )

    owner = session.scalar(select(User).where(User.email == owner_email))
    if owner is None or session.get(UserRole, (owner.id, "arpqi")) is None:
        raise HTTPException(
            status_code=409,
            detail="O titular ainda não confirmou a conta ARPQI no portal.",
        )
    owner_slot = session.get(ArpqiAccessSlot, 1)
    if owner_slot is None or owner_slot.user_id != owner.id:
        raise HTTPException(
            status_code=409,
            detail="A conta titular ainda não foi registada como primeira conta ARPQI.",
        )

    now = datetime.now(timezone.utc)
    existing_request = session.scalar(
        select(ArpqiAccessRequest).where(
            ArpqiAccessRequest.user_id == current_user,
            ArpqiAccessRequest.status == "pending",
        )
    )
    if existing_request is not None:
        if existing_request.expires_at.replace(tzinfo=timezone.utc) > now:
            return ArpqiRequestResponse(
                status="pending",
                detail="O pedido já foi enviado e aguarda aprovação do titular.",
            )
        existing_request.status = "expired"
        session.commit()

    if session.get(ArpqiAccessSlot, 2) is not None:
        raise HTTPException(
            status_code=409,
            detail="A área ARPQI já atingiu o limite de duas contas autorizadas.",
        )
    pending_request = session.scalar(
        select(ArpqiAccessRequest).where(
            ArpqiAccessRequest.status == "pending"
        )
    )
    if pending_request is not None:
        if pending_request.expires_at.replace(tzinfo=timezone.utc) > now:
            raise HTTPException(
                status_code=409,
                detail="Já existe outro pedido ARPQI pendente de aprovação.",
            )
        pending_request.status = "expired"
        session.commit()

    token = secrets.token_urlsafe(32)
    access_request = ArpqiAccessRequest(
        id=uuid4().hex,
        user_id=user.id,
        token_digest=hashlib.sha256(token.encode()).hexdigest(),
        status="pending",
        expires_at=now + APPROVAL_TOKEN_MAX_AGE,
    )
    session.add(access_request)
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=current_user,
            event_type="arpqi_access_requested",
            detail="Tentativa de acesso ARPQI registada; aprovação enviada ao titular.",
        )
    )
    session.commit()

    try:
        _send_approval_email(owner_email, user.name, user.email, token)
    except HTTPException:
        access_request.status = "notification_failed"
        session.add(
            SecurityEvent(
                id=uuid4().hex,
                user_id=current_user,
                event_type="arpqi_approval_email_failed",
                detail="Não foi possível notificar o titular sobre o pedido ARPQI.",
            )
        )
        session.commit()
        raise

    return ArpqiRequestResponse(
        status="pending",
        detail="Advertência: esta área é restrita. A tentativa foi registada e o titular recebeu um pedido de aprovação por email.",
    )


@router.post("/auth/arpqi/approve", response_model=ArpqiRequestResponse)
def approve_arpqi_access(
    request: ArpqiApprovalRequest,
    session: Session = Depends(get_db),
) -> ArpqiRequestResponse:
    owner_email = _require_arpqi_configuration()
    token_digest = hashlib.sha256(request.token.encode()).hexdigest()
    access_request = session.scalar(
        select(ArpqiAccessRequest).where(
            ArpqiAccessRequest.token_digest == token_digest
        )
    )
    now = datetime.now(timezone.utc)
    if (
        access_request is None
        or access_request.status != "pending"
        or access_request.expires_at.replace(tzinfo=timezone.utc) <= now
    ):
        raise HTTPException(
            status_code=400,
            detail="Este link de aprovação é inválido, expirou ou já foi utilizado.",
        )

    owner = session.scalar(select(User).where(User.email == owner_email))
    if owner is None or session.get(UserRole, (owner.id, "arpqi")) is None:
        raise HTTPException(
            status_code=403,
            detail="A conta titular não está autorizada a aprovar este pedido.",
        )
    owner_slot = session.get(ArpqiAccessSlot, 1)
    if owner_slot is None or owner_slot.user_id != owner.id:
        raise HTTPException(
            status_code=403,
            detail="A conta titular não está registada como primeira conta ARPQI.",
        )
    if session.get(ArpqiAccessSlot, 2) is not None:
        raise HTTPException(
            status_code=409,
            detail="A área ARPQI já atingiu o limite de duas contas autorizadas.",
        )

    requester = session.get(User, access_request.user_id)
    if requester is None or requester.email.lower() == owner_email:
        raise HTTPException(
            status_code=409, detail="A conta deste pedido já não é elegível."
        )
    access_request.status = "approved"
    access_request.decided_at = now
    session.add(
        UserRole(
            user_id=requester.id,
            role_key="arpqi",
            assigned_by="arpqi-email-approval",
        )
    )
    session.add(ArpqiAccessSlot(slot_number=2, user_id=requester.id))
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=owner.id,
            event_type="arpqi_access_approved",
            detail="O titular aprovou um pedido de acesso ARPQI por email.",
        )
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="O limite de contas ARPQI foi atingido ou este pedido já foi decidido.",
        ) from None
    return ArpqiRequestResponse(
        status="approved",
        detail=f"Acesso ARPQI aprovado para {requester.name}.",
    )
