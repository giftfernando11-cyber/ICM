from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import (
    InstitutionalRole,
    get_current_user,
    require_roles,
)
from backend.app.db.models import (
    AccessRequest,
    AccessRequestDocument,
    MfaCredential,
    SecurityEvent,
    User,
    UserRole,
    LoginSession,
)
from backend.app.db.session import get_db

router = APIRouter()

RoleKey = InstitutionalRole
PRIVILEGED_ROLES = {"direction", "institutional_admin", "technical_admin"}
APPROVER_ROLES = ("direction", "institutional_admin", "technical_admin")
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
ALLOWED_DOCUMENT_TYPES = {
    "application/pdf": b"%PDF-",
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
}

ROLE_DOCUMENT_REQUIREMENTS: dict[RoleKey, list[dict[str, str]]] = {
    "student": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "student_link", "label": "Comprovativo de admissão ou vínculo estudantil"},
    ],
    "teacher": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "teacher_link", "label": "Comprovativo de vínculo ou nomeação docente"},
    ],
    "staff": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "staff_link", "label": "Comprovativo de vínculo profissional"},
    ],
    "administrative_services": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "staff_link", "label": "Comprovativo de vínculo profissional"},
        {"key": "role_authorisation", "label": "Autorização para a função administrativa"},
    ],
    "direction": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "appointment", "label": "Despacho ou comprovativo de nomeação"},
    ],
    "institutional_admin": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "appointment", "label": "Despacho ou comprovativo de nomeação"},
        {"key": "role_authorisation", "label": "Autorização institucional"},
    ],
    "technical_admin": [
        {"key": "identity", "label": "Documento de identificação"},
        {"key": "staff_link", "label": "Comprovativo de vínculo profissional"},
        {"key": "role_authorisation", "label": "Autorização institucional"},
    ],
}


class AccessRequestView(BaseModel):
    id: str
    role_key: str
    status: str
    requested_at: datetime
    requester_name: str | None = None
    requester_email: str | None = None
    justification: str = ""
    requirements_confirmed: bool = False
    documents: list["AccessDocumentView"] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class AccessDocumentRequirement(BaseModel):
    key: str
    label: str


class AccessRequirementsView(BaseModel):
    role_key: RoleKey
    role_label: str
    notice: str
    common_requirements: list[str]
    documents: list[AccessDocumentRequirement]


class AccessDocumentView(BaseModel):
    id: str
    document_key: str
    filename: str
    media_type: str
    uploaded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AccessRequestCreate(BaseModel):
    role_key: RoleKey
    justification: str = Field(default="", min_length=0, max_length=2000)
    requirements_confirmed: bool = False


class AccessDecision(BaseModel):
    approved: bool
    reviewer_note: str | None = Field(default=None, max_length=500)


require_access_approver = require_roles(*APPROVER_ROLES)


@router.get(
    "/auth/access-requirements/{role_key}",
    response_model=AccessRequirementsView,
)
def get_access_requirements(
    role_key: RoleKey,
    _: str = Depends(get_current_user),
) -> AccessRequirementsView:
    return AccessRequirementsView(
        role_key=role_key,
        role_label=role_key.replace("_", " ").title(),
        notice=(
            "Lista provisória: documentos e regras devem ser confirmados pelo "
            "ICM antes de serem considerados requisitos oficiais."
        ),
        common_requirements=[
            "Indicar uma justificação e o vínculo com a área seleccionada.",
            "Confirmar que as informações e os documentos submetidos são verdadeiros.",
        ],
        documents=[
            AccessDocumentRequirement(**document)
            for document in ROLE_DOCUMENT_REQUIREMENTS[role_key]
        ],
    )


@router.post("/auth/access-requests", response_model=AccessRequestView, status_code=201)
def create_access_request(
    request: AccessRequestCreate,
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> AccessRequest:
    if request.role_key == "arpqi":
        raise HTTPException(
            status_code=403,
            detail="Os pedidos ARPQI têm de ser aprovados pelo titular por email.",
        )
    existing_role = session.get(UserRole, (current_user, request.role_key))
    if existing_role is not None:
        raise HTTPException(status_code=409, detail="Esta função já está atribuída.")
    pending = session.scalar(
        select(AccessRequest).where(
            AccessRequest.user_id == current_user,
            AccessRequest.role_key == request.role_key,
            AccessRequest.status == "pending",
        )
    )
    if pending is not None:
        raise HTTPException(
            status_code=409, detail="Já existe um pedido pendente para esta função."
        )
    access_request = AccessRequest(
        id=uuid4().hex,
        user_id=current_user,
        role_key=request.role_key,
        status="pending",
    )
    session.add(access_request)
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=current_user,
            event_type="access_requested",
            detail=f"Pedido de função: {request.role_key}",
        )
    )
    session.commit()
    session.refresh(access_request)
    return access_request


@router.get("/auth/access-requests", response_model=list[AccessRequestView])
def list_own_access_requests(
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> list[AccessRequest]:
    return list(
        session.scalars(
            select(AccessRequest)
            .where(AccessRequest.user_id == current_user)
            .order_by(AccessRequest.requested_at.desc())
        )
    )


@router.get(
    "/admin/access-requests",
    response_model=list[AccessRequestView],
)
def list_pending_access_requests(
    _: str = Depends(require_access_approver),
    session: Session = Depends(get_db),
) -> list[dict[str, object]]:
    rows = session.execute(
        select(AccessRequest, User.name, User.email)
        .join(User, User.id == AccessRequest.user_id)
        .where(AccessRequest.status == "pending")
        .order_by(AccessRequest.requested_at)
    )
    return [
        {
            "id": request.id,
            "role_key": request.role_key,
            "status": request.status,
            "requested_at": request.requested_at,
            "requester_name": name,
            "requester_email": email,
        }
        for request, name, email in rows
    ]


@router.post(
    "/admin/access-requests/{request_id}/decision",
    response_model=AccessRequestView,
)
def decide_access_request(
    request_id: str,
    decision: AccessDecision,
    reviewer: str = Depends(require_access_approver),
    session: Session = Depends(get_db),
) -> AccessRequest:
    access_request = session.get(AccessRequest, request_id)
    if access_request is None:
        raise HTTPException(status_code=404, detail="Pedido não encontrado.")
    if access_request.role_key == "arpqi":
        raise HTTPException(
            status_code=403,
            detail="Os pedidos ARPQI só podem ser decididos pelo titular através do link enviado por email.",
        )
    if access_request.status != "pending":
        raise HTTPException(
            status_code=409, detail="Este pedido já foi analisado."
        )
    requester = session.get(User, access_request.user_id)
    if requester is None or not requester.email_verified:
        raise HTTPException(
            status_code=409,
            detail="A conta deve ter o e-mail confirmado antes da aprovação.",
        )
    if decision.approved and access_request.user_id == reviewer:
        raise HTTPException(
            status_code=403,
            detail="Não podes aprovar o teu próprio pedido de acesso.",
        )
    if decision.approved and access_request.role_key in PRIVILEGED_ROLES:
        credential = session.get(MfaCredential, access_request.user_id)
        if credential is None or not credential.enabled:
            raise HTTPException(
                status_code=409,
                detail="A pessoa deve activar MFA antes da atribuição de função privilegiada.",
            )

    access_request.status = "approved" if decision.approved else "rejected"
    access_request.reviewed_at = datetime.now(timezone.utc)
    access_request.reviewed_by = reviewer
    access_request.reviewer_note = decision.reviewer_note
    if decision.approved:
        session.add(
            UserRole(
                user_id=access_request.user_id,
                role_key=access_request.role_key,
                assigned_by=reviewer,
            )
        )
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=reviewer,
            event_type="access_request_decided",
            detail=(
                f"Pedido {request_id}: {access_request.status} "
                f"({access_request.role_key})"
            ),
        )
    )
    session.commit()
    session.refresh(access_request)
    return access_request


@router.delete("/admin/users/{user_id}/roles/{role_key}")
def revoke_user_role(
    user_id: str,
    role_key: RoleKey,
    reviewer: str = Depends(require_access_approver),
    session: Session = Depends(get_db),
) -> dict[str, bool]:
    assignment = session.get(UserRole, (user_id, role_key))
    if assignment is None:
        raise HTTPException(status_code=404, detail="Função não encontrada.")
    if role_key == "institutional_admin":
        active_admins = session.scalar(
            select(func.count())
            .select_from(UserRole)
            .where(UserRole.role_key == "institutional_admin")
        )
        if active_admins is not None and active_admins <= 1:
            raise HTTPException(
                status_code=409,
                detail="Não é permitido revogar o último administrador institucional.",
            )
    session.delete(assignment)
    for login_session in session.scalars(
        select(LoginSession).where(
            LoginSession.user_id == user_id,
            LoginSession.revoked_at.is_(None),
        )
    ):
        login_session.revoked_at = datetime.now(timezone.utc)
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=reviewer,
            event_type="role_revoked",
            detail=f"Função revogada: {role_key} para utilizador {user_id}.",
        )
    )
    session.commit()
    return {"revoked": True}
