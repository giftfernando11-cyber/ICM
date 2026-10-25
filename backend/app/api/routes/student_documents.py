from datetime import datetime
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import get_current_user, require_roles
from backend.app.db.models import SecurityEvent, StudentDocument
from backend.app.db.session import get_db

router = APIRouter()

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
DOCUMENT_FORMATS = {
    "application/pdf": (".pdf", b"%PDF-"),
    "image/png": (".png", b"\x89PNG\r\n\x1a\n"),
    "image/jpeg": (".jpg", b"\xff\xd8\xff"),
}
DocumentType = Literal[
    "requerimento",
    "acta",
    "minuta",
    "relatorio",
    "carta_apresentacao",
    "curriculo",
    "declaracao",
    "outro",
]


class StudentDocumentView(BaseModel):
    id: str
    document_type: str
    filename: str
    description: str
    status: str
    submitted_at: datetime

    model_config = ConfigDict(from_attributes=True)


@router.get("", response_model=list[StudentDocumentView])
def list_student_documents(
    current_user: str = Depends(require_roles("student")),
    session: Session = Depends(get_db),
) -> list[StudentDocument]:
    return list(
        session.scalars(
            select(StudentDocument)
            .where(StudentDocument.user_id == current_user)
            .order_by(StudentDocument.submitted_at.desc())
        )
    )


@router.post("", response_model=StudentDocumentView, status_code=201)
async def submit_student_document(
    document_type: Annotated[DocumentType, Form()],
    file: Annotated[UploadFile, File()],
    description: Annotated[str, Form(max_length=500)] = "",
    current_user: str = Depends(require_roles("student")),
    session: Session = Depends(get_db),
) -> StudentDocument:
    file_format = DOCUMENT_FORMATS.get(file.content_type or "")
    if file_format is None:
        raise HTTPException(
            status_code=415,
            detail="Formato não suportado. Envia um documento PDF, PNG ou JPG.",
        )

    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not filename or len(filename) > 150:
        raise HTTPException(status_code=400, detail="Nome de ficheiro inválido.")
    if not filename.lower().endswith(file_format[0]):
        raise HTTPException(
            status_code=415,
            detail="A extensão do ficheiro não corresponde ao formato enviado.",
        )

    content = await file.read(MAX_DOCUMENT_BYTES + 1)
    if len(content) > MAX_DOCUMENT_BYTES:
        raise HTTPException(
            status_code=413, detail="O ficheiro não pode exceder 8 MB."
        )
    if not content.startswith(file_format[1]):
        raise HTTPException(
            status_code=415, detail="O conteúdo do ficheiro não corresponde ao formato."
        )

    document = StudentDocument(
        id=uuid4().hex,
        user_id=current_user,
        document_type=document_type,
        filename=filename,
        media_type=file.content_type or "application/octet-stream",
        description=description.strip(),
        content=content,
        status="pending",
    )
    session.add(document)
    session.add(
        SecurityEvent(
            id=uuid4().hex,
            user_id=current_user,
            event_type="student_document_submitted",
            detail=f"Documento submetido: {document_type}",
        )
    )
    session.commit()
    session.refresh(document)
    return document
