from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import get_current_user
from backend.app.db.models import Conversation, StoredMessage
from backend.app.db.session import get_db

router = APIRouter()


class ConversationSummary(BaseModel):
    id: str
    title: str

    model_config = ConfigDict(from_attributes=True)


class ConversationMessage(BaseModel):
    role: str
    content: str

    model_config = ConfigDict(from_attributes=True)


class ConversationDetail(ConversationSummary):
    messages: list[ConversationMessage]


@router.get("/conversations", response_model=list[ConversationSummary])
def list_conversations(
    session: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> list[Conversation]:
    return list(
        session.scalars(
            select(Conversation)
            .where(Conversation.owner_id == current_user)
            .order_by(Conversation.updated_at.desc(), Conversation.id.desc())
        )
    )


@router.post("/conversations", response_model=ConversationSummary, status_code=201)
def create_conversation(
    session: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> Conversation:
    conversation = Conversation(id=uuid4().hex, owner_id=current_user)
    session.add(conversation)
    session.commit()
    session.refresh(conversation)
    return conversation


@router.get(
    "/conversations/{conversation_id}", response_model=ConversationDetail
)
def get_conversation(
    conversation_id: str,
    session: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> Conversation:
    conversation = session.scalar(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.owner_id == current_user,
        )
    )
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")
    return conversation
