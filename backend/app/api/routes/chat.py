import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from openai import AsyncOpenAI, OpenAIError
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import get_current_user
from backend.app.core.config import settings
from backend.app.db.models import Conversation, StoredMessage
from backend.app.db.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    content: str = Field(min_length=1, max_length=8000)


class ChatResponse(BaseModel):
    message: str


def _bounded_context(messages: list[ChatMessage]) -> list[ChatMessage]:
    context: list[ChatMessage] = []
    content_length = 0
    for message in reversed(messages):
        if len(context) == 30 or content_length + len(message.content) > 24000:
            break
        context.append(message)
        content_length += len(message.content)
    context.reverse()
    return context


@router.post(
    "/conversations/{conversation_id}/messages", response_model=ChatResponse
)
async def send_message(
    conversation_id: str,
    request: ChatRequest,
    session: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> ChatResponse:
    conversation = session.scalar(
        select(Conversation)
        .where(
            Conversation.id == conversation_id,
            Conversation.owner_id == current_user,
        )
        .with_for_update()
    )
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")

    history = [
        ChatMessage(role=message.role, content=message.content)
        for message in conversation.messages
    ]
    session.rollback()

    if settings.openai_api_key is None:
        raise HTTPException(
            status_code=503, detail="O fornecedor de IA não está configurado."
        )

    context = _bounded_context(
        [*history, ChatMessage(role="user", content=request.content)]
    )
    try:
        async with AsyncOpenAI(
            api_key=settings.openai_api_key.get_secret_value()
        ) as client:
            completion = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": message.role, "content": message.content}
                    for message in context
                ],
                max_completion_tokens=1024,
            )
    except OpenAIError:
        logger.exception("O fornecedor OpenAI não conseguiu processar a conversa.")
        raise HTTPException(
            status_code=502,
            detail="Não foi possível obter uma resposta do fornecedor de IA.",
        ) from None

    if not completion.choices or not completion.choices[0].message.content:
        raise HTTPException(
            status_code=502,
            detail="O fornecedor de IA devolveu uma resposta vazia.",
        )

    answer = completion.choices[0].message.content
    conversation = session.scalar(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.owner_id == current_user,
        )
    )
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversa não encontrada.")

    if not conversation.messages:
        title = request.content.strip()
        conversation.title = title if len(title) <= 77 else f"{title[:77].rstrip()}..."

    conversation.messages.extend(
        [
            StoredMessage(role="user", content=request.content.strip()),
            StoredMessage(role="assistant", content=answer),
        ]
    )
    try:
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        logger.exception("Não foi possível guardar as mensagens da conversa.")
        raise HTTPException(
            status_code=500, detail="Não foi possível guardar a conversa."
        ) from None

    return ChatResponse(message=answer)
