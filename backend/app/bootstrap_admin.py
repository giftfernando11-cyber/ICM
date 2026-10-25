import argparse
import logging
from uuid import uuid4

from sqlalchemy import func, select

from backend.app.db.models import MfaCredential, SecurityEvent, User, UserRole
from backend.app.db.session import SessionLocal

logger = logging.getLogger(__name__)


def bootstrap_admin(email: str, confirm: bool) -> None:
    if not confirm:
        raise SystemExit("Confirma a operação com --confirm após validar o operador.")
    normalized_email = email.strip().lower()
    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.email == normalized_email))
        if user is None or not user.email_verified:
            raise SystemExit("A conta tem de existir e ter o e-mail confirmado.")
        credential = session.get(MfaCredential, user.id)
        if credential is None or not credential.enabled:
            raise SystemExit("A conta tem de activar MFA antes da promoção.")
        admin_count = session.scalar(
            select(func.count())
            .select_from(UserRole)
            .where(UserRole.role_key == "institutional_admin")
        )
        if admin_count:
            raise SystemExit(
                "Já existe um administrador institucional. Usa o fluxo de aprovação."
            )
        session.add(
            UserRole(
                user_id=user.id,
                role_key="institutional_admin",
                assigned_by="controlled-bootstrap",
            )
        )
        session.add(
            SecurityEvent(
                id=uuid4().hex,
                user_id=user.id,
                event_type="initial_admin_bootstrap",
                detail="Primeiro administrador institucional provisionado offline.",
            )
        )
        session.commit()
        logger.warning(
            "Bootstrap do primeiro administrador institucional concluído para %s.",
            normalized_email,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Atribui a primeira função de administrador institucional."
    )
    parser.add_argument("email", help="E-mail confirmado da conta existente.")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirma que esta operação foi autorizada e revista.",
    )
    arguments = parser.parse_args()
    bootstrap_admin(arguments.email, arguments.confirm)


if __name__ == "__main__":
    main()
