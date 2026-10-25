from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.routes.auth import InstitutionalRole, get_current_user
from backend.app.db.models import UserRole
from backend.app.db.session import get_db

router = APIRouter()


class DashboardModule(BaseModel):
    key: str
    title: str
    description: str
    status: Literal["available", "planned"]


class RolePanel(BaseModel):
    role_key: InstitutionalRole
    title: str
    modules: list[DashboardModule]


class DashboardResponse(BaseModel):
    roles: list[RolePanel]


ROLE_PANELS: dict[InstitutionalRole, RolePanel] = {
    "student": RolePanel(
        role_key="student",
        title="Área do estudante",
        modules=[
            DashboardModule(
                key="academic-record",
                title="Percurso académico",
                description="Consulta de matrícula, disciplinas, avaliações e resultados.",
                status="planned",
            ),
            DashboardModule(
                key="student-documents",
                title="Documentos e declarações",
                description="Pedidos e acompanhamento de documentos académicos.",
                status="planned",
            ),
            DashboardModule(
                key="academic-calendar",
                title="Calendário académico",
                description="Datas e actividades académicas confirmadas pelo ICM.",
                status="planned",
            ),
        ],
    ),
    "teacher": RolePanel(
        role_key="teacher",
        title="Área do docente",
        modules=[
            DashboardModule(
                key="classes",
                title="Turmas e disciplinas",
                description="Acesso às turmas e disciplinas atribuídas.",
                status="planned",
            ),
            DashboardModule(
                key="assessment",
                title="Avaliações e pautas",
                description="Registo e consulta de avaliações autorizadas.",
                status="planned",
            ),
            DashboardModule(
                key="teaching-materials",
                title="Materiais pedagógicos",
                description="Partilha de materiais com as turmas atribuídas.",
                status="planned",
            ),
        ],
    ),
    "staff": RolePanel(
        role_key="staff",
        title="Área do funcionário",
        modules=[
            DashboardModule(
                key="internal-tasks",
                title="Tarefas e serviços internos",
                description="Consulta e acompanhamento de tarefas institucionais.",
                status="planned",
            ),
            DashboardModule(
                key="staff-documents",
                title="Documentos de serviço",
                description="Consulta de documentos autorizados para a função.",
                status="planned",
            ),
        ],
    ),
    "administrative_services": RolePanel(
        role_key="administrative_services",
        title="Serviços administrativos",
        modules=[
            DashboardModule(
                key="enrolments",
                title="Matrículas e processos",
                description="Gestão dos processos administrativos de estudantes.",
                status="planned",
            ),
            DashboardModule(
                key="service-desk",
                title="Atendimento",
                description="Registo e acompanhamento de pedidos de atendimento.",
                status="planned",
            ),
            DashboardModule(
                key="official-documents",
                title="Documentação",
                description="Emissão e acompanhamento de documentos oficiais.",
                status="planned",
            ),
        ],
    ),
    "direction": RolePanel(
        role_key="direction",
        title="Painel da Direcção",
        modules=[
            DashboardModule(
                key="institutional-indicators",
                title="Indicadores institucionais",
                description="Indicadores baseados em dados oficiais validados.",
                status="planned",
            ),
            DashboardModule(
                key="institutional-reports",
                title="Relatórios",
                description="Relatórios de gestão de acordo com as regras do ICM.",
                status="planned",
            ),
        ],
    ),
    "institutional_admin": RolePanel(
        role_key="institutional_admin",
        title="Administração institucional",
        modules=[
            DashboardModule(
                key="access-requests",
                title="Pedidos de acesso",
                description="Revisão de pedidos de funções institucionais.",
                status="available",
            ),
            DashboardModule(
                key="institutional-content",
                title="Conteúdos institucionais",
                description="Gestão de conteúdos oficiais após validação do ICM.",
                status="planned",
            ),
        ],
    ),
    "technical_admin": RolePanel(
        role_key="technical_admin",
        title="Administração técnica",
        modules=[
            DashboardModule(
                key="system-monitoring",
                title="Monitorização do sistema",
                description="Estado dos serviços e integrações técnicas.",
                status="planned",
            ),
            DashboardModule(
                key="security-audit",
                title="Auditoria e segurança",
                description="Consulta controlada de eventos de segurança.",
                status="planned",
            ),
        ],
    ),
    "arpqi": RolePanel(
        role_key="arpqi",
        title="Área restrita ARPQI",
        modules=[
            DashboardModule(
                key="arpqi-restricted-workspace",
                title="Espaço de trabalho ARPQI",
                description=(
                    "Acesso limitado a duas contas autorizadas pelo titular."
                ),
                status="planned",
            ),
        ],
    ),
}


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(
    current_user: str = Depends(get_current_user),
    session: Session = Depends(get_db),
) -> DashboardResponse:
    assigned_roles = set(
        session.scalars(
            select(UserRole.role_key).where(UserRole.user_id == current_user)
        )
    )
    return DashboardResponse(
        roles=[
            panel
            for role_key, panel in ROLE_PANELS.items()
            if role_key in assigned_roles
        ]
    )
