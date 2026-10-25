from urllib.parse import urlparse

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./mindia.db"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o-mini"
    auth_secret_key: SecretStr | None = None
    auth_cookie_secure: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_starttls: bool = True
    twilio_account_sid: str | None = None
    twilio_auth_token: SecretStr | None = None
    twilio_from_number: str | None = None
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    google_redirect_uri: str | None = None
    facebook_client_id: str | None = None
    facebook_client_secret: SecretStr | None = None
    facebook_redirect_uri: str | None = None
    frontend_base_url: str = "http://localhost:5173"
    arpqi_owner_email: str | None = None
    arpqi_owner_phone: str | None = None
    auth_demo_mode: bool = False

    @field_validator("frontend_base_url", mode="before")
    @classmethod
    def normalize_frontend_base_url(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        value = value.strip().rstrip("/")
        if "://" not in value:
            value = f"https://{value}"
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("FRONTEND_BASE_URL tem de ser uma origem HTTP(S) válida.")
        return value

    @field_validator(
        "openai_api_key",
        "auth_secret_key",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from",
        "twilio_account_sid",
        "twilio_auth_token",
        "twilio_from_number",
        "google_client_id",
        "google_client_secret",
        "google_redirect_uri",
        "facebook_client_id",
        "facebook_client_secret",
        "facebook_redirect_uri",
        "arpqi_owner_email",
        "arpqi_owner_phone",
        mode="before",
    )
    @classmethod
    def empty_secret_is_unconfigured(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("arpqi_owner_email")
    @classmethod
    def normalize_arpqi_owner_email(cls, value: str | None) -> str | None:
        return value.strip().lower() if value else None

    @field_validator("arpqi_owner_phone")
    @classmethod
    def normalize_arpqi_owner_phone(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = "".join(value.split())
        if not normalized.startswith("+") or not normalized[1:].isdigit():
            raise ValueError(
                "ARPQI_OWNER_PHONE tem de usar o formato internacional, por exemplo +258840000000."
            )
        return normalized

    @field_validator("auth_secret_key")
    @classmethod
    def require_strong_signing_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("AUTH_SECRET_KEY tem de ter pelo menos 32 caracteres.")
        return value

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def auth_configured(self) -> bool:
        is_local_demo = self.auth_demo_mode and urlparse(
            self.frontend_base_url
        ).hostname in {"localhost", "127.0.0.1", "::1"}
        return bool(
            self.auth_secret_key
            and ((self.smtp_host and self.smtp_from) or is_local_demo)
        )

    @property
    def arpqi_configured(self) -> bool:
        return bool(self.arpqi_owner_email and self.smtp_host and self.smtp_from)

    @property
    def cors_allowed_origins(self) -> list[str]:
        parsed = urlparse(self.frontend_base_url)
        origins = [f"{parsed.scheme}://{parsed.netloc}"]
        if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            origins.extend(
                ["http://localhost:5173", "http://127.0.0.1:5173"]
            )
        return list(dict.fromkeys(origins))


settings = Settings()
