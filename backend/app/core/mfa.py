import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote

import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from fastapi import HTTPException

from backend.app.core.config import settings

TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
RECOVERY_CODE_COUNT = 10


def _encryption_key() -> bytes:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    return hashlib.sha256(
        b"icm-mfa-secret-v1:" + settings.auth_secret_key.get_secret_value().encode()
    ).digest()


def encrypt_totp_secret(secret: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_encryption_key()).encrypt(nonce, secret, b"icm-mfa-v1")
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_totp_secret(encrypted: str) -> bytes:
    try:
        payload = base64.urlsafe_b64decode(encrypted.encode())
        return AESGCM(_encryption_key()).decrypt(
            payload[:12], payload[12:], b"icm-mfa-v1"
        )
    except (ValueError, IndexError, InvalidTag):
        raise HTTPException(
            status_code=500, detail="Não foi possível validar a configuração MFA."
        ) from None


def new_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def totp_code(secret: bytes, timestamp: int | None = None) -> tuple[str, int]:
    step = (timestamp or int(time.time())) // TOTP_PERIOD_SECONDS
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % (10**TOTP_DIGITS):0{TOTP_DIGITS}d}", step


def verify_totp(secret: bytes, code: str, now: int | None = None) -> int | None:
    timestamp = int(time.time()) if now is None else now
    current_step = timestamp // TOTP_PERIOD_SECONDS
    for step in (current_step - 1, current_step, current_step + 1):
        expected, _ = totp_code(secret, step * TOTP_PERIOD_SECONDS)
        if hmac.compare_digest(expected, code):
            return step
    return None


def provisioning_uri(secret: bytes, email: str) -> str:
    encoded_secret = base64.b32encode(secret).decode().rstrip("=")
    issuer = "ICM Digital"
    label = quote(f"{issuer}:{email}")
    return (
        f"otpauth://totp/{label}?secret={encoded_secret}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def provisioning_qr_data_url(uri: str) -> str:
    image = qrcode.make(uri)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()


def new_recovery_codes() -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return [
        "-".join(
            "".join(secrets.choice(alphabet) for _ in range(4))
            for _ in range(3)
        )
        for _ in range(RECOVERY_CODE_COUNT)
    ]


def recovery_code_digest(code: str) -> str:
    if settings.auth_secret_key is None:
        raise HTTPException(
            status_code=503, detail="A autenticação ainda não está configurada."
        )
    normalized = code.replace("-", "").strip().upper()
    return hmac.new(
        settings.auth_secret_key.get_secret_value().encode(),
        b"icm-recovery-v1:" + normalized.encode(),
        hashlib.sha256,
    ).hexdigest()
