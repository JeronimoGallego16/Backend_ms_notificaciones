"""Notification service configuration.

Real Gmail delivery requires GMAIL_SENDER to be an authorized sender and a
Gmail OAuth client file at credentials/credentials.json. On first use, the
OAuth flow authorizes the Gmail send scope and stores its local token in
credentials/token.pickle. Keep both credential files out of source control.
"""

import base64
import hashlib
import hmac
import html
import logging
import os
import pickle
import secrets
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import lru_cache
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build


logger = logging.getLogger(__name__)
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_DIR = BASE_DIR / "credentials"
CLIENT_SECRET_FILE = CREDENTIALS_DIR / "credentials.json"
TOKEN_FILE = CREDENTIALS_DIR / "token.pickle"
SHARED_SERVICE_TOKEN_FILE = BASE_DIR / ".notification-service-token"
# This must be configured as an environment value, not hardcoded here.
SENDER = os.getenv("GMAIL_SENDER", "").strip()
TFA_CODE_TTL_SECONDS = int(os.getenv("TFA_CODE_TTL_SECONDS", "300"))
TFA_MAX_ATTEMPTS = int(os.getenv("TFA_MAX_ATTEMPTS", "5"))
LOCAL_SECRET_FILE = BASE_DIR / ".tfa_hash_secret"
TFA_HASH_SECRET = os.getenv("TFA_HASH_SECRET")

if not SENDER:
    logger.warning(
        "GMAIL_SENDER is not configured; Gmail message delivery is unavailable"
    )
if not CLIENT_SECRET_FILE.is_file() and not TOKEN_FILE.is_file():
    logger.warning(
        "Gmail OAuth is not configured; provide credentials/credentials.json "
        "and authorize the Gmail send scope"
    )


def _get_or_create_shared_service_token() -> str:
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=".notification-service-token-",
        dir=SHARED_SERVICE_TOKEN_FILE.parent,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as token_file:
            generated_token = secrets.token_urlsafe(32)
            token_file.write(generated_token)
            token_file.flush()
            os.fsync(token_file.fileno())
        try:
            os.link(temporary_path, SHARED_SERVICE_TOKEN_FILE)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary_path)

    token = SHARED_SERVICE_TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("The local shared service-token file is empty")
    return token


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if not os.getenv("SERVICE_TOKEN", "").strip():
        _get_or_create_shared_service_token()
        logger.info("Local shared service-token source is ready")
    yield


if not TFA_HASH_SECRET:
    if LOCAL_SECRET_FILE.exists():
        TFA_HASH_SECRET = LOCAL_SECRET_FILE.read_text(encoding="utf-8").strip()
    else:
        TFA_HASH_SECRET = secrets.token_urlsafe(32)
        LOCAL_SECRET_FILE.write_text(TFA_HASH_SECRET, encoding="utf-8")
        print(
            "Advertencia: se generó una clave 2FA local. "
            "Configura TFA_HASH_SECRET en producción."
        )

app = FastAPI(title="Servicio de notificaciones", lifespan=lifespan)


class EmailRequest(BaseModel):
    to: str = Field(..., min_length=3, description="Correo del destinatario")
    text: str = Field(..., min_length=1, description="Texto del correo")


class TwoFactorRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Correo del usuario")


class TwoFactorVerification(BaseModel):
    email: str = Field(..., min_length=3, description="Correo del usuario")
    challenge_id: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordRecoveryRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    to: str = Field(..., min_length=3, description="Correo del destinatario")
    recovery_url: str = Field(..., alias="recoveryUrl", min_length=1)


@dataclass
class TwoFactorChallenge:
    email: str
    code_hash: str
    expires_at: float
    attempts: int = 0


_challenges: dict[str, TwoFactorChallenge] = {}


def _configured_service_token() -> str:
    environment_token = os.getenv("SERVICE_TOKEN", "").strip()
    if environment_token:
        return environment_token

    try:
        return SHARED_SERVICE_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _hash_code(challenge_id: str, email: str, code: str) -> str:
    value = f"{challenge_id}:{email.strip().lower()}:{code}".encode("utf-8")
    return hmac.new(TFA_HASH_SECRET.encode("utf-8"), value, hashlib.sha256).hexdigest()


def _remove_expired_challenges() -> None:
    now = time.time()
    for challenge_id, challenge in list(_challenges.items()):
        if challenge.expires_at <= now:
            del _challenges[challenge_id]


def _send_message(message: dict[str, str]) -> str:
    try:
        gmail_service = get_gmail_service()
    except Exception as error:
        logger.error(
            "Gmail authentication/client initialization failed (%s)",
            type(error).__name__,
        )
        raise

    try:
        return (
            gmail_service.users()
            .messages()
            .send(userId="me", body=message)
            .execute()["id"]
        )
    except Exception as error:
        logger.error(
            "Gmail API message submission failed (%s)",
            type(error).__name__,
        )
        raise


def request_two_factor_code(request: TwoFactorRequest) -> dict[str, int | str]:
    _remove_expired_challenges()
    challenge_id = secrets.token_urlsafe(32)
    code = f"{secrets.randbelow(1_000_000):06d}"
    email = request.email.strip().lower()
    expires_at = time.time() + TFA_CODE_TTL_SECONDS
    _challenges[challenge_id] = TwoFactorChallenge(
        email=email,
        code_hash=_hash_code(challenge_id, email, code),
        expires_at=expires_at,
    )
    expires_in_minutes = TFA_CODE_TTL_SECONDS // 60
    plain_text = (
        f"Tu código de verificación es: {code}\n"
        f"Este código vence en {expires_in_minutes} minutos."
    )
    html_text = f"""
    <html>
      <body style="margin:0;background-color:#f4f7fb;font-family:Arial,sans-serif;color:#172033;">
        <div style="max-width:560px;margin:32px auto;padding:0 16px;">
          <div style="background-color:#173b70;padding:24px;text-align:center;border-radius:12px 12px 0 0;">
            <h1 style="margin:0;color:#ffffff;font-size:24px;">Verificación de inicio de sesión</h1>
          </div>
          <div style="background-color:#ffffff;padding:32px;text-align:center;border-radius:0 0 12px 12px;">
            <p style="font-size:16px;margin:0 0 20px;">Usa este código para continuar:</p>
            <div style="display:inline-block;padding:16px 28px;border:2px solid #2f80ed;border-radius:10px;background-color:#eef5ff;">
              <span style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#173b70;">{code}</span>
            </div>
            <p style="font-size:14px;color:#5d6878;margin:24px 0 0;">
              Este código vence en <strong>{expires_in_minutes} minutos</strong>.
            </p>
            <p style="font-size:13px;color:#7a8492;margin:20px 0 0;">
              Si no solicitaste este código, puedes ignorar este mensaje.
            </p>
          </div>
        </div>
      </body>
    </html>
    """
    message = create_message(
        SENDER,
        email,
        plain_text,
        html=html_text,
        subject="Tu código de verificación",
    )
    try:
        _send_message(message)
    except Exception as error:
        _challenges.pop(challenge_id, None)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No fue posible enviar el código de verificación",
        ) from error

    return {
        "challenge_id": challenge_id,
        "expires_in": TFA_CODE_TTL_SECONDS,
    }


def verify_two_factor_code(request: TwoFactorVerification) -> dict[str, bool]:
    _remove_expired_challenges()
    challenge = _challenges.get(request.challenge_id)
    email = request.email.strip().lower()
    if not challenge or challenge.email != email:
        raise HTTPException(status_code=400, detail="Código inválido o expirado")

    challenge.attempts += 1
    expected_hash = _hash_code(request.challenge_id, email, request.code)
    if not hmac.compare_digest(challenge.code_hash, expected_hash):
        if challenge.attempts >= TFA_MAX_ATTEMPTS:
            del _challenges[request.challenge_id]
        raise HTTPException(status_code=400, detail="Código inválido o expirado")

    del _challenges[request.challenge_id]
    return {"verified": True}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/2fa/request", status_code=status.HTTP_202_ACCEPTED)
def request_two_factor(request: TwoFactorRequest) -> dict[str, int | str]:
    return request_two_factor_code(request)


@app.post("/2fa/verify")
def verify_two_factor(request: TwoFactorVerification) -> dict[str, bool]:
    return verify_two_factor_code(request)


@app.post("/internal/email/password-recovery", status_code=status.HTTP_202_ACCEPTED)
def send_password_recovery_email(
    request: PasswordRecoveryRequest,
    service_token: str | None = Header(default=None, alias="X-Service-Token"),
) -> dict[str, str]:
    logger.info("Password recovery request received")
    configured_token = _configured_service_token()
    if (
        not service_token
        or not configured_token
        or not secrets.compare_digest(
            service_token.encode("utf-8"), configured_token.encode("utf-8")
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credencial de servicio inválida",
        )
    logger.info("Password recovery service credential accepted")

    if not SENDER:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de correo no configurado",
        )

    safe_recovery_url = html.escape(request.recovery_url, quote=True)
    plain_text = (
        "Recibimos una solicitud para restablecer tu contraseña.\n\n"
        f"Usa este enlace para continuar: {request.recovery_url}\n\n"
        "Si no solicitaste este cambio, puedes ignorar este mensaje."
    )
    html_text = f"""
    <html>
      <body style="font-family:Arial,sans-serif;color:#172033;">
        <h1>Restablecer contraseña</h1>
        <p>Recibimos una solicitud para restablecer tu contraseña.</p>
        <p><a href="{safe_recovery_url}">Continuar con el restablecimiento</a></p>
        <p>Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
      </body>
    </html>
    """
    message = create_message(
        SENDER,
        request.to,
        plain_text,
        html=html_text,
        subject="Recuperación de contraseña",
    )
    try:
        _send_message(message)
    except Exception as error:
        logger.error(
            "Password recovery email submission failed (%s)",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No fue posible enviar el correo de recuperación",
        ) from None

    logger.info("Gmail API accepted password recovery message")
    return {"message": "Gmail API accepted password recovery message"}


def authenticate_gmail():
    credentials = None

    if TOKEN_FILE.exists():
        with TOKEN_FILE.open("rb") as token:
            credentials = pickle.load(token)

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            if not CLIENT_SECRET_FILE.exists():
                raise FileNotFoundError(
                    "Gmail OAuth is not configured: provide "
                    "credentials/credentials.json and authorize the Gmail send scope"
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                str(CLIENT_SECRET_FILE), SCOPES
            )
            credentials = flow.run_local_server(port=0)

        CREDENTIALS_DIR.mkdir(exist_ok=True)
        with TOKEN_FILE.open("wb") as token:
            pickle.dump(credentials, token)

    return credentials


@lru_cache(maxsize=1)
def get_gmail_service() -> Resource:
    credentials = authenticate_gmail()
    return build("gmail", "v1", credentials=credentials)


def create_message(
    sender: str,
    recipient: str,
    text: str,
    html: str | None = None,
    subject: str = "Notificación",
) -> dict[str, str]:
    if html:
        message = MIMEMultipart("alternative")
        message.attach(MIMEText(text, "plain", "utf-8"))
        message.attach(MIMEText(html, "html", "utf-8"))
    else:
        message = MIMEText(text, "plain", "utf-8")
    message["to"] = recipient
    message["from"] = sender
    message["subject"] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    return {"raw": raw_message.decode("utf-8")}


@app.post("/send-email")
def send_email(request: EmailRequest):
    message = create_message(SENDER, request.to, request.text)

    try:
        message_id = _send_message(message)
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="No fue posible enviar el correo"
        ) from error

    return {"message": "Correo enviado correctamente", "id": message_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
