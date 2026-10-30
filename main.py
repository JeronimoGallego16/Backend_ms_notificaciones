import base64
import os
import pickle
from email.mime.text import MIMEText
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build


SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_DIR = BASE_DIR / "credentials"
CLIENT_SECRET_FILE = CREDENTIALS_DIR / "credentials.json"
TOKEN_FILE = CREDENTIALS_DIR / "token.pickle"
SENDER = os.getenv("GMAIL_SENDER", "jeronimo.gallego60880@ucaldas.edu.co")

app = FastAPI(title="Servicio de notificaciones")


class EmailRequest(BaseModel):
    to: str = Field(..., min_length=3, description="Correo del destinatario")
    text: str = Field(..., min_length=1, description="Texto del correo")


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
                    f"No se encontró el archivo de credenciales: {CLIENT_SECRET_FILE}"
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


def create_message(sender: str, recipient: str, text: str) -> dict[str, str]:
    message = MIMEText(text, "plain", "utf-8")
    message["to"] = recipient
    message["from"] = sender
    message["subject"] = "Notificación"
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    return {"raw": raw_message.decode("utf-8")}


@app.post("/send-email")
def send_email(request: EmailRequest):
    message = create_message(SENDER, request.to, request.text)

    try:
        sent_message = (
            get_gmail_service()
            .users()
            .messages()
            .send(userId="me", body=message)
            .execute()
        )
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="No fue posible enviar el correo"
        ) from error

    return {"message": "Correo enviado correctamente", "id": sent_message["id"]}
