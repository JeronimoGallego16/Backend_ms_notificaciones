from __future__ import print_function
import base64
from email.mime.text import MIMEText
import os
import pickle

from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Alcance de la API (permite enviar correos)
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_DIR = os.path.join(os.path.dirname(__file__), 'credentials')
CLIENT_SECRET_FILE = os.path.join(CREDENTIALS_DIR, 'credentials.json')
TOKEN_FILE = os.path.join(CREDENTIALS_DIR, 'token.pickle')

def authenticate_gmail():
    creds = None
    # Cargar credenciales si ya existen
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    # Si no hay credenciales válidas, iniciar flujo OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        os.makedirs(CREDENTIALS_DIR, exist_ok=True)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return creds

def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw_message.decode()}

def send_message(service, user_id, message):
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        print(f"✅ Mensaje enviado. ID: {sent_message['id']}")
        return sent_message
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    mensaje = create_message(
        sender="felipe.buitragoca@autonoma.edu.co",
        to="felipebuitragocarmona@gmail.com,felipe.buitrago@ucaldas.edu.co",
        subject="Prueba Gmail API",
        message_text="Hola, este es un correo enviado con la Gmail API en Python."
    )
    send_message(service, 'me', mensaje)
