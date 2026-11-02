# Microservicio de notificaciones

Este servicio envía correos mediante Gmail API y genera códigos de segundo
factor (2FA) para que el backend de seguridad pueda completar el inicio de
sesión.

## URL para el backend de seguridad

La URL base local es `http://localhost:8000`. En el ambiente desplegado, usa
la URL pública asignada al servicio:

```text
POST {URL_DEL_SERVICIO}/2fa/request
POST {URL_DEL_SERVICIO}/2fa/verify
POST {URL_DEL_SERVICIO}/internal/email/password-recovery
GET  {URL_DEL_SERVICIO}/health
```

El backend de seguridad debe guardar `challenge_id` durante el flujo de
inicio de sesión y enviarlo al verificar el código. La respuesta de
`/2fa/request` nunca contiene el código.

## Endpoints 2FA

### Solicitar código

```http
POST /2fa/request
Content-Type: application/json

{"email": "persona@example.com"}
```

La respuesta `202` contiene un `challenge_id` y el tiempo de expiración. El
código nunca se devuelve por la API; se envía al correo indicado.

### Verificar código

```http
POST /2fa/verify
Content-Type: application/json

{
  "email": "persona@example.com",
  "challenge_id": "id-recibido-al-solicitar",
  "code": "123456"
}
```

Un código dura cinco minutos por defecto, es de un solo uso y se invalida
después de cinco intentos fallidos. Los retos se almacenan en memoria, por lo
que deben migrarse a un almacenamiento compartido (por ejemplo, Redis) antes
de ejecutar varias réplicas o producción.

## Configuración

```text
GMAIL_SENDER=cuenta-que-envia@example.com
TFA_CODE_TTL_SECONDS=300
TFA_MAX_ATTEMPTS=5
TFA_HASH_SECRET=una-clave-secreta-larga
```

`TFA_HASH_SECRET` debe ser una clave aleatoria de producción y mantenerse
fuera del repositorio. El servicio responde `502` si el envío del correo falla
y `400` si el código es incorrecto, expiró o ya fue utilizado.

## Recuperación de contraseña

El backend de seguridad puede solicitar el envío del enlace de recuperación:

```http
POST /internal/email/password-recovery
X-Service-Token: <secreto-compartido>
Content-Type: application/json

{
  "to": "usuario@ejemplo.com",
  "recoveryUrl": "http://localhost:4200/authentication/reset-password?token=..."
}
```

La ruta responde `202` cuando Gmail acepta el mensaje, `401` si falta o no es
válido `X-Service-Token`, `503` si falta `GMAIL_SENDER` y `502` si falla Gmail.
Este servicio solo retransmite el enlace recibido; no genera, valida ni guarda
tokens. No se debe registrar el enlace ni el header de autenticación.

Spring y FastAPI deben tener configurado el mismo secreto:

```text
Spring:  NOTIFICATION_SERVICE_TOKEN=<secreto-compartido>
FastAPI: SERVICE_TOKEN=<secreto-compartido>
FastAPI: GMAIL_SENDER=cuenta-que-envia@example.com
Spring:  PASSWORD_RECOVERY_RESET_URL=http://localhost:4200/authentication/reset-password
```

Para el desarrollo local en Windows, ejecuta desde PowerShell:

```powershell
.\run-local-password-recovery.ps1 -GmailSender 'cuenta-autorizada@gmail.com'
```

Si omites `-GmailSender`, el iniciador usa `GMAIL_SENDER` si ya está definido
en esa sesión; de lo contrario, lo solicita. FastAPI crea el secreto aleatorio
al arrancar, una sola vez, en `.notification-service-token` (excluido de Git).
FastAPI y Spring leen ese mismo archivo; el iniciador espera a que FastAPI
complete su arranque antes de iniciar Spring. No imprime ni pide copiar el
secreto. Este archivo compartido sirve únicamente para desarrollo en la misma
máquina. En despliegue, ambos servicios deben recibir el mismo secreto desde
el gestor de secretos o desde su entorno.

`GMAIL_SENDER` debe ser una dirección válida y autorizada para Gmail API.

`credentials/credentials.json` y `credentials/token.pickle` son credenciales
locales de Gmail y no deben versionarse. La aplicación espera el cliente OAuth
en `credentials/credentials.json`; en el primer envío abre el flujo de
autorización requerido y guarda el token local en
`credentials/token.pickle`. La respuesta `202` indica que Gmail API aceptó la
solicitud, no confirma que el mensaje llegó a la bandeja del destinatario.

Para iniciar solo FastAPI:

```bash
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

También puedes usar el botón **Run** de VS Code o ejecutar `python main.py`.
En desarrollo se crea automáticamente `.tfa_hash_secret`, que está excluido
de Git. En producción debes definir explícitamente `TFA_HASH_SECRET`.
