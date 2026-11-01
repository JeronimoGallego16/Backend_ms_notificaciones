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

`credentials/credentials.json` y `credentials/token.pickle` son credenciales
locales de Gmail y no deben versionarse.

Para iniciar:

```bash
uvicorn main:app --reload
```

También puedes usar el botón **Run** de VS Code o ejecutar `python main.py`.
En desarrollo se crea automáticamente `.tfa_hash_secret`, que está excluido
de Git. En producción debes definir explícitamente `TFA_HASH_SECRET`.
