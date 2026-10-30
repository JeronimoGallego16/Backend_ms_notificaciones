# Microservicio de notificaciones

Este servicio envía correos mediante Gmail API y genera códigos de segundo
factor (2FA) para que otro servicio los verifique posteriormente.

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

`credentials/credentials.json` y `credentials/token.pickle` son credenciales
locales de Gmail y no deben versionarse.

Para iniciar:

```bash
uvicorn main:app --reload
```
