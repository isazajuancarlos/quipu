# quipu-oprf-django

Endurecimiento de contraseñas con VOPRF para Django. **Una línea en `PASSWORD_HASHERS`
y tu tabla de usuarios deja de ser crackeable offline.**

```
Argon2 solo:   te roban la BD  ->  fuerza bruta offline, a la velocidad de su GPU.
Con OPRF:      te roban la BD  ->  no pueden derivar nada. Cada intento exige una
                                   petición a tu servidor: la ves, la limitas y la cortas.
```

El servidor **nunca ve la contraseña** (viaja cegada) y **no puede mentir**: cada
respuesta trae una prueba DLEQ que el cliente verifica contra una clave pública
que fijas tú.

> **Estado: beta.** El servicio está pre-auditoría. Ver "Antes de producción".

## Instalación

```sh
pip install quipu-oprf-django
```

```python
# settings.py
PASSWORD_HASHERS = [
    "quipu_oprf_django.hashers.OprfArgon2PasswordHasher",   # preferido
    "django.contrib.auth.hashers.Argon2PasswordHasher",     # para migrar (ver abajo)
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

QUIPU_OPRF = {
    "BASE_URL":   os.environ["QUIPU_OPRF_URL"],      # https://oprf.xiliux.com
    "API_KEY":    os.environ["QUIPU_OPRF_API_KEY"],  # quipu_live_...
    "PUBLIC_KEY": os.environ["QUIPU_OPRF_PUBKEY"],   # 64 hex — ver "Fijar la clave"
    "TIMEOUT":    5.0,
}
```

Nada más. `User.set_password()` y `authenticate()` siguen funcionando igual.

## Migrar usuarios existentes

**No hace falta script.** Deja `Argon2PasswordHasher` (o el que uses) *después* del
nuestro en la lista: Django verifica cada hash antiguo con su hasher original y lo
**re-codifica con el preferido** en el siguiente login correcto. Los usuarios migran
solos según entran.

## Fijar la clave pública

`PUBLIC_KEY` debe venir **fuera de banda** — del README de tu proveedor, de tu gestor
de secretos, de donde sea menos del propio servidor.

Pedírsela a `/v1/public-key` anula la garantía: la prueba DLEQ demuestra que el
servidor usó la clave correspondiente a la clave pública **que tú fijaste**. Si el
servidor también elige contra qué se le verifica, un servidor comprometido puede
responder lo que quiera. Por eso este paquete **exige** `PUBLIC_KEY` y no la descarga.

Instancia beta:

```
BASE_URL    https://oprf.xiliux.com
PUBLIC_KEY  f84ef4132b8351921eda4f841ec2cf7aacb23fd3c93ac6118b48dfc4babaa16f
```

## Falla cerrado, a propósito

Si el servicio no responde, **el login falla**; no se degrada a Argon2 pelado.

No es rigidez: un hash sin endurecer no casaría con el guardado, así que degradar
sería *además* de inseguro, incorrecto. Y `verify()` **levanta** en vez de devolver
`False`, porque una caída no es una contraseña incorrecta — decir "clave errónea"
durante un incidente de red manda al usuario a resetear su contraseña por nada.

| Excepción | Qué pasó | Qué hacer |
|---|---|---|
| `OprfUnavailable` | red, timeout, 5xx, o API key rechazada | reintentar; mirar el servicio |
| `OprfRejected` | la prueba DLEQ **no valida** contra tu clave fijada | **investigar**: no lo produjo esa clave |

`OprfRejected` nunca es un fallo transitorio. Significa servidor comprometido,
suplantado, o `PUBLIC_KEY` mal configurada. No lo reintentes a ciegas.

## Antes de producción

- **Cada login paga un viaje de red.** Ajusta `TIMEOUT` y ten en cuenta la latencia
  hasta tu servidor OPRF.
- **El servicio es un punto único de fallo** (R2 del modelo de amenaza): si cae, nadie
  entra. Planifica alta disponibilidad.
- **La semilla del servidor es crítica.** Si se pierde, ningún usuario vuelve a
  entrar: los hashes guardados no se pueden reproducir. Respáldala.
- **Servicio en beta, pre-auditoría externa.**

## Licencia

**Sin decidir, y hay que resolverlo antes de publicar.**

El núcleo de Quipu es AGPL-3.0-or-later. Este plugin importa `quipu`, así que hoy la
AGPL se propagaría a cualquier SaaS que lo instale — y ninguna empresa mete AGPL en
sus `PASSWORD_HASHERS`. O sea: la licencia bloquearía la rampa de entrada al servicio
de pago, que es exactamente lo que este paquete existe para abrir.

El patrón habitual de open-core es **núcleo copyleft + SDK de cliente permisivo**
(Apache-2.0): MongoDB con SSPL y drivers Apache, Elastic, Redis. El titular único del
copyright puede relicenciar el subconjunto del cliente VOPRF sin tocar el núcleo.

## Pruebas

```sh
pip install -e ".[dev]" argon2-cffi
pytest
```

Las pruebas usan un **doble** de `quipu` que simula el *contrato* del VOPRF: aquí se
verifica el cableado del plugin (clasificación de errores, fallo cerrado, migración),
**no la criptografía**. Esa vive en Rust — `src/voprf.rs`,
`crates/quipu-oprf-server/tests/e2e.rs` — y los 4 clientes de referencia se contrastan
entre sí en `scripts/oprf-e2e.sh`.
