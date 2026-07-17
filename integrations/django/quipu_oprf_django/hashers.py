"""Hasher de contraseñas para Django endurecido con el OPRF de Quipu.

Qué cambia respecto de Argon2 a secas:

    Argon2 solo:   robas la BD -> fuerza bruta offline, a la velocidad de tu GPU.
    Con OPRF:      robas la BD -> NO puedes derivar nada sin la clave del
                   servidor. Cada intento exige una petición que tú ves,
                   limitas y puedes cortar.

El servidor nunca ve la contraseña (va cegada) ni puede mentir (prueba DLEQ
verificada contra una clave fijada).

Instalación (settings.py):

    PASSWORD_HASHERS = [
        "quipu_oprf_django.hashers.OprfArgon2PasswordHasher",   # preferido
        "django.contrib.auth.hashers.Argon2PasswordHasher",     # migración
        "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    ]

    QUIPU_OPRF = {
        "BASE_URL":   os.environ["QUIPU_OPRF_URL"],
        "API_KEY":    os.environ["QUIPU_OPRF_API_KEY"],
        "PUBLIC_KEY": os.environ["QUIPU_OPRF_PUBKEY"],  # 64 hex, FIJADA fuera de banda
        "TIMEOUT":    5.0,
    }

Migración de usuarios existentes: al poner este hasher el PRIMERO y dejar
`Argon2PasswordHasher` detrás, Django verifica los hashes antiguos con su hasher
original y los RE-CODIFICA con el preferido en el siguiente login correcto. No
hace falta script: los usuarios migran solos al entrar.
"""

from __future__ import annotations

from django.contrib.auth.hashers import Argon2PasswordHasher
from django.core.exceptions import ImproperlyConfigured

from .client import OprfClient, OprfRejected, OprfUnavailable

__all__ = ["OprfArgon2PasswordHasher"]

_client: OprfClient | None = None


def _get_client() -> OprfClient:
    """Cliente único, construido en el primer uso desde `settings.QUIPU_OPRF`."""
    global _client
    if _client is not None:
        return _client

    from django.conf import settings

    cfg = getattr(settings, "QUIPU_OPRF", None)
    if not cfg:
        raise ImproperlyConfigured(
            "Falta QUIPU_OPRF en settings. Se necesitan BASE_URL, API_KEY y PUBLIC_KEY."
        )
    faltan = [k for k in ("BASE_URL", "API_KEY", "PUBLIC_KEY") if not cfg.get(k)]
    if faltan:
        raise ImproperlyConfigured(f"QUIPU_OPRF incompleto, falta: {', '.join(faltan)}")

    pub_hex = cfg["PUBLIC_KEY"].strip()
    try:
        pub = bytes.fromhex(pub_hex)
    except ValueError as e:
        raise ImproperlyConfigured("QUIPU_OPRF['PUBLIC_KEY'] debe ser hexadecimal") from e
    if len(pub) != 32:
        raise ImproperlyConfigured(
            f"QUIPU_OPRF['PUBLIC_KEY'] debe medir 32 bytes (64 hex), no {len(pub)}"
        )

    _client = OprfClient(
        base_url=cfg["BASE_URL"],
        api_key=cfg["API_KEY"],
        public_key=pub,
        timeout=float(cfg.get("TIMEOUT", 5.0)),
    )
    return _client


def reset_client() -> None:
    """Descarta el cliente memorizado. Para tests, o tras rotar la API key."""
    global _client
    _client = None


class OprfArgon2PasswordHasher(Argon2PasswordHasher):
    """Argon2id sobre el secreto endurecido, en vez de sobre la contraseña.

    Toda la mecánica de Argon2 (parámetros, salt, formato, `must_update`) la
    hereda de Django. Lo único que se interpone es el endurecimiento previo.
    """

    algorithm = "quipu_oprf_argon2"

    def _harden(self, password: str) -> str:
        """Contraseña -> 64 hex del secreto endurecido, que es lo que ve Argon2.

        Falla CERRADO: si el servicio no responde o la prueba no valida, esto
        levanta. Nunca devuelve la contraseña sin endurecer — hacerlo produciría
        un hash que no casa con nada y, peor, ocultaría la pérdida de la
        garantía justo cuando importa.
        """
        secreto = _get_client().harden(password.encode("utf-8"))
        return secreto.hex()

    def encode(self, password: str, salt: str) -> str:
        return super().encode(self._harden(password), salt)

    def verify(self, password: str, encoded: str) -> bool:
        # Un fallo del servicio NO es una contraseña incorrecta: se propaga.
        # Devolver False aquí le diría al usuario "clave errónea" durante una
        # caída, y acabaría reseteando su contraseña por un problema de red.
        return super().verify(self._harden(password), encoded)

    def harden_runtime(self, password: str, encoded: str) -> None:
        # Django llama a esto para igualar el coste entre hashers. El nuestro ya
        # pagó el viaje de red en verify(); repetirlo solo añade latencia.
        pass
