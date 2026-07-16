"""Endurecimiento de contraseñas con VOPRF de Quipu para Django.

Cambia una línea de `PASSWORD_HASHERS` y tu base de usuarios deja de ser
crackeable offline: sin la clave del servidor OPRF, un volcado de la tabla no
permite derivar nada.
"""

from .client import OprfClient, OprfError, OprfRejected, OprfUnavailable
from .hashers import OprfArgon2PasswordHasher, reset_client

__version__ = "0.1.0"
__all__ = [
    "OprfArgon2PasswordHasher",
    "OprfClient",
    "OprfError",
    "OprfRejected",
    "OprfUnavailable",
    "reset_client",
]
