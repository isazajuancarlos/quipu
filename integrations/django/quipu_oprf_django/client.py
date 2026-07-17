"""Cliente OPRF: contraseña -> secreto endurecido de 32 bytes.

El servidor NUNCA ve la contraseña (va cegada) y su respuesta se VERIFICA contra
una clave pública fijada fuera de banda. Sin esa verificación el OPRF no aporta
nada: un servidor tomado podría devolver lo que quisiera.

Aislado de Django a propósito: aquí no se importa nada del framework, de modo que
esta pieza se puede probar y reutilizar sola.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

__all__ = ["OprfClient", "OprfError", "OprfUnavailable", "OprfRejected"]


class OprfError(Exception):
    """Base de los fallos del endurecimiento."""


class OprfUnavailable(OprfError):
    """El servicio no respondió (red, timeout, 5xx) o rechazó la API key.

    Es RECUPERABLE: reintentar más tarde puede funcionar. Nunca se degrada a
    'sin endurecer': eso produciría un hash distinto y, además, silenciaría la
    pérdida de la garantía. Ver R2 del modelo de amenaza.
    """


class OprfRejected(OprfError):
    """La prueba DLEQ no valida contra la clave pública fijada.

    NO es un fallo de red: significa que la respuesta no la produjo la clave que
    fijaste. Servidor comprometido, suplantado, o clave mal configurada. Nunca se
    reintenta a ciegas ni se ignora.
    """


class OprfClient:
    """Endurece contraseñas contra un `quipu-oprf-server`.

    Args:
        base_url:    p. ej. ``https://oprf.xiliux.com``
        api_key:     ``quipu_live_...``
        public_key:  32 bytes de la clave pública del servidor, FIJADOS fuera de
                     banda. Obligatoria: pedírsela al servidor anularía la
                     garantía de verificabilidad.
        timeout:     segundos por petición. Cada login paga este viaje.
    """

    def __init__(self, base_url: str, api_key: str, public_key: bytes, timeout: float = 5.0):
        if not base_url:
            raise ValueError("base_url es obligatorio")
        if not api_key:
            raise ValueError("api_key es obligatoria")
        if len(public_key) != 32:
            raise ValueError(f"public_key debe medir 32 bytes, no {len(public_key)}")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.public_key = public_key
        self.timeout = timeout

    def harden(self, password: bytes) -> bytes:
        """Devuelve 32 bytes derivados de `password` y de la clave del servidor.

        Raises:
            OprfUnavailable: el servicio no respondió o rechazó la key.
            OprfRejected:    la prueba DLEQ no valida (respuesta no confiable).
        """
        # `quipu_voprf` (Apache-2.0), NO `quipu` (AGPL). Este código corre dentro
        # del servidor de auth del cliente: enlazar el núcleo copyleft ahí le
        # arrastraría la AGPL a su SaaS. Importación perezosa: no obliga a
        # tenerlo instalado para importar el módulo.
        import quipu_voprf

        state, blinded = quipu_voprf.voprf_blind(password)

        req = urllib.request.Request(
            f"{self.base_url}/v1/oprf/evaluate",
            data=blinded.hex().encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "text/plain",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:200]
            raise OprfUnavailable(f"el servicio respondió HTTP {e.code}: {detail}") from e
        except Exception as e:  # noqa: BLE001 — red, DNS, timeout, TLS
            raise OprfUnavailable(f"no se pudo contactar el servicio: {e}") from e

        try:
            resp = json.loads(body)
            evaluated = bytes.fromhex(resp["evaluation"])
            proof = bytes.fromhex(resp["proof"])
        except (ValueError, KeyError, TypeError) as e:
            raise OprfUnavailable(f"respuesta ininteligible del servicio: {e}") from e

        # Aquí se cierra el hallazgo F1: si la prueba no valida contra la clave
        # fijada, el resultado NO se usa.
        try:
            return quipu_voprf.voprf_finalize(password, state, evaluated, proof, self.public_key)
        except Exception as e:  # noqa: BLE001
            raise OprfRejected(
                "la prueba DLEQ no valida contra la clave pública fijada: la "
                "respuesta no la produjo esa clave"
            ) from e
