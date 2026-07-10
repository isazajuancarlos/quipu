"""Cliente OPRF de referencia (Python) para un `quipu-oprf-server`.

Flujo verificable de endurecimiento:
  1. quipu.voprf_blind(password)        -> el servidor nunca ve la contraseña.
  2. POST /v1/oprf/evaluate (API key)   -> evaluación + prueba DLEQ.
  3. quipu.voprf_finalize(...)          -> VERIFICA la prueba contra la clave
     pública FIJADA y deriva el secreto endurecido.

Uso:
  QUIPU_OPRF_URL=https://oprf.tudominio.com \\
  QUIPU_OPRF_API_KEY=quipu_live_... \\
  python examples/oprf_client.py "mi-contraseña"

En producción, FIJA (pin) la clave pública fuera de banda con QUIPU_OPRF_PUBKEY
en vez de pedirla al servidor.
"""

import json
import os
import sys
import urllib.request

import quipu


def _http(url, method, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req) as r:
        return r.status, r.read().decode()


def harden(password, base_url, api_key, server_pub=None):
    """Devuelve el secreto endurecido (bytes) para `password`."""
    base = base_url.rstrip("/")
    if server_pub is None:
        _, body = _http(base + "/v1/public-key", "GET")
        server_pub = bytes.fromhex(json.loads(body)["public_key"])

    state, blinded = quipu.voprf_blind(password)
    _, body = _http(
        base + "/v1/oprf/evaluate",
        "POST",
        data=blinded.hex().encode(),
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "text/plain"},
    )
    resp = json.loads(body)
    evaluated = bytes.fromhex(resp["evaluation"])
    proof = bytes.fromhex(resp["proof"])
    # Lanza ValueError si la prueba DLEQ no valida contra server_pub.
    return quipu.voprf_finalize(password, state, evaluated, proof, server_pub)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("uso: oprf_client.py <contraseña>")
    url = os.environ.get("QUIPU_OPRF_URL", "http://127.0.0.1:8787")
    api_key = os.environ["QUIPU_OPRF_API_KEY"]
    pinned = os.environ.get("QUIPU_OPRF_PUBKEY")
    pub = bytes.fromhex(pinned) if pinned else None
    secret = harden(sys.argv[1].encode(), url, api_key, pub)
    print("secreto endurecido:", secret.hex())
