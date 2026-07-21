"""Andamiaje de pruebas.

IMPORTANTE — qué se prueba aquí y qué NO:

  SÍ:  el cableado del plugin. Que un servicio caído no se confunda con una
       contraseña incorrecta; que un servidor mentiroso se rechace; que el
       hasher falle CERRADO y jamás degrade a Argon2 pelado.

  NO:  la criptografía. `voprf_blind`/`voprf_finalize` se sustituyen por un
       doble que simula el CONTRATO del VOPRF (una prueba válida verifica,
       una de otra clave no). El VOPRF real está probado en Rust
       (`src/voprf.rs`, `crates/quipu-oprf-server/tests/e2e.rs`) y con los
       clientes de los 4 lenguajes en `scripts/oprf-e2e.sh`.

El doble hace falta porque el módulo `quipu` con las funciones VOPRF aún no está
publicado en PyPI (0.7.0 no las trae) y esta máquina no puede compilarlo: no
tiene enlazador MSVC.
"""

import hashlib
import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# --- Doble del módulo `quipu`: simula el contrato, no la criptografía ---------

def _fake_blind(password: bytes):
    state = hashlib.sha512(b"state" + password).digest()  # 64 B, como el real
    blinded = hashlib.sha256(b"blind" + password).digest()  # 32 B
    return state, blinded


def _fake_finalize(password, state, evaluated, proof, server_pub):
    """Rechaza si la prueba no corresponde a `server_pub`, como haría el DLEQ."""
    if proof != hashlib.sha256(b"proof" + server_pub + evaluated).digest():
        raise ValueError("prueba DLEQ inválida (doble de pruebas)")
    return hashlib.sha256(b"final" + password + evaluated).digest()  # 32 B


@pytest.fixture(autouse=True)
def quipu_doble(monkeypatch):
    # OJO CON EL NOMBRE DEL MÓDULO: `client.py` importa `quipu_voprf` (el SDK
    # Apache-2.0), NO `quipu` (el núcleo AGPL). Es toda la razón de ser del
    # reparto de licencias: este plugin vive dentro del servidor de auth del
    # cliente y no puede arrastrarle copyleft de red.
    #
    # Este doble parcheaba "quipu" y por tanto NO SE APLICABA: corría la
    # librería real, que rechazaba —con razón— la prueba DLEQ de 32 bytes que
    # fabrica este archivo. Once pruebas «pasaban» antes por no tener instalada
    # la librería real, y fallaban en cuanto se instalaba. Nadie lo vio porque
    # el CI no ejecutaba `integrations/`. Corregido el 2026-07-21.
    mod = types.ModuleType("quipu_voprf")
    mod.voprf_blind = _fake_blind
    mod.voprf_finalize = _fake_finalize
    monkeypatch.setitem(sys.modules, "quipu_voprf", mod)
    yield mod


# --- Servidor OPRF falso ------------------------------------------------------

CLAVE = b"\xaa" * 32       # "clave secreta" del servidor
PUB = b"\x11" * 32         # su clave pública (la que el cliente fija)
OTRA_PUB = b"\x22" * 32    # la de un impostor


class _Handler(BaseHTTPRequestHandler):
    # `modo` vive en el SERVIDOR (self.server), no en la clase: como atributo de
    # clase era estado global y se filtraba entre tests.

    def log_message(self, *a):
        pass

    def _responder(self, code, body: bytes, ctype="text/plain"):
        """Siempre con Content-Length: sin él, urllib compite contra el cierre de
        conexión y el mismo test falla o pasa según la carga de la máquina."""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # El cuerpo se lee SIEMPRE y lo PRIMERO, incluso en los modos de fallo.
        # Si respondes dejando datos sin leer en el socket, al cerrar la conexión
        # Windows manda un RST y el cliente revienta con WinError 10053 antes de
        # poder leer la respuesta. Era la causa del test flaky: una carrera entre
        # el RST y la lectura del 401.
        n = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(n) if n else b""

        m = self.server.modo
        if m in ("caido", "sin_key"):
            self._responder(503 if m == "caido" else 401, b"fallo simulado")
            return
        if m == "basura":
            self._responder(200, b"esto no es json")
            return

        blinded = bytes.fromhex(cuerpo.decode())
        evaluated = hashlib.sha256(CLAVE + blinded).digest()
        # El mentiroso responde con la prueba de OTRA clave: en forma es válida,
        # pero no puede verificar contra la clave que el cliente fijó.
        pub = OTRA_PUB if m == "mentiroso" else PUB
        proof = hashlib.sha256(b"proof" + pub + evaluated).digest()

        body = json.dumps({"evaluation": evaluated.hex(), "proof": proof.hex()}).encode()
        self._responder(200, body, "application/json")


@pytest.fixture
def servidor():
    """Servidor OPRF falso. `servidor.set_modo("...")` cambia su comportamiento."""
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.modo = "honesto"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    httpd.url = f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.pub = PUB
    httpd.set_modo = lambda m: setattr(httpd, "modo", m)
    yield httpd
    httpd.shutdown()
    # server_close() es obligatorio: shutdown() solo para el bucle y deja el
    # socket abierto. Con SO_REUSEADDR, otro servidor cogía el mismo puerto y la
    # petición caía en el socket huérfano -> timeout en vez de la respuesta
    # esperada. Ese era el test flaky.
    httpd.server_close()
