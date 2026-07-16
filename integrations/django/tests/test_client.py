"""Cliente OPRF: clasificación de fallos y rechazo del servidor mentiroso.

Ver conftest.py para el alcance: aquí se prueba el cableado, no la criptografía.
"""

import pytest

from quipu_oprf_django.client import OprfClient, OprfRejected, OprfUnavailable


def _cliente(servidor, pub=None, timeout=5.0):
    return OprfClient(servidor.url, "quipu_live_test", pub or servidor.pub, timeout)


# --- Configuración: fallar pronto y claro ------------------------------------

def test_public_key_debe_medir_32_bytes():
    with pytest.raises(ValueError, match="32 bytes"):
        OprfClient("http://x", "k", b"corta")


def test_api_key_obligatoria():
    with pytest.raises(ValueError, match="api_key"):
        OprfClient("http://x", "", b"\x00" * 32)


def test_base_url_obligatoria():
    with pytest.raises(ValueError, match="base_url"):
        OprfClient("", "k", b"\x00" * 32)


# --- Camino feliz -------------------------------------------------------------

def test_harden_devuelve_32_bytes(servidor):
    out = _cliente(servidor).harden("mi-contraseña".encode("utf-8"))
    assert len(out) == 32


def test_acepta_utf8_no_ascii(servidor):
    """Las contraseñas reales llevan acentos, eñes y emoji."""
    c = _cliente(servidor)
    assert len(c.harden("contraseña-ñandú-🔐".encode("utf-8"))) == 32


def test_harden_es_determinista(servidor):
    c = _cliente(servidor)
    assert c.harden(b"misma") == c.harden(b"misma")


def test_contrasenas_distintas_dan_secretos_distintos(servidor):
    c = _cliente(servidor)
    assert c.harden(b"una") != c.harden(b"otra")


# --- Lo que de verdad importa: el servidor no puede mentir --------------------

def test_servidor_mentiroso_es_rejected_no_unavailable(servidor):
    """Un servidor tomado que responde con otra clave DEBE detectarse.

    Es la garantía entera del VOPRF verificable: sin esto, el servicio podría
    devolver cualquier cosa y el cliente la aceptaría.
    """
    servidor.set_modo("mentiroso")
    with pytest.raises(OprfRejected, match="DLEQ"):
        _cliente(servidor).harden(b"clave")


def test_clave_publica_equivocada_es_rejected(servidor):
    """Fijar la clave que no es se detecta igual que un servidor mentiroso."""
    with pytest.raises(OprfRejected):
        _cliente(servidor, pub=b"\x99" * 32).harden(b"clave")


# --- Caídas: nunca se confunden con "contraseña incorrecta" -------------------

@pytest.mark.parametrize(
    "modo, patron",
    [("caido", "503"), ("sin_key", "401"), ("basura", "ininteligible")],
)
def test_fallos_del_servicio_son_unavailable(servidor, modo, patron):
    servidor.set_modo(modo)
    with pytest.raises(OprfUnavailable, match=patron):
        _cliente(servidor).harden(b"clave")


def test_sin_servidor_es_unavailable():
    c = OprfClient("http://127.0.0.1:1", "quipu_live_test", b"\x01" * 32, timeout=1.0)
    with pytest.raises(OprfUnavailable):
        c.harden(b"clave")


def test_unavailable_y_rejected_no_se_confunden(servidor):
    """La distinción es operativa: Unavailable se reintenta, Rejected se investiga."""
    assert not issubclass(OprfUnavailable, OprfRejected)
    assert not issubclass(OprfRejected, OprfUnavailable)
