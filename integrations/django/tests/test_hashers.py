"""El hasher de Django: round-trip, fallo cerrado y migración de usuarios.

Ver conftest.py para el alcance: aquí se prueba el cableado, no la criptografía.
"""

import django
import pytest
from django.conf import settings

from quipu_oprf_django.client import OprfRejected, OprfUnavailable


def _configurar(servidor, **extra):
    from quipu_oprf_django import hashers

    cfg = {
        "BASE_URL": servidor.url,
        "API_KEY": "quipu_live_test",
        "PUBLIC_KEY": servidor.pub.hex(),
        "TIMEOUT": 5.0,
    }
    cfg.update(extra)
    if not settings.configured:
        settings.configure(
            QUIPU_OPRF=cfg,
            PASSWORD_HASHERS=[
                "quipu_oprf_django.hashers.OprfArgon2PasswordHasher",
                "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            ],
            USE_TZ=True,
        )
        django.setup()
    else:
        settings.QUIPU_OPRF = cfg
    hashers.reset_client()  # el cliente se memoriza: hay que soltarlo entre tests


@pytest.fixture
def hasher(servidor):
    pytest.importorskip("argon2", reason="requiere argon2-cffi")
    _configurar(servidor)
    from quipu_oprf_django.hashers import OprfArgon2PasswordHasher

    return OprfArgon2PasswordHasher()


# --- Round-trip ---------------------------------------------------------------

def test_encode_y_verify_round_trip(hasher):
    enc = hasher.encode("contraseña-buena", hasher.salt())
    assert hasher.verify("contraseña-buena", enc) is True


def test_contrasena_incorrecta_no_verifica(hasher):
    enc = hasher.encode("la-buena", hasher.salt())
    assert hasher.verify("la-mala", enc) is False


def test_el_hash_lleva_nuestro_algoritmo(hasher):
    """El prefijo permite a Django distinguir estos hashes de los de Argon2 solo,
    que es lo que hace posible la migración automática."""
    enc = hasher.encode("x", hasher.salt())
    assert enc.startswith("quipu_oprf_argon2$")


def test_el_hash_no_contiene_la_contrasena(hasher):
    enc = hasher.encode("secreto-literal", hasher.salt())
    assert "secreto-literal" not in enc


def test_dos_hashes_de_la_misma_clave_difieren(hasher):
    """Salt distinto -> hash distinto, aunque el secreto endurecido sea el mismo."""
    assert hasher.encode("igual", hasher.salt()) != hasher.encode("igual", hasher.salt())


# --- Fallo cerrado: lo que no debe pasar nunca -------------------------------

def test_servicio_caido_levanta_no_devuelve_False(hasher, servidor):
    """Si el OPRF cae, verify NO puede decir 'contraseña incorrecta'.

    Decir False durante una caída manda al usuario a resetear su contraseña por
    un problema de red. Es un incidente operativo y debe verse como tal.
    """
    enc = hasher.encode("clave", hasher.salt())
    servidor.set_modo("caido")
    with pytest.raises(OprfUnavailable):
        hasher.verify("clave", enc)


def test_servicio_caido_no_permite_registrar(hasher, servidor):
    """Tampoco se puede crear un hash sin endurecer: sería un hash inservible."""
    servidor.set_modo("caido")
    with pytest.raises(OprfUnavailable):
        hasher.encode("clave-nueva", hasher.salt())


def test_servidor_mentiroso_levanta_en_verify(hasher, servidor):
    enc = hasher.encode("clave", hasher.salt())
    servidor.set_modo("mentiroso")
    with pytest.raises(OprfRejected):
        hasher.verify("clave", enc)


# --- Configuración ------------------------------------------------------------

def test_public_key_mal_medida_es_error_de_configuracion(servidor):
    from django.core.exceptions import ImproperlyConfigured

    from quipu_oprf_django.hashers import _get_client

    _configurar(servidor, PUBLIC_KEY="aabb")  # 2 bytes, no 32
    with pytest.raises(ImproperlyConfigured, match="32 bytes"):
        _get_client()


def test_public_key_no_hex_es_error_de_configuracion(servidor):
    from django.core.exceptions import ImproperlyConfigured

    from quipu_oprf_django.hashers import _get_client

    _configurar(servidor, PUBLIC_KEY="no-soy-hexadecimal")
    with pytest.raises(ImproperlyConfigured, match="hexadecimal"):
        _get_client()


def test_falta_api_key_es_error_de_configuracion(servidor):
    from django.core.exceptions import ImproperlyConfigured

    from quipu_oprf_django.hashers import _get_client

    _configurar(servidor, API_KEY="")
    with pytest.raises(ImproperlyConfigured, match="API_KEY"):
        _get_client()
