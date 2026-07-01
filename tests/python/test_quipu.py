"""Tests de integración de los bindings de Python de Quipu.

Ejecutar (con el venv activo):  python -m pytest tests/python -q
o directamente:                 python tests/python/test_quipu.py
"""

import quipu


def test_round_trip():
    data = b"mensaje secreto desde Python"
    symbols = quipu.encode(data, "clave-correcta")
    assert quipu.decode(symbols, "clave-correcta") == data


def test_wrong_passphrase_raises():
    symbols = quipu.encode(b"datos", "correcta")
    try:
        quipu.decode(symbols, "incorrecta")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_pepper_round_trip():
    data = b"con pepper"
    symbols = quipu.encode(data, "clave", b"pepper-app")
    assert quipu.decode(symbols, "clave", b"pepper-app") == data
    # pepper incorrecto -> falla
    try:
        quipu.decode(symbols, "clave", b"pepper-malo")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_hybrid_post_quantum_round_trip():
    public, secret = quipu.generate_keypair()
    data = b"secreto post-cuantico desde Python"
    symbols = quipu.encode_to_recipient(data, public)
    assert quipu.decode_as_recipient(symbols, secret) == data


def test_hybrid_wrong_recipient_raises():
    public, _secret = quipu.generate_keypair()
    _public2, secret2 = quipu.generate_keypair()
    symbols = quipu.encode_to_recipient(b"datos", public)
    try:
        quipu.decode_as_recipient(symbols, secret2)
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_round_trip()
    test_wrong_passphrase_raises()
    test_pepper_round_trip()
    test_hybrid_post_quantum_round_trip()
    test_hybrid_wrong_recipient_raises()
    print("OK: todos los tests de Python pasaron")
