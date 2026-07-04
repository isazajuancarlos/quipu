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


def test_signature_round_trip():
    verifying, signing = quipu.generate_signing_keypair()
    data = b"acta firmada desde Python"
    signed = quipu.encode_signed(data, signing)
    assert quipu.decode_verified(signed, verifying) == data


def test_signature_wrong_key_raises():
    verifying, signing = quipu.generate_signing_keypair()
    other_vk, _ = quipu.generate_signing_keypair()
    signed = quipu.encode_signed(b"datos", signing)
    try:
        quipu.decode_verified(signed, other_vk)
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_signature_tampered_raises():
    verifying, signing = quipu.generate_signing_keypair()
    signed = quipu.encode_signed(b"orden importante", signing)
    tampered = ("X" if signed[0] != "X" else "Y") + signed[1:]
    try:
        quipu.decode_verified(tampered, verifying)
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_stream_round_trip():
    data = b"datos grandes en streaming " * 1000
    blob = quipu.encrypt_stream(data, "clave-stream")
    assert isinstance(blob, bytes)
    assert quipu.decrypt_stream(blob, "clave-stream") == data


def test_stream_small_chunk_round_trip():
    data = b"varios trozos" * 2000  # > un par de chunks de 4 KiB
    blob = quipu.encrypt_stream(data, "clave", chunk_size=4096)  # mínimo permitido
    # chunk_size se lee de la cabecera; descifrar no lo necesita
    assert quipu.decrypt_stream(blob, "clave") == data


def test_stream_pepper_round_trip():
    data = b"con pepper en streaming"
    blob = quipu.encrypt_stream(data, "clave", b"pepper-app")
    assert quipu.decrypt_stream(blob, "clave", b"pepper-app") == data
    try:
        quipu.decrypt_stream(blob, "clave", b"pepper-malo")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_stream_wrong_passphrase_raises():
    blob = quipu.encrypt_stream(b"datos", "correcta")
    try:
        quipu.decrypt_stream(blob, "incorrecta")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_stream_tampered_raises():
    blob = bytearray(quipu.encrypt_stream(b"orden importante en streaming", "clave"))
    blob[-1] ^= 0x01  # corromper el último byte del cuerpo cifrado
    try:
        quipu.decrypt_stream(bytes(blob), "clave")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_stream_truncation_raises():
    blob = quipu.encrypt_stream(b"x" * 20000, "clave", chunk_size=4096)
    try:
        quipu.decrypt_stream(blob[: len(blob) // 2], "clave")
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_stream_bad_chunk_size_raises():
    # Fuera de rango [4 KiB, 16 MiB] -> ValueError, no pánico del intérprete.
    for bad in (0, 64, 32 * 1024 * 1024):
        try:
            quipu.encrypt_stream(b"datos", "clave", chunk_size=bad)
            assert False, f"chunk_size={bad} debería haber lanzado ValueError"
        except ValueError:
            pass


if __name__ == "__main__":
    test_round_trip()
    test_wrong_passphrase_raises()
    test_pepper_round_trip()
    test_hybrid_post_quantum_round_trip()
    test_hybrid_wrong_recipient_raises()
    test_signature_round_trip()
    test_signature_wrong_key_raises()
    test_signature_tampered_raises()
    test_stream_round_trip()
    test_stream_small_chunk_round_trip()
    test_stream_pepper_round_trip()
    test_stream_wrong_passphrase_raises()
    test_stream_tampered_raises()
    test_stream_truncation_raises()
    test_stream_bad_chunk_size_raises()
    print("OK: todos los tests de Python pasaron")
