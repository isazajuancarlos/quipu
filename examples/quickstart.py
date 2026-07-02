#!/usr/bin/env python3
"""Quickstart de Quipu (Python) — ejemplo funcional de punta a punta.

Requisitos:
    pip install quipu-crypto        # se importa como `quipu`
    # o en desarrollo, desde el repo:  maturin develop --features python

Ejecutar:
    python examples/quickstart.py

Cada paso verifica su round-trip con assert. Si el script imprime "OK", todo funcionó.
"""

import quipu

secret = b"Mensaje confidencial: el tesoro esta bajo el arbol viejo."
print("Secreto original:", secret.decode())
print()

# -----------------------------------------------------------------------------
# 1) Modo simétrico (passphrase).
# -----------------------------------------------------------------------------
encoded = quipu.encode(secret, "correct-horse-battery-staple")
print(f"[1] Simétrico -> {len(encoded)} símbolos")
print("   ", encoded)
decoded = quipu.decode(encoded, "correct-horse-battery-staple")
assert decoded == secret, "round-trip simétrico"
print("    round-trip OK ✔")
print()

# -----------------------------------------------------------------------------
# 2) Passphrase incorrecta -> lanza ValueError (integridad autenticada).
# -----------------------------------------------------------------------------
try:
    quipu.decode(encoded, "passphrase-incorrecta")
    raise SystemExit("ERROR: una passphrase incorrecta NO debería descifrar")
except ValueError:
    print("[2] Passphrase incorrecta rechazada ✔")
print()

# -----------------------------------------------------------------------------
# 3) Con pepper (secreto fuera del dato).
# -----------------------------------------------------------------------------
e = quipu.encode(secret, "misma-pass", pepper=b"pepper-en-el-codigo")
try:
    quipu.decode(e, "misma-pass")  # sin pepper -> falla
    raise SystemExit("ERROR: sin el pepper no debería descifrar")
except ValueError:
    pass
d = quipu.decode(e, "misma-pass", pepper=b"pepper-en-el-codigo")
assert d == secret
print("[3] Pepper: solo con el pepper correcto se descifra ✔")
print()

# -----------------------------------------------------------------------------
# 4) Modo asimétrico POST-CUÁNTICO (cifrar a una clave pública).
# -----------------------------------------------------------------------------
public_key, secret_key = quipu.generate_keypair()
enc_pq = quipu.encode_to_recipient(secret, public_key)
dec_pq = quipu.decode_as_recipient(enc_pq, secret_key)
assert dec_pq == secret, "round-trip post-cuántico"
print("[4] Post-cuántico (X25519 + ML-KEM-1024) -> round-trip OK ✔")
print()

# -----------------------------------------------------------------------------
# 5) Firma híbrida (autenticidad/no-repudio, NO confidencialidad).
# -----------------------------------------------------------------------------
verifying_key, signing_key = quipu.generate_signing_keypair()
signed = quipu.encode_signed(secret, signing_key)
verified = quipu.decode_verified(signed, verifying_key)
assert verified == secret, "round-trip firmado"
# Una clave de verificación ajena NO debe validar la firma:
other_vk, _ = quipu.generate_signing_keypair()
try:
    quipu.decode_verified(signed, other_vk)
    raise SystemExit("ERROR: una clave de verificación ajena no debería validar")
except ValueError:
    pass
print("[5] Firma híbrida (Ed25519 + ML-DSA-87) -> verifica y rechaza clave ajena ✔")
print()

print("OK ✅  Todos los modos funcionaron correctamente.")
