# Presentando Quipu: reutiliza la rueda, innova la oruga

> 🇬🇧 English version: [`announcement.md`](announcement.md)

*Una pequeña librería en Rust para cifrar y codificar datos — híbrido
post-cuántico, endurecimiento online verificable y un canal visual de glifos
opcional. Construida solo sobre primitivos criptográficos vetados.*

> **Estado y honestidad por delante.** Quipu es `v0.1.0`. **No** está auditada por
> un tercero independiente todavía, y es mi primer proyecto serio en Rust. Por
> favor, **no** la uses para proteger secretos reales hasta que tenga una
> auditoría externa. La publico ahora para invitar a que la revisen, no para
> afirmar que está lista para producción. Si haces criptografía o seguridad en
> Rust, desmontarla es lo más útil que puedes hacer — issues y PRs bienvenidos.

## La única regla: nunca inventar primitivos

La mayoría de los proyectos de "me hice mi propia cripto" fallan por lo mismo:
inventan la parte peligrosa. La regla que guía a Quipu es la opuesta, y la pienso
como *"reutiliza la rueda, innova la oruga"*: donde ya existe buena criptografía,
se reutiliza intacta; solo se innova en **representación, formato y composición de
protocolos**.

Así que las piezas críticas para la seguridad son todas crates estándar y vetados:

- **AEAD:** XChaCha20-Poly1305
- **KDF:** Argon2id + HKDF-SHA256 (+ normalización NFKC, pepper opcional)
- **KEM post-cuántico:** ML-KEM-768 (FIPS-203) vía el crate `ml-kem`
- **KEM/DH clásico:** X25519 (`x25519-dalek`)
- **Grupo del OPRF:** ristretto255 (`curve25519-dalek`)

Hay **cero `unsafe`** en el código propio de Quipu. La seguridad de memoria
descansa en dependencias auditadas; lo que vale la pena revisar en Quipu es la
**composición**.

## Qué hace

```
datos → KDF(passphrase + pepper) → AEAD → contenedor → codec base-N → símbolos
```

La salida puede ser texto denso, un PNG sin pérdidas, o una tira de **glifos**
propios. La representación es pública y versionada — nada de la seguridad depende
de ocultarla (Kerckhoffs). Es una *oruga*, no un candado.

## Qué es realmente nuevo (la composición)

Primitivos estándar, combinados de formas que un `cifrar-y-codificar` hecho a mano
normalmente no se molesta en hacer:

### 1. Modo híbrido post-cuántico
Cifrar hacia la clave pública de un destinatario deriva la clave de contenido a
partir de **ambos**: un secreto compartido X25519 **y** un secreto ML-KEM-768,
combinados con HKDF y un binding de transcript estilo X-Wing (la clave pública
completa del destinatario —X25519 + la clave de encapsulación ML-KEM— se liga
dentro del KDF). Un atacante tiene que romper **los dos** para recuperar la clave,
que es justo el punto de la resistencia a "cosecha ahora, descifra después".

### 2. Endurecimiento online verificable (VOPRF)
El endurecimiento de contraseña asistido por servidor suele obligar al cliente a
*confiar* en el servidor. Quipu usa un OPRF **verificable** sobre ristretto255 con
una prueba **DLEQ** no interactiva (estilo RFC 9497): el servidor publica una clave
pública, y cada evaluación lleva una prueba de que usó esa misma clave. El cliente
verifica la prueba contra una clave pública fijada (pinned) — así, un **servidor
deshonesto o comprometido se detecta** y la operación se aborta, en vez de producir
en silencio la clave equivocada.

### 3. Un canal visual que no es teatro de seguridad
El mismo ciphertext puede representarse como un alfabeto de glifos propio o un PNG,
con corrección de errores Reed-Solomon para canales impresos/fotografiados. Esto es
explícitamente **representación, no protección**: corrige ruido del canal, no añade
secreto. Ser claro sobre esa distinción es parte del diseño.

## Rigor de ingeniería (porque "confía en mí" no basta)

No puedo ofrecer una trayectoria, así que ofrezco disciplina en su lugar:

- **Desarrollo guiado por tests:** 89 tests en Rust + tests en Python, todos verdes.
- **Vectores Wycheproof** de Google (known-answer tests) para el AEAD.
- **Miri** — sin comportamiento indefinido en los módulos de lógica pura.
- **Fuzzing** (`cargo-fuzz`) sobre los parsers del contenedor/codec — sin crashes.
- **`cargo-audit`** en CI, en cada push y semanalmente.
- Un componente de **red-team interno** ("hackerbot") que ya encontró y corrigió un
  DoS real (parámetros Argon2 maliciosos en una cabecera manipulada).
- Un **informe de pre-auditoría** interno y un **modelo de amenaza** (activos,
  adversarios, garantías por modo, riesgos residuales) en el repo.

Nada de esto sustituye una auditoría independiente. Su objetivo es abaratarla.

## Pruébala

**Rust:**
```rust
use quipu::api::{encode, decode, Options};
use quipu::dictionaries;

let dict = dictionaries::ascii94();
let sym = encode(b"secreto", "correct-horse-battery-staple", &dict, &Options::default());
let back = decode(&sym, "correct-horse-battery-staple", &dict, b"").unwrap();
assert_eq!(back, b"secreto");
```
`cargo add quipu` · <https://crates.io/crates/quipu> · <https://docs.rs/quipu>

**Python:**
```python
import quipu
s = quipu.encode(b"secreto", "correct-horse-battery-staple")
assert quipu.decode(s, "correct-horse-battery-staple") == b"secreto"

pub, sec = quipu.generate_keypair()          # híbrido post-cuántico
assert quipu.decode_as_recipient(quipu.encode_to_recipient(b"pq", pub), sec) == b"pq"
```
`pip install quipu-crypto` (se importa como `quipu`) · <https://pypi.org/project/quipu-crypto/>

Ejemplos ejecutables de punta a punta: [`examples/quickstart.rs`](../examples/quickstart.rs)
y [`examples/quickstart.py`](../examples/quickstart.py).

## Hacia dónde va

- Auditoría de seguridad independiente (el paso que habilita recomendarla para uso real).
- Una especificación escrita + vectores de test de interoperabilidad para que otros
  la reimplementen.
- Bindings a más lenguajes sobre la ABI de C (C / Node / Go).
- Un despliegue de referencia del servidor de endurecimiento online VOPRF.

## Se busca feedback

Si detectas un error de composición, un hueco en la separación de dominios, un
transcript que no está ligado con suficiente firmeza, o cualquier cosa que huela
mal — por favor abre un issue. Para una librería de cripto, el "muchos ojos" es la
razón de ser de que sea abierta.

**Repo (AGPL-3.0):** <https://github.com/isazajuancarlos/quipu>
