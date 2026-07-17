# quipu-voprf

VOPRF (OPRF verificable) sobre ristretto255 con pruebas DLEQ. Son las primitivas
que hablan con un [`quipu-oprf-server`](../quipu-oprf-server).

```
Argon2 solo:  robas la BD -> fuerza bruta offline, a la velocidad de tu GPU.
Con VOPRF:    robas la BD -> no puedes derivar nada sin la clave del servidor.
              Cada intento exige una peticion que el operador ve, limita y corta.
```

El servidor nunca ve la entrada (llega cegada) y no puede mentir sobre el
resultado: adjunta una prueba DLEQ de que uso la misma `k` de su clave publica,
y el cliente la verifica contra una clave **fijada fuera de banda**.

## Licencia: Apache-2.0 (distinta del núcleo)

El núcleo de Quipu es AGPL-3.0-or-later. **Este crate no**, y es deliberado.

Es lo único que un cliente del servicio Quipu OPRF debe enlazar dentro de su
servidor de autenticación. Si arrastrara la AGPL, el copyleft de red alcanzaría
al SaaS del cliente — y nadie enchufa eso a su auth. Poner Apache solo en el SDK
no bastaba: la licencia de un envoltorio no relicencia su dependencia, así que
había que separar el código de verdad.

Lo que se cede son ~270 líneas de matemática de curva estándar. No es el foso:
el foso son el servidor, la clave `k` y la biblioteca post-cuántica completa,
que siguen AGPL. Apache-2.0 y no MIT por la concesión expresa de patentes, que
es lo que revisa el departamento legal de una empresa.

Apache-2.0 fluye hacia AGPL-3.0, así que el núcleo puede seguir usando este
crate sin fricción. Al revés no funcionaría — de ahí la dirección de la
dependencia.

## Uso

```rust
use quipu_voprf::{Server, blind, finalize};

// Servidor (guarda k; publica Y = k·G)
let server = Server::from_seed(&seed);
let public_key = server.public_key();

// Cliente: cegar
let (state, blinded) = blind(b"contraseña");

// Servidor: evaluar + probar
let (evaluated, proof) = server.evaluate(&blinded).unwrap();

// Cliente: verificar la prueba contra la clave FIJADA y finalizar
let secret = finalize(b"contraseña", &state, &evaluated, &proof, &public_key)
    .expect("la prueba DLEQ no valida: servidor deshonesto o clave incorrecta");
```

`finalize` devuelve `None` si la prueba no valida. No lo ignores: significa que
el servidor no es el que fijaste, o que rotó su clave.

## AVISO: no es RFC 9497 (todavía)

La construcción está **inspirada** en RFC 9497, no conforme a ella:

- Separación de dominio propia (`quipu/v2/voprf`), no la ciphersuite
  `OPRFV1-\x01-ristretto255-SHA512`.
- `hash_to_curve` usa `RistrettoPoint::hash_from_bytes::<Sha512>` con prefijo,
  no `hash_to_ristretto255` con `expand_message_xmd` y su DST.
- La transcripción de la DLEQ es propia, no la de `GenerateProof`/`ComputeComposites`.

Consecuencias, sin adornos: **no interopera** con ninguna otra implementación de
VOPRF, y **no hereda el análisis de seguridad de la RFC**. La construcción
Chaum-Pedersen subyacente es estándar, pero el enmarcado es nuestro.

Migrar a RFC 9497 es una ruptura del formato en cable: el dominio está horneado
en cada secreto endurecido, así que cambiarlo invalida todos los secretos ya
almacenados — y, a diferencia de las API keys, `k` y el enmarcado no rotan
nunca. Con cero clientes es gratis; con uno, es imposible. Ver `docs/SPEC.md`.
