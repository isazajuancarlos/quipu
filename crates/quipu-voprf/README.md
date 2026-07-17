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

## Conforme a RFC 9497

Ciphersuite `ristretto255-SHA512`, modo VOPRF (`contextString =
"OPRFV1-\x01-ristretto255-SHA512"`). Verificado contra los **vectores oficiales
del Apéndice A.1.2**: `cargo test -p quipu-voprf`.

Los tests cubren `DeriveKeyPair`, `Blind`, `BlindEvaluate` + `GenerateProof` y
`Finalize` contra los vectores 1 y 2 (lote 1). El vector 3 es de lote 2 y este
API no expone lotes: queda fuera de alcance, y se dice en vez de fingir
cobertura.

Interoperable con cualquier otra implementación de RFC 9497.

### Nota: la construcción propia nunca se publicó

Durante el desarrollo hubo una construcción propia (`quipu/v2/voprf`), inspirada
en la RFC pero no conforme. **Nunca llegó a PyPI**: 0.2.0 es la primera versión
publicada, y nace conforme. Se documenta aquí porque la instancia
`oprf.xiliux.com` sí la sirvió hasta el 2026-07-17, y su clave pública cambió al
migrar. La construcción vieja era: dominio propio, `hash_to_curve` sin
`expand_message_xmd` y transcripción DLEQ propia. No interoperaba con nadie ni
heredaba el análisis de seguridad de la RFC. Se **eliminó**, no se deprecó:
dejarla solo invitaba a usarla por error.

Lo que cambia, y no es reversible:

- La **salida pasa de 32 a 64 bytes** (`Hash` es SHA-512; truncarla haría fallar
  los vectores).
- La **clave pública del servidor cambia para la misma semilla**: ahora se deriva
  con `DeriveKeyPair` (§3.2), con `info = "quipu-oprf-server-v1"`.
- Todo secreto endurecido con la versión anterior queda invalidado.

Se hizo con cero clientes, que era la única ventana: el dominio está horneado en
cada secreto y, como `k`, no rota nunca.
