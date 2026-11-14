# Quipu

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/quipu.svg)](https://crates.io/crates/quipu)
[![docs.rs](https://img.shields.io/docsrs/quipu)](https://docs.rs/quipu)
[![CI](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml/badge.svg)](https://github.com/isazajuancarlos/quipu/actions/workflows/ci.yml)
[![post-quantum](https://img.shields.io/badge/post--quantum-ML--KEM--1024-purple.svg)](#modos)

> 🇬🇧 **[Read this in English →](README.md)** — esta versión en español es la
> original, y las dos se mantienen al día.

Librería de codificación con **protección criptográfica** y **simbología propia**.

> Filosofía "rueda y oruga": donde existe buena criptografía, la **reutilizamos**
> (XChaCha20-Poly1305, Argon2id, HKDF, ML-KEM, X25519); donde hay terreno nuevo
> (representación, simbología, formato), **innovamos**. Nunca inventamos primitivas
> criptográficas: la seguridad vive en la clave + el AEAD, no en la representación.

## Qué hace

Protege datos y los representa como **símbolos** (texto denso o una imagen),
de forma reversible y autenticada.

```
datos → KDF(passphrase+pepper) → AEAD → contenedor → codec base-N → diccionario → símbolos
```

## Modos

| Modo | API (Rust) | Descripción |
|---|---|---|
| Simétrico (passphrase) | `api::encode` / `api::decode` | Argon2id + XChaCha20-Poly1305 |
| Post-cuántico (clave pública) | `api::encode_to_recipient` / `decode_as_recipient` | Híbrido **X25519 + ML-KEM-1024** (transcript ligado estilo X-Wing) |
| Online (endurecimiento) | `api::encode_online` / `decode_online` | **VOPRF conforme a [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)** (ristretto255-SHA512, prueba DLEQ): el cliente detecta un servidor deshonesto |
| Firmado (autenticidad) | `api::encode_signed` / `decode_verified` | Firma híbrida **Ed25519 + ML-DSA-87** (combinador AND). Autenticidad y no-repudio verificables; **no** confidencialidad |
| Firmado triple (alta garantía, feature `slh`) | `api::encode_signed_triple` / `decode_verified_triple` | Firma triple-híbrida **Ed25519 + ML-DSA-87 + SLH-DSA-256s** (AND 3-de-3): infalsificable mientras sobreviva ≥1 de {curva, retículo, hash}. Opt-in; firma ~34 KB |
| Streaming (archivos grandes) | `api::encrypt_stream` / `decrypt_stream` | Cifrado por chunks (memoria acotada) para datos en reposo grandes; resistente a truncación/reordenamiento/splice. Contenedor `QST1` |
| Señuelos / Honey (feature `honey`) | `honey::encrypt_pin` / `decrypt_pin` (y genérico `encrypt`/`decrypt`) | **Honey Encryption** para secretos de baja entropía (PIN, frase mnemónica): cualquier passphrase equivocada descifra a **otro secreto plausible**, no a un error → sin oráculo de fuerza bruta. Opt-in. **Sin autenticación por diseño** (un tag sería un oráculo); no sustituye al núcleo AEAD, solo para secuencias uniformes |
| Negación (feature `negacion`) | `negacion::crear` / `abrir` | Un archivo, **dos contraseñas**: una abre el señuelo que se entrega bajo coacción y otra el volumen verdadero. **Nada dentro del contenedor dice si el segundo existe**, y el resto se rellena con azar exista o no. Opt-in. Ver el límite en negrita más abajo |
| Reparto ciego (feature `blindaje`) | `api::encode_blindado` / `api::decode` | Dos AEAD de **dos crates distintos** (AES-256-GCM + XChaCha20-Poly1305), y **ninguno de los dos llega a ver el texto en claro**: el mensaje se reparte con XOR y cada mitad va a una capa. Defiende de que una LIBRERÍA esté comprometida, que es lo que el cifrado normal no cubre. Opt-in: la salida ocupa el **doble** y cifrar cuesta ~**×17** a 256 KiB y ×52 en mensajes de 1 KiB (medido el 2026-08-17; el ×5,2 que aquí se publicó era de `QBL1`, antes de la máscara) |

### Un límite del alcance: no hay streaming CON CLAVE PÚBLICA

La tabla de arriba tiene los dos modos, y **no se cruzan**:

- `encrypt_stream` / `decrypt_stream` (`QST1`) cifra por trozos con memoria
  acotada — pero es **simétrico**: deriva de una contraseña.
- `encode_to_recipient` cifra hacia una clave pública post-cuántica — pero
  recibe un `&[u8]` y devuelve una `String`: **carga el archivo entero en
  memoria** y lo pasa por el codec base-N.

O sea que **«cifrar un archivo grande hacia la clave pública de otro» no tiene
hoy un camino con memoria acotada**. No es un fallo; es alcance que nadie ha
pedido todavía, y está escrito aquí para que nadie lo descubra a mitad de una
integración.

**El coste en TIEMPO del camino simbólico, que hasta el 2026-08-16 no estaba
escrito y era la limitación que mordía primero.** El codec base-N convierte el
mensaje entero como un solo número, y eso se hacía dividiendo en bucle: era
**cuadrático**. 512 KiB costaban 50,7 s y 10 MiB habrían costado unas 5,6 horas
— o sea que el límite real no era la memoria (10 MiB no son nada), era el
reloj. Reescrito con conversión de base por **divide y vencerás**, el orden baja
a `O(M(m)·log m)`: **512 KiB pasan de 50,7 s a 0,46 s (111×) y 10 MiB de ~5,6 h
a 41,4 s**, medidos los dos. Lo vigila
`crates/quipu-nucleo/tests/escala_del_codec.rs`, que se pone rojo si vuelve a
ser cuadrático.

Sigue siendo superlineal, así que el camino simbólico no es para archivos
arbitrariamente grandes: para eso está `encrypt_stream`, que no pasa por el
codec. Y el techo de memoria no se movió — la mejora es de tiempo, no de
espacio, y la tabla de potencias que usa suma aproximadamente otro tanto del
tamaño del mensaje.

Lo que costaría, para que no haya que volver a deducirlo: un `QST1` cuya
cabecera lleve la encapsulación ML-KEM en lugar del salt y los parámetros de
Argon2id. La clave de contenido ya sale de la decapsulación, así que el resto
del formato de trozos —AAD por trozo, resistencia a truncación y
reordenamiento— sirve igual. Es una variante de contenedor, no criptografía
nueva.

## Qué protege tu secreto: los tres factores, y cuál elegir

La tabla de arriba dice qué **hace** cada modo. Esta dice de qué depende que
alguien pueda abrirlo, que es la pregunta que hay que responder antes.

**El eje no es «clave o archivo».** Lo que decide la seguridad es *cuántos
intentos consigue el atacante y si puede hacerlos sin pedir permiso a nadie*.

| Factor | Qué es | Fuerte contra | Débil contra |
|---|---|---|---|
| **Contraseña** (siempre) | lo que SABES. Argon2id la convierte en clave | robo del archivo: no hay nada guardado que copiar | adivinación **offline, en paralelo y sin límite** — y coacción |
| **`pepper`** (`Options::pepper`) | lo que TIENES: variable de entorno, código, HSM. Se mezcla antes del KDF | quien consigue el contenedor y no el pepper **no puede ni empezar** a adivinar | copiarse sin que te enteres; si lo pierdes, los datos se van con él |
| **VOPRF online** (`encode_online`) | lo que un **servidor concede**, con prueba DLEQ verificada contra una clave fijada | es el único que **ACOTA EL NÚMERO DE INTENTOS**: cada uno exige una consulta que el servidor puede negar | disponibilidad — si el servidor cae, no se descifra ([R2/N5](docs/THREAT_MODEL.md)) |

**Argon2id encarece cada intento; no limita cuántos hay.** Esa es la frase que
ordena la tabla: contra alguien con tu contenedor, tiempo y máquinas, el coste
por intento solo multiplica su factura. Lo único que le pone un techo al número
de intentos es el VOPRF, y por eso es el servicio de pago y no un adorno.

### Qué usar

- **Nada más que la contraseña**: si es larga y aleatoria (una frase de
  diccionario de 6+ palabras, no una que hayas inventado). Sin infraestructura,
  y es el defecto. `Options::pepper` viene vacío: **por omisión no hay segundo
  factor**, y conviene saberlo.
- **Contraseña + `pepper`**: en cuanto exista un sitio para guardarlo que no sea
  el mismo disco que el contenedor. Es la mejora más barata que hay.
- **Contraseña + VOPRF**: cuando el adversario pueda llevarse el contenedor y
  tenga paciencia. A cambio aceptas depender de un servicio — por eso su dominio
  y su clave `k` **no rotan nunca**: rotar invalidaría todo lo derivado.
- **Modo de clave pública** (`encode_to_recipient`): cuando quien cifra **no**
  es quien descifra, o cuando no hay ningún humano que teclee nada (un servidor
  cifrando su propia base). Ahí sí hay un secreto que guardar, y para eso están
  el [HSM](#firma-en-un-dispositivo-hsmpkcs11-feature-hsm) y la
  [custodia k-de-n](#custodia-de-claves-k-de-n-feature-escrow).

### Por qué Quipu NO tiene «archivo de clave» a secas

Sería un objeto único cuya **copia no deja rastro** y cuya **pérdida no tiene
recurso**, y traslada el problema justo a donde un atacante con acceso al sistema
de ficheros es más fuerte. El `pepper` es la versión estrictamente mejor de «algo
que tienes»: no está obligado a ser un archivo —puede vivir en el entorno o en un
HSM— y **suma** a la contraseña en vez de sustituirla. Añadir además un archivo de
clave daría aspecto de más protección introduciendo un punto único de fallo.

## Reparto ciego: la amenaza que el cifrado normal no cubre (feature `blindaje`)

Todos los modos de arriba protegen del que **intercepta** el contenedor. Ninguno
protege de que una de las **librerías** de las que dependemos esté comprometida
—que es hacia donde se han movido los ataques—, porque el crate malicioso corre
en el mismo proceso y ve el claro y la clave antes que nadie.

Lo primero que se piensa es encadenar dos cifrados, `AES(XChaCha(P))`. **No
sirve para esto**: la capa de dentro recibe el claro entero. Sirve contra un
fallo criptoanalítico de una de las dos, que es otra amenaza.

Este modo **reparte en vez de encadenar**:

```text
    S1 = aleatorio(|P|)              S2 = P xor S1
    C1 = AES-256-GCM(K1, S1)         C2 = XChaCha20-Poly1305(K2, S2)
```

`S1` es uniforme por construcción y `S2` lo es porque es `P` enmascarado con
`S1`, así que **cada implementación de algoritmo recibe ruido** y por separado
ninguna contiene un solo bit de información sobre el mensaje. Y sigue haciendo
falta romper las dos para leer, igual que la cascada: el reparto tiene las dos
propiedades, no cambia una por otra.

**Hasta dónde llega ese «AND», y cómo se cerró.** La revisión del 2026-08-16
encontró que el reparto era ciego para cada implementación de algoritmo y **no
para el pegamento**: ni `aes-gcm` ni `chacha20poly1305` implementan el `encrypt`
que recibe el mensaje —los dos heredan el genérico del crate `aead`—, así que
`aead` veía `S1` en una llamada y `S2` en la siguiente, y `S1 xor S2 = P`.

Se cerró el 2026-08-17 con el formato **`QBL2`**, y sin importar ningún
ecosistema nuevo: la capa XChaCha ya no recibe `S2` sino `S2 xor M`, con `M` derivada
por HKDF-SHA256 del maestro y del identificador del mensaje. Quien vea las dos
llamadas obtiene `P xor M`, que sin `M` no es nada. Lo sostiene un hecho de la
cadena de suministro, medido y vigilado por una prueba: **los 14 paquetes
exclusivos del camino AEAD —`aead`, `cipher` e `inout` entre ellos— no están en
el cierre de dependencias de `hkdf`/`sha2`**, así que ninguno puede ver `M`.

Lo que el reparto da, con precisión: un fallo criptoanalítico o una puerta
trasera **en `aes` o en `chacha20`** no entrega nada, y desde `QBL2` tampoco la
entrega el pegamento compartido de esos dos caminos. **Lo que sigue sin dar es
inmunidad a dos paquetes**: `block-buffer`, que está en las dos rutas, y
`zeroize`, al que el módulo entrega las dos mitades en claro porque es quien las
borra. Eran 22; quedan dos. Cerrar también eso exigiría una de las dos capas
fuera de RustCrypto, que es una decisión de dependencias con su propio precio y
sigue sin tomarse; está escrito en el módulo para no volver a deducirlo.

**No es criptografía inventada.** `P = S1 xor S2` con `S1` uniforme es el
cuaderno de un solo uso y el caso `k = n = 2` de Shamir, que ya vive en el
repositorio. El secreto de cada mitad por separado es perfecto, no
computacional. *(La propiedad que añade `QBL2` —que juntar las dos llamadas no
dé el claro— sí es computacional: descansa en que HKDF-SHA256 sea un PRF. Son
dos afirmaciones distintas y conviene no mezclarlas.)* Lo propio aquí es la
COMPOSICIÓN —qué recibe cada capa, cómo se deriva su material, qué las ata—, y
eso no es un primitivo.

**El precio, medido el 2026-08-16:** la salida ocupa exactamente `2·|P| + 56`
bytes y cifrar cuesta **×17** a 256 KiB y **×52** a 1 KiB, donde mandan las cuatro
derivaciones HKDF). El doble de tamaño **no es optimizable**: cualquier
construcción que conserve el tamaño tiene por fuerza un componente que toca el
claro el primero, y ese componente lo ve. Mantener a todos ciegos cuesta el
doble. Por eso es opt-in y no el camino por defecto — en el camino simbólico, el
doble de bytes es el doble de glifos.

**Cómo se usa, y qué le pasa a quien no lo tenga.** Se cifra con
`api::encode_blindado` y se abre con `api::decode`, **la misma de siempre**: el
modo viaja en el bit 0 de `flags` de la cabecera, así que un artefacto guardado
declara cómo se escribió y quien lo abra dentro de dos años no tiene que
acordarse. El contenedor es el mismo —misma versión, misma cabecera, misma
cabecera como AAD—, así que cambiarle el bit a un contenedor ya escrito **rompe
la autenticación** en vez de degradarlo en silencio.

Un binario del producto por defecto —sin la feature— devuelve
`DecodeError::ModoNoCompilado`; uno anterior al 2026-08-16 devuelve
`FlagsDesconocidos`. Los dos se niegan en voz alta, que es para lo que ese
segundo error existía desde el principio: éste es el primer bit de `flags` que se
usa desde que el formato existe.

**De qué NO protege**, que importa tanto como lo otro: de que estén comprometidos
los dos crates; de un HKDF o un Argon2id comprometidos, que ven la clave maestra;
y de un generador de aleatoriedad comprometido — si `S1` es predecible el reparto
se desmonta. Por eso la mitad aleatoria `S1` sale de `aleatorio::llenar`, o sea del sistema
operativo, y **nunca** de `aleatorio::generador()`, que es un DRBG de ChaCha20:
usar el crate de ChaCha para generar la máscara *y* para cifrar la otra mitad le
entregaría las dos a un solo crate comprometido. Ésa es la forma sutil de
implementar este modo mal, y es parte de ese coste.

## Negación: lo que promete y lo que NO (feature `negacion`)

**Protege contra la PRUEBA, no contra la SOSPECHA de quien ya decidió
sospechar.** Ante coacción física esa distinción puede no valer nada. Esto **no**
es «cifrado indetectable», y quien lo use puede ser alguien cuya libertad dependa
de entender la diferencia.

El modelo de amenaza supone que el adversario ve el contenedor **una vez**. Quien
guarde versiones sucesivas del mismo archivo en un respaldo —o lo sincronice a la
nube— **pierde la negación**: comparar dos instantáneas delata qué región cambió.

Lo que sí está medido, con casos rojos que ponen rojo el banco: el contenedor no
se distingue de azar, ninguna posición de byte es predecible, uno con volumen
oculto no se distingue de uno sin él, y abrir el señuelo cuesta lo mismo que
abrir el oculto (`t = 0,73`, umbral 10). El diseño, las desviaciones y las
mediciones están en [`docs/DISENO_NEGACION.md`](docs/DISENO_NEGACION.md).

No viaja en las ruedas de Python en esta versión: una API mal usada aquí no
produce un error, produce una falsa sensación de negación.

## Custodia de claves (k-de-n, feature `escrow`)

`quipu::shamir` reparte un secreto en `n` comparticiones de las que **k**
cualesquiera lo reconstruyen y **k-1 no revelan nada**. Va **tras un feature
gate opt-in**: es una herramienta de escrow, no del núcleo de cifrado, y quien
no la necesite no la lleva compilada. Sirve para respaldar la
clave del servidor OPRF, custodiar la clave de firma de un integrador o montar
un escrow contractual — **sin red y sin HSM**, que es la condición de un
despliegue air-gapped.

```rust
let comparticiones = quipu::shamir::split(&clave, 3, 5)?;   // 3 de 5
let clave = quipu::shamir::combine(&comparticiones[..3])?;
```

Cada compartición lleva un verificador, así que una corrupta o de otro reparto
**se detecta** en vez de devolver basura. Ese verificador permitiría comprobar
conjeturas de un secreto adivinable, así que el módulo **rechaza secretos más
cortos que el material de clave más pequeño que produce la propia arquitectura**
(`kdf::KEY_LEN`, 32 bytes): es para claves, y para lo adivinable está `honey`. No es firma umbral — el secreto se reconstruye en memoria para usarlo.

## Firma en un dispositivo (HSM/PKCS#11, feature `hsm`)

La clave privada de firma puede vivir en un **HSM, token o tarjeta PKCS#11 y no
salir de ahí**. Es la respuesta a la primera pregunta de un comité de seguridad,
y funciona con la firma híbrida completa: las **dos mitades** —Ed25519 y
ML-DSA-87— se generan y se usan **dentro** del dispositivo; de la librería solo
salen firmas y la clave pública.

El trait `firmante::Custodio` separa *quién guarda la clave* de *cómo se arma la
firma*. Pide operaciones, nunca material: no existe forma de sacar la clave,
porque el punto entero es que no salga. Una firma hecha en un HSM y una hecha en
memoria **las verifica el mismo verificador, sin distinguir su origen**.

> **Corregido el 2026-08-01.** Esta frase decía «son **idénticas byte a byte**», y
> es falsa: en PKCS#11 se pide `HedgeType::Preferred`, o sea ML-DSA **aleatorizado**
> si el dispositivo lo admite, mientras el camino en memoria firma determinista.
> Los bytes difieren; lo que no cambia es que ambas verifican con la misma clave y
> el mismo verificador, que es lo único que necesita quien las usa. El *hedging*
> además es lo que recomienda FIPS-204 frente a la inyección de fallos, así que la
> diferencia juega a favor.
>
> Lo halló una revisión independiente, y la prueba que respaldaba la frase
> —`firmar_por_el_trait_da_lo_mismo_que_el_camino_directo`— **solo ejercita el
> custodio en memoria**, donde la igualdad se cumple trivialmente porque los dos
> caminos llaman al mismo código. Pasaba por la razón equivocada.

```rust
// El custodio en memoria de siempre (predeterminado, sin feature):
let firma = firmante::firmar(&firmante::EnMemoria::nuevo(sk), mensaje)?;

// O contra un dispositivo PKCS#11, con la clave dentro (feature `hsm`):
let custodio = CustodioPkcs11::por_etiqueta(sesion, "firma-ed", "firma-ml")?;
let firma = firmante::firmar(&custodio, mensaje)?;  // la clave nunca cruza aquí
```

Con `escrow`, `firmar_con_comparticiones` reconstruye desde Shamir, firma y
borra en una sola llamada de Rust, sin que la clave cruce a los bindings.
Probado de punta a punta —128 firmas concurrentes contra un token real, cada una
verificada— y en el binding de Python (`quipu.CustodioHsm`), que va en la rueda.

## Diccionarios (simbología enchufable)

- `dictionaries::ascii94()` — 94 símbolos ASCII (copy-paste universal).
- `dictionaries::flagship()` — 4096 glifos (12 bits/símbolo, ~2× más denso).
- `dictionaries::from_range(start, count)` — alfabeto a medida.

## Seguridad y endurecimiento

- **Precapas**: normalización NFKC, pepper, padding Padmé (oculta longitud),
  binding de contexto (AAD), HKDF (separación de subclaves).
- **Antihacker**: borrado de claves en memoria (`zeroize`), comparación en tiempo
  constante, validación de parámetros KDF, errores uniformes.
- **Fallo de entropía, no sustitución silenciosa**: cuando el sistema operativo
  no puede dar aleatoriedad, Quipu **no cae a una fuente más débil** — ninguna
  clave nace de un RNG muerto. El fallo se informa como un error accionable
  (¿reintento yo, o arreglo el despliegue?) con un reintento acotado para el
  único caso transitorio, en vez de un `panic`: así la limpieza de memoria
  (`Drop`/zeroize) se ejecuta incluso ahí, que es justo cuando más importa. Es
  el modo de fallo de Debian OpenSSL 2008 —claves predecibles que *parecen*
  correctas— prevenido por construcción, y hay una autoprueba que avisa al
  arrancar en vez de matar el proceso.
- **Autopruebas de arranque** (`quipu::selftest`): 14 vectores de respuesta
  conocida sobre **el binario que realmente se ejecuta**, no sobre el build de
  CI. Corren una vez por proceso al entrar por cualquier punto del núcleo, y si
  alguna falla el módulo **se niega a operar** en vez de producir resultados
  silenciosamente incorrectos.

  Una autoprueba fallida **no significa que Quipu falle**: significa que la
  máquina no está ejecutando la criptografía correctamente — una rueda compilada
  para otro procesador, un archivo dañado o sustituido, memoria defectuosa. No
  introducen modos de fallo, hacen visibles los que ya existían.

  Van más allá de lo que exigen FIPS 140-3 y los GM/T chinos en tres puntos:
  usan **vectores publicados** donde existen (HKDF contra el RFC 5869, no
  vectores propios que solo demuestran consistencia consigo mismos), incluyen
  **pruebas negativas** (lo manipulado debe *fallar*), y vigilan la **salud del
  RNG** en continuo. Cada comprobación está probada de que **discrimina**: una
  que devolviera siempre `true` pasaría una batería convencional igual que una
  correcta.

  Verificadas con 1300 operaciones simuladas —200 pasadas, 100 hebras
  concurrentes, 1000 llamadas repetidas— y con inyección de fallo para ejercitar
  el camino de error, ambas en CI.
- **Hackerbot**: red-team interno (tamper/truncation/uniqueness). Encontró y se
  corrigió un DoS por parámetros Argon2 maliciosos.
- **Security Lab** (features `lab` / `lab-offline`, no viajan en el build
  publicado): red-team **adaptativo** que se ataca a sí mismo. Núcleo en CI
  (fuga de formato + falsificación de firmas) con corpus encadenado y meta-tests
  que fallan si se debilita una defensa antihacker; y un **banco offline aislado**
  (contenedor sin red) para timing y coste de guessing acelerado por IA.
  `cargo run --example securitylab --features lab` · `bash lab/run.sh`. Ver
  [`lab/README.md`](lab/README.md) y `THREAT_MODEL.md` §9.

## Uso (Rust)

```rust
use quipu::api::{encode, decode, Options};
use quipu::dictionaries;

let dict = dictionaries::ascii94();
let sym = encode(b"secreto", "passphrase", &dict, &Options::default());
let data = decode(&sym, "passphrase", &dict, b"").unwrap();
```

Firma híbrida (autenticidad verificable por terceros, post-cuántica):

```rust
use quipu::api::{encode_signed, decode_verified};
use quipu::{dictionaries, pqsign};

let dict = dictionaries::ascii94();
let (vk, sk) = pqsign::generate_keypair();
let signed = encode_signed(b"acta oficial", &sk, &dict);
let msg = decode_verified(&signed, &vk, &dict).unwrap(); // falla si se altera
```

## Uso (Python)

**La rueda nativa de Python se retiró el 2026-08-14.** quipu es ahora Rust puro
**sin ningún binding**: `src/python.rs`, `pyproject.toml` y la dependencia de
PyO3 ya no existen. `pip install quipu-crypto` no corresponde a ninguna fuente de
este repositorio, y esas versiones de PyPI están retiradas.

El motivo: la cadena de PyO3 costaba 120 551 líneas de árbol, 8 crates y —lo que
de verdad importaba— **5 de los crates que ejecutan código al compilar**, que es
el vector por el que entraron los gusanos de npm y del AUR.

**Lo que sigue funcionando desde Python**, y no es lo mismo: el cliente del
servicio OPRF. Habla HTTP, no enlaza nada y no le afecta — ver «Endurecimiento de
contraseñas» más abajo.

**Si hace falta un binding nativo otra vez**, la decisión ya está tomada y *no*
es PyO3 ni una C-ABI escrita a mano: un envoltorio de Python puro que hable con
el binario de quipu por una tubería. Cero FFI, cero `unsafe`, y sirve para
cualquier lenguaje, no solo Python.

## Ejemplos funcionales

Round-trip de todos los modos, listo para correr:

```bash
cargo run --example quickstart          # Rust  (examples/quickstart.rs)
python examples/quickstart.py           # Python (examples/quickstart.py)
```

## Construir y probar

```bash
cargo test                      # tests unit + property
cargo clippy --all-targets      # lint
cargo run --example demo        # demo simétrico
cargo run --example v2demo      # post-cuántico + OPRF + imagen
cargo run --example hackerbot --features lab   # red-team
cargo run --example testplatform --features lab --release   # batería completa
cargo run --example securitylab --features lab   # laboratorio de seguridad (red-team adaptativo)
cargo run --example redteam --features "lab slh honey" --release   # red-team consolidado (todas las superficies)
bash lab/run.sh   # banco offline aislado (timing + guessing) — Etapa B

# Fuzzing coverage-guided (libFuzzer, nightly). Targets: parse_container,
# honey_decrypt, unpad, codec_roundtrip.
cargo +nightly fuzz run honey_decrypt

# (los bindings de Python se retiraron el 2026-08-14: quipu es Rust puro)
```

## Estado

v1 + v1.1 + v2 + streaming AEAD (`QST1`) + honey (`QHNY`) + firmas (híbrida
Ed25519+ML-DSA-87 y triple con SLH-DSA) implementados con TDD estricto.
**380 pruebas Rust en 38 binarios + Wycheproof + 15 de Python** verdes
(recontadas el 2026-08-03 con `cargo test --workspace --all-targets`; la cifra
anterior, 267, era de antes de la rama de negación y del medidor de residuo),
clippy limpio, fuzzing sin
crashes, Miri sin UB. **Rust puro**: fuera la C ABI, Node y Go —el único binding
**tampoco la rueda de Python**: desde el 2026-08-14 no hay ningún binding—.
Parámetros post-cuánticos en **categoría de seguridad NIST 5 (CNSA 2.0)**:
**ML-KEM-1024** y **ML-DSA-87**. Modo online con **VOPRF conforme a RFC 9497**
(ristretto255-SHA512), verificado contra los **vectores oficiales del Apéndice
A.1.2**, KEM híbrido con transcript ligado estilo X-Wing, **firma híbrida Ed25519 +
ML-DSA-87** (combinador AND), y
**pre-auditoría** propia (ver `INFORME_PREAUDITORIA.txt` y `MODELO_DE_AMENAZA.txt`).
**Security Lab** (red-team adaptativo auto-hospedado): 14 ataques en CI
(`--features lab`) + banco offline de timing/guessing (`--features lab-offline`).

> ⚠️ Proyecto en desarrollo. La pre-auditoría interna NO sustituye una auditoría
> criptográfica **independiente**: no usar para proteger datos críticos reales
> hasta ese sello externo.

## La familia: un núcleo, dos perfiles

Quipu no es un crate: es un **núcleo agnóstico de primitivas** y perfiles finos
encima que declaran con qué criptografía se comprometen.

| Crate | Qué es |
|---|---|
| [`crates/padme-frame`](crates/padme-frame) | El relleno **Padmé** con su marco de longitud, en un crate aparte y **`MIT OR Apache-2.0`**: `no_std`, cero dependencias, y utilizable sin arrastrar la AGPL de todo lo demás. Es la única pieza de aquí que sirve fuera de Quipu, y por eso es la única con licencia permisiva. |
| [`crates/quipu-nucleo`](crates/quipu-nucleo) | Todo lo que **no** es criptografía: formato del contenedor, codec base-N, Reed-Solomon, carga útil del portador de papel. **Cero primitivas.** El relleno Padmé se le reexporta desde `padme-frame` — `prelayers::pad`/`unpad` siguen donde estaban y con la misma firma. |
| `quipu` (este crate) | El perfil por defecto: **XChaCha20-Poly1305**, HKDF-SHA-256, nonce extendido de 192 bits. |
| [`crates/quipu-cnsa`](crates/quipu-cnsa) | El perfil alineado con **CNSA 2.0**: AES-256-GCM, HKDF-SHA-384, nonce de 96 bits. **NO validado FIPS 140-3.** | **Y su canal de destinatario abandona el híbrido: es ML-KEM-1024 PURO, sin socio clásico.** Más fuerte frente a lo cuántico que `quipu` y más débil frente a un fallo clásico de retículos — quien elige este perfil por mandato normativo está aceptando además ese cambio de postura, y conviene saberlo aquí, que es donde se elige.

La relación es la de Devuan con Debian: no una rama de mantenimiento, sino un
**compromiso declarado** que comparte casi todo. El formato, el codec y el canal
visual viven una sola vez en el núcleo, así que **un fallo se arregla una vez** —
no dos ramas divergiendo hasta que una recibe el parche y la otra no.

**Si puedes elegir, usa `quipu`.** El perfil CNSA existe para quien tiene un
mandato normativo: en hardware sin aceleración AES, AES-GCM es una *regresión*
—más lento y más difícil de escribir en tiempo constante, por sus tablas de
sustitución—. ChaCha20 no tiene tablas y es constante por construcción.

## Endurecimiento de contraseñas (servicio OPRF)

```
Argon2 solo:  robas la BD -> fuerza bruta offline, a la velocidad de tu GPU.
Con VOPRF:    robas la BD -> no derivas nada sin la clave del servidor. Cada
              intento exige una petición que el operador ve, limita y corta.
```

Hay una instancia gestionada en **`https://oprf.xiliux.com`** (beta). El cliente
va aparte y es **Apache-2.0**: no arrastra la AGPL de este núcleo a tu servidor
de autenticación.

```bash
pip install quipu-oprf-django   # Django: solo toca PASSWORD_HASHERS
pip install quipu-voprf         # las primitivas, para cualquier otro stack
```

La contraseña sale **cegada** (el servidor nunca la ve) y el servidor no puede
mentir: adjunta una prueba DLEQ que el cliente verifica contra una clave pública
**fijada fuera de banda**. Falla cerrado: si el servicio no responde o la prueba
no valida, no se degrada a "sin endurecer".

- [`crates/quipu-voprf`](crates/quipu-voprf) — primitivas VOPRF (RFC 9497), Apache-2.0
- [`crates/quipu-oprf-server`](crates/quipu-oprf-server) — el servidor, auto-hospedable
- [`integrations/`](integrations) — Django (publicado)

## Documentación

- [`docs/HOJA_DE_RUTA.md`](docs/HOJA_DE_RUTA.md) — **qué falta y en qué orden**,
  con el estado medido y las decisiones ya tomadas para no reabrirlas.
- [`docs/RAMAS.md`](docs/RAMAS.md) — el modelo de ramas (estable, testing,
  desarrollo) y por qué la promoción no se hace a mano.
- [`docs/SPEC.md`](docs/SPEC.md) — **especificación técnica** (formato del
  contenedor, KDF, modo híbrido, VOPRF/DLEQ, separación de dominios).
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — modelo de amenaza (EN)
  · original [`MODELO_DE_AMENAZA.txt`](MODELO_DE_AMENAZA.txt) (ES).
- [`docs/PRE_AUDIT.md`](docs/PRE_AUDIT.md) — pre-auditoría interna (EN)
  · original [`INFORME_PREAUDITORIA.txt`](INFORME_PREAUDITORIA.txt) (ES).
- [`SECURITY.md`](SECURITY.md) — política de seguridad y reporte de fallos.
- [`docs/RELEASES.md`](docs/RELEASES.md) — cómo verificar la autenticidad de un
  release (**retirado el 2026-08-10** — las ruedas están yanked y no hay CI que
  firme nada; la fuente se entrega como paquete con firma híbrida, ver
  `docs/RELEASES.md`).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — cómo contribuir · [`CHANGELOG.md`](CHANGELOG.md).
- [`LICENSING.md`](LICENSING.md) — modelo de licenciamiento dual.
- [`docs/announcement.md`](docs/announcement.md) — artículo de diseño (EN/ES).
- [`docs/superpowers/specs/2026-07-01-quipu-security-lab-design.md`](https://github.com/isazajuancarlos/quipu/blob/estable/docs/superpowers/specs/2026-07-01-quipu-security-lab-design.md)
  — diseño del **Security Lab** (red-team adaptativo, feature `lab`). El enlace
  es absoluto a propósito: ese directorio queda EXCLUIDO del `.crate` publicado,
  así que una ruta relativa daría 404 a quien lea esto desde crates.io o docs.rs.

> ⚠️ La pre-auditoría interna es preparación, **no** sustituye una auditoría
> independiente. Ese sello externo es el siguiente paso del proyecto (solicitud
> enviada al OTF Security Lab).

## Licencia

Modelo de **licencia dual** (open-core). **No todo el repositorio es AGPL**: lo
que un cliente del servicio OPRF enlaza dentro de su propio servidor es permisivo.

| Componente | Licencia |
|---|---|
| `quipu` (núcleo) y sus bindings | `AGPL-3.0-or-later` (ver `LICENSE`) |
| `crates/quipu-nucleo` (formato, codec y portador de papel) | `AGPL-3.0-or-later` / comercial |
| `crates/padme-frame` (relleno Padmé, `no_std`) | **`MIT OR Apache-2.0`** |
| `crates/quipu-cnsa` (perfil CNSA 2.0) | `AGPL-3.0-or-later` / comercial |
| `crates/quipu-voprf` → [`quipu-voprf`](https://pypi.org/project/quipu-voprf/) | **`Apache-2.0`** |
| `crates/quipu-oprf-server` | `AGPL-3.0-or-later` / comercial |

### Qué se cobra, exactamente

**Quipu es libre y siempre lo será.** Puedes usarlo hoy sin pagar nada. La única
condición es publicar el código de lo que construyas encima. Si eso no te sirve,
te vendemos la exención de esa obligación.

Dicho de otro modo: **no se cobra por el uso, se cobra por el derecho a no
publicar.** El copyleft no prohíbe cobrar —la GPL dice literalmente que puedes
cobrar cualquier precio o ninguno—; lo que restringe es el **secreto**, no el
precio.

- **Licencia comercial** — para producto propietario cerrado o SaaS sin abrir
  código. Términos en [`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL). Es una
  concesión **adicional y paralela** a la AGPL, no una sustitución: con contrato
  o sin él conservas todo lo que la AGPL concede a cualquiera —usar, estudiar,
  modificar, redistribuir, vender, bifurcar e incluso competir—. Lo único que
  añade es la exención del copyleft de red.
- **Servidor OPRF gestionado** — negocio distinto y complementario: ahí no se
  vende exención sino no tener que operar la infraestructura ni custodiar la
  clave.

**Si puedes cumplir el copyleft, no necesitas comprarnos nada.** Un proyecto
libre, uno académico o una entidad con política de software abierto usan Quipu
gratis, y nos interesa que lo hagan.

**Por qué AGPL y no GPL:** con GPL a secas, quien corre el software como servicio
en red nunca lo *distribuye*, así que nunca dispara el copyleft. El artículo 13
de la AGPL cierra ese hueco. No fue una elección ideológica.

Es la misma estructura que **Qt** o **MySQL**: licencia libre para quien cumple,
licencia comercial para quien necesita términos propietarios.

Copyright (c) 2024-2026 Juan Carlos Isaza — titular único; ver
[`COPYRIGHT`](COPYRIGHT). El uso del nombre «Quipu» se rige por
[`TRADEMARK.md`](TRADEMARK.md).

Las primitivas VOPRF viven en un crate **separado** (no solo con otra etiqueta):
la licencia de un envoltorio no relicencia su dependencia. Detalles y el porqué
en [`LICENSING.md`](LICENSING.md) §0. Contacto: isazajuancarlos@gmail.com
